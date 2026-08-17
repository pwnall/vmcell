//! KVM-free gates for the bridge's **deadline** contract — the two ways the per-call budget added
//! for M12 could itself lose a request:
//!
//! - `an_execs_budget_strictly_exceeds_the_guest_timeout_it_forwards` /
//!   `an_absurd_exec_timeout_is_served_instead_of_panicking_the_deadline_math` — the budget is
//!   DERIVED from the request, so an accepted `timeout_secs` is honored rather than cut short by a
//!   fixed outer ceiling smaller than the inner one.
//! - `a_write_cancelled_mid_frame_tears_the_stream_down_instead_of_desyncing_it` — a deadline that
//!   expires inside `write_all` must not leave a partial frame on the shared stream for the next
//!   request's bytes to land inside.

use super::tests::serve_fake;
use super::*;
use crate::dto::ExecRequestDto;

/// An `ExecRequestDto` asking the guest for `secs` of runtime.
fn exec_with_timeout(secs: u64) -> ExecRequestDto {
    ExecRequestDto {
        timeout_secs: Some(secs),
        ..ExecRequestDto::new(vec!["sleep".to_string(), secs.to_string()])
    }
}

/// The forwarded request an `exec` of `secs` produces.
fn exec_request(secs: u64) -> EngineRequest {
    EngineRequest::Exec(VmId("vm-1".to_string()), exec_with_timeout(secs))
}

// M12 follow-up: `timeout_secs` is an accepted input the guest honors, so the bridge's budget for
// that call must strictly EXCEED it — an outer deadline smaller than a legitimate inner one 500s
// the request while the guest command keeps running, which is an accepted input silently not
// honored. Asserted as the invariant (budget > timeout, with the margin), not as a constant, across
// timeouts on both sides of the fixed VM ceiling — 840 and 841 straddle the crossover exactly
// (840 + the 60 s margin IS the 900 s floor), so both branches of the `max` are driven.
//
// RED on the fixed `BROKER_VM_CALL_BUDGET` for every exec: with a 900 s ceiling the 3600 s case
// yields 900 s, which is *less* than the guest timeout it forwards. RED on a dropped
// `EXEC_BUDGET_MARGIN` (`Duration::from_secs(secs).max(BROKER_VM_CALL_BUDGET)`): the 899 s case
// yields exactly the 900 s floor, which clears the guest timeout by 1 s instead of the margin the
// vsock round-trip and the output capture need. That second inverse used to be invisible: the margin
// assertion carried an `|| budget >= BROKER_VM_CALL_BUDGET` escape clause, and the floor assertion
// below asserts precisely that disjunct unconditionally — so the margin clause could never fail.
#[test]
fn an_execs_budget_strictly_exceeds_the_guest_timeout_it_forwards() {
    for secs in [1_u64, 60, 840, 841, 899, 900, 901, 3_600, 86_400] {
        let budget = call_budget(&exec_request(secs));
        let guest = Duration::from_secs(secs);
        assert!(
            budget > guest,
            "an exec's bridge budget ({budget:?}) must outlive the guest timeout it forwards \
             ({guest:?}), or the bridge fails the call while the guest command still runs"
        );
        // Unconditional: where the floor wins, the floor is itself ≥ timeout + margin, so this holds
        // on both branches of the `max` and there is no case for an escape clause to excuse.
        assert!(
            budget >= guest + EXEC_BUDGET_MARGIN,
            "the budget must clear the guest timeout by the {EXEC_BUDGET_MARGIN:?} margin \
             (got {budget:?} for {guest:?})"
        );
        assert!(
            budget >= BROKER_VM_CALL_BUDGET,
            "the VM-lifecycle budget stays the FLOOR (got {budget:?} for {guest:?})"
        );
    }

    // No timeout asked for: the plain VM-lifecycle ceiling, unchanged.
    let no_timeout = EngineRequest::Exec(VmId("vm-1".to_string()), ExecRequestDto::new(vec![]));
    assert_eq!(call_budget(&no_timeout), BROKER_VM_CALL_BUDGET);

    // The other arms are untouched: real guest work gets the VM budget, control ops the short one.
    assert_eq!(
        call_budget(&EngineRequest::Destroy(VmId("vm-1".to_string()))),
        BROKER_VM_CALL_BUDGET
    );
    assert_eq!(
        call_budget(&EngineRequest::List),
        BROKER_CONTROL_CALL_BUDGET
    );
    assert!(BROKER_CONTROL_CALL_BUDGET < BROKER_VM_CALL_BUDGET);
}

// The derived budget is client-controlled arithmetic: `timeout_secs: u64::MAX` makes
// `Instant::now() + budget` PANIC ("overflow when adding duration to instant") in the cap-dropped,
// network-facing parent. The call must still be served. Driven end-to-end through `call` (against a
// fake broker that replies at once) so it proves the wiring, not just `deadline_from` in isolation.
//
// RED on `tokio::time::Instant::now() + budget` in `call`: the test panics instead of returning.
#[tokio::test]
async fn an_absurd_exec_timeout_is_served_instead_of_panicking_the_deadline_math() {
    let client = serve_fake(0);
    let out = client
        .exec(&VmId("vm-1".to_string()), exec_with_timeout(u64::MAX))
        .await
        .expect("an absurd timeout must be served, not panic the parent's deadline math");
    assert_eq!(out.stdout().expect("decode"), b"sleep 18446744073709551615");

    // The clamp is a horizon, not a disabled deadline: it is still a bounded instant in the future.
    let deadline = deadline_from(call_budget(&exec_request(u64::MAX)));
    assert!(deadline > tokio::time::Instant::now());
    assert!(deadline <= tokio::time::Instant::now() + CALL_DEADLINE_HORIZON);
}

// M12 follow-up (the partial-write desync): the request writer is SHARED, so a deadline that
// expires inside `write_all` drops the future after a partial frame and the next request's bytes
// land inside it — every later reply on that stream is then read against the wrong frame boundary.
// A write that has begun must therefore either complete or take the stream down with it.
//
// The peer here never reads, so the socket send buffer fills and the 8 MiB frame is provably still
// being written when the 200 ms budget expires. The assertions are on the WIRE: the peer sees a
// truncated frame followed by EOF (the write half was shut down), and no later request's bytes
// appended to it.
//
// RED on the single `timeout_at` around lock-acquire + `write_frame`: the stream is left open and
// desynced, so `read_to_end` never reaches EOF and the 5 s guard fires.
#[tokio::test]
async fn a_write_cancelled_mid_frame_tears_the_stream_down_instead_of_desyncing_it() {
    let (client_sock, broker_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    // Split, and hold the peer's write half: the parent's reply reader must NOT see EOF, or the
    // in-flight call would fail through the (already gated) broker-death drain instead of the write
    // deadline this test is about.
    let (mut broker_rd, _broker_wr) = broker_sock.into_split();
    let client =
        BrokerClientEngine::with_call_budget(client_sock, Some(Duration::from_millis(200)));

    let huge = "x".repeat(8 * 1024 * 1024);
    let err = client
        .exec(&VmId("vm-1".to_string()), ExecRequestDto::new(vec![huge]))
        .await
        .expect_err("a frame this size cannot be written to a peer that never reads");
    assert_eq!(err.kind().status_code(), 500, "{}", err.message());
    assert!(
        err.message().contains("torn down"),
        "the caller must be told the stream is gone, not just that the write was slow: {}",
        err.message()
    );

    // THE discriminator: the peer drains what was written and then reaches EOF. Without the
    // teardown the stream stays open (and desynced) and this read never returns.
    let mut drained = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), broker_rd.read_to_end(&mut drained))
        .await
        .expect("a write cancelled mid-frame must SHUT DOWN the write half, not leave it desynced")
        .expect("read");
    assert!(n > 4, "the write had genuinely begun (only {n} bytes)");
    let announced = u32::from_be_bytes(drained[..4].try_into().expect("4 bytes")) as usize;
    assert!(
        n < 4 + announced,
        "the frame must be TRUNCATED for this test to mean anything: wrote all {n} of {} bytes",
        4 + announced
    );

    // And the next caller is refused outright rather than handed the desynced stream.
    let next = client
        .list()
        .await
        .expect_err("a torn-down stream must refuse later requests");
    assert!(
        next.message().contains("torn down"),
        "the refusal must name the teardown: {}",
        next.message()
    );
}

// Positive control for the teardown: a healthy stream is NOT torn down by a request that is merely
// over the frame cap — that one is rejected before any byte reaches the wire, and the connection
// keeps serving. Without the pre-write check an over-cap request would poison the whole bridge.
#[tokio::test]
async fn an_over_cap_request_is_rejected_without_tearing_the_stream_down() {
    let client = serve_fake(0);
    let over_cap = "x".repeat(MAX_BRIDGE_FRAME_BYTES + 1);
    let err = client
        .exec(
            &VmId("vm-1".to_string()),
            ExecRequestDto::new(vec![over_cap]),
        )
        .await
        .expect_err("an over-cap request frame must be refused");
    assert_eq!(
        err.kind().status_code(),
        413,
        "an over-cap request is the client's, not an internal error: {}",
        err.message()
    );
    assert_eq!(
        client.list().await.expect("the bridge keeps serving").len(),
        2,
        "an over-cap request must not tear down a healthy connection"
    );
}
