#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::path::PathBuf;
use vmcell::config::{
    ConsoleMode, Egress, KernelVerbosity, NetConfig, RootfsSource, VmConfig, build_kernel_cmdline,
};
use vmcell::vmm::PerVmResources;

// The append-only kernel-cmdline contract (invariant F3): `with_kernel_arg` → `build()`'s
// `validate_extra_kernel_arg` → `is_reserved_cmdline_arg`, and the composition
// `build_kernel_cmdline` emits.
//
// WHO SUPPLIES THE BYTES: a remote REST client. `CreateVmRequest::extra_kernel_args` is an
// arbitrary `Vec<String>` that the daemon copies onto its `LaunchSpec`, feeds to
// `with_kernel_arg` one by one, and lands on the guest kernel command line — appended LAST, after
// every token vmcell owns. The kernel applies duplicate parameters IN ORDER, so a token that slips
// past the predicate overrides the one vmcell owns.
//
// PRODUCTION PRECONDITION MIRRORED: the args go through the builder, which is the honest path (the
// daemon does exactly this) and the only place the validator runs. `build()` performs NO filesystem
// access, so the target is pure — no KVM, no fs, no VMM.
//
// PROPERTY: no ACCEPTED argument may carry the kernel-normalized key of a token vmcell emits. The
// owned key set is not restated in the harness — it is DERIVED by composing the very same config
// with no extra args, so it tracks whatever the builder actually emits. The reference key is the
// name the KERNEL would read, applied to the OUTPUT rather than restated as the predicate: see
// `cmdline_key` for the two folds and the two `lib/cmdline.c`/`kernel/params.c` clauses behind them.
// It is red on the real historical defects: drop the dash fold from the predicate and
// `kvm_intel.nested=1` is accepted beside the owned `kvm-intel.nested=0` (finding `m1`); accept a
// token carrying `"` and `"init=/evil` is accepted beside the owned `init=` (finding `m3`). It is
// likewise red if the `vmcell_` prefix rule is dropped. A second assertion pins the splice itself —
// the composed line is exactly the owned line with each accepted arg appended as ONE unmodified
// token, which is red if an arg carrying whitespace is ever accepted (it would forge a second boot
// token). A third bans the quoting metacharacter from every accepted token, which is what the key
// comparison alone cannot state: a `"` in the MIDDLE of a token collides with no key at all (it
// toggles `in_quote`, so whitespace stops separating parameters and everything after it is swallowed
// into this token's value), and a leading one on an ALIAS — `"rw`, the very token `m3` reports —
// re-keys to `rw`, which vmcell reserves but does not emit, so no duplicate-key oracle can see it.
//
// A caller arg colliding with ANOTHER CALLER ARG is deliberately not a finding: `extra_kernel_args`
// is the caller's own list and repeating a key in it is their business, not an override of a token
// vmcell owns.
//
// WHAT IT CANNOT DO, stated so nobody reads more into a green run: it cannot discover a MISSING
// ALIAS. `rw` inverting the owned `ro`, or `quiet` overriding `loglevel=`, share no key with the
// token they override, so no duplicate-key oracle sees them — that is why the alias block in
// `RESERVED_CMDLINE_KEYS` is hand-maintained with its own negative test. Finding a missing alias
// needs a model of the kernel's semantics, which no byte-oriented fuzzer has. (The `"`-prefixed form
// of an alias is caught anyway, by the metacharacter assertion rather than by the key oracle — that
// is a property of the character, not knowledge of the alias.)
//
// The configs built here carry NO shares, deliberately: `vmcell_share=` legitimately repeats once
// per share, so a shared-directory config would make the duplicate-key property false by design.

/// The kernel's own parameter-name normal form, in the two folds its parser applies before it has a
/// name to compare: a leading `"` stripped, the text before the first `=` taken, `-` folded to `_`.
///
/// Both folds are the kernel's, and the oracle has to model BOTH or it shares the predicate's blind
/// spot rather than checking it:
///
/// * `lib/cmdline.c`'s `next_arg` strips one leading quote before the parameter name begins
///   (`if (*args == '"') { args++; in_quote = 1; }`), so the token `"rw` IS the parameter `rw`. The
///   oracle keyed it as `"rw`, which collides with nothing — the exact hole finding `m3` names in its
///   own text, and the reason a fuzzer running against the pre-fix predicate would have reported
///   nothing while `"rw` cleared `MS_RDONLY` under the owned `ro`.
/// * `kernel/params.c`'s `dash2underscore` folds `-` to `_` inside the name for every `parameq`
///   comparison, which is finding `m1`.
///
/// Written as the kernel's parse, deliberately, not as a copy of `normalize_cmdline_key`: an oracle
/// that mirrors the predicate can only ever agree with it.
fn cmdline_key(token: &str) -> String {
    let token = token.strip_prefix('"').unwrap_or(token);
    token.split('=').next().unwrap_or(token).replace('-', "_")
}

fuzz_target!(|input: (u8, Vec<&str>)| {
    let (knobs, args) = input;
    // One input is one command line, not a stress test: the property is about collisions between a
    // caller token and an owned one, which a handful of args already exercises.
    if args.len() > 8 {
        return;
    }

    let rootfs = if knobs & 1 == 0 {
        RootfsSource::Erofs {
            image: PathBuf::from("/var/lib/vmcell/rootfs.erofs"),
        }
    } else {
        RootfsSource::Block {
            image: PathBuf::from("/var/lib/vmcell/root.img"),
            overlay: None,
        }
    };
    let net = if knobs & 2 == 0 {
        NetConfig::None
    } else {
        NetConfig::Unprivileged {
            egress: Egress::Blocked,
            host_services_port: None,
        }
    };
    let verbosity = match (knobs >> 2) & 3 {
        0 => KernelVerbosity::Quiet,
        1 => KernelVerbosity::Balanced,
        2 => KernelVerbosity::Verbose,
        _ => KernelVerbosity::Debug,
    };
    let console = if knobs & 16 == 0 {
        ConsoleMode::Uart
    } else {
        ConsoleMode::VirtioConsole
    };

    let base_builder = || {
        let mut b = VmConfig::builder("/var/lib/vmcell/vmlinux", rootfs.clone())
            .net(net.clone())
            .kernel_verbosity(verbosity)
            .console_mode(console)
            .nested_virt(knobs & 32 != 0);
        if knobs & 64 != 0 {
            b = b.init("/usr/sbin/custom-init");
        }
        b
    };

    let mut builder = base_builder();
    for arg in &args {
        builder = builder.with_kernel_arg(*arg);
    }
    let Ok(cfg) = builder.build() else {
        return;
    };

    let res = PerVmResources {
        cgroup_name: "vmcell-vm-1".to_string(),
        tap_name: None,
        netns_name: None,
        segment: None,
        vhost_user_socket: None,
        vmid: 1,
        guest_cid: 3,
        tmp_dir: PathBuf::from("/run/vmcell/1"),
    };
    let cmdline = build_kernel_cmdline(&cfg, &res, "").expect("cmdline composition");

    // The owned token set, DERIVED from the same config with no caller args.
    let owned_cfg = base_builder()
        .build()
        .expect("the arg-free config is valid");
    let owned_cmdline = build_kernel_cmdline(&owned_cfg, &res, "").expect("cmdline composition");

    let mut owned: HashMap<String, &str> = HashMap::new();
    for token in owned_cmdline.split_whitespace() {
        let key = cmdline_key(token);
        if let Some(previous) = owned.insert(key.clone(), token) {
            panic!(
                "vmcell emits kernel key {key:?} twice on its own ({previous:?} then {token:?}) in \
                 {owned_cmdline:?}"
            );
        }
    }

    for arg in &args {
        let key = cmdline_key(arg);
        assert!(
            !owned.contains_key(&key),
            "accepted extra kernel arg {arg:?} carries kernel key {key:?}, which vmcell already \
             emits as {:?}; caller args go LAST and the kernel applies duplicates in order, so it \
             overrides the token vmcell owns — cmdline {cmdline:?}",
            owned.get(&key)
        );
    }

    // The kernel's quoting metacharacter never survives acceptance. Stated separately from the key
    // comparison above because it is a different failure: a leading `"` re-keys the token (caught
    // above, via `cmdline_key`), while a `"` anywhere else toggles `in_quote` so whitespace stops
    // separating parameters and every token emitted after it is swallowed into this one's value —
    // which collides with no key and would pass the whole oracle above.
    for arg in &args {
        assert!(
            !arg.contains('"'),
            "accepted extra kernel arg {arg:?} carries the kernel's quoting metacharacter; \
             `lib/cmdline.c`'s `next_arg` strips a leading one (re-keying the token) and toggles \
             `in_quote` on any other (swallowing the tokens after it) — cmdline {cmdline:?}"
        );
    }

    // The splice is append-only: the composed line is the owned line with each accepted arg
    // appended as ONE unmodified whitespace-separated token, in order.
    let mut expected = owned_cmdline.clone();
    for arg in &args {
        expected.push(' ');
        expected.push_str(arg);
    }
    assert_eq!(
        cmdline, expected,
        "the extra-arg splice is not append-only/one-token-per-arg"
    );
});
