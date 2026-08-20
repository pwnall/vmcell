# Workaround inventory — what we carry, and what the 2026-08-20 dependency bump dismissed

Companion to the dependency-modernization pass recorded in `docs/implementation-notes.md`. It answers
one question per row: **is this workaround still load-bearing after moving every dependency to its
latest stable?**

Method: each carried workaround was re-tested against the *current* upstream rather than against its
recorded rationale. Where a rationale was a hazard rather than a blocker, the pass tried the move,
observed what actually broke, and replaced the rationale with the measured one. Two recorded
rationales turned out to be wrong in exactly that way (rows V1 and A1) — the pattern this project
already tracks under "re-verify the premise anchors before cutting".

## Verdicts at a glance

| # | Workaround | Verdict after this bump |
|---|---|---|
| V1 | `vendor/vhost` + `vendor/vhost-user-backend` — the `SET_VRING_ENABLE` patch | **KEEP** — upstream still unpatched; blocker re-diagnosed |
| V2 | `=` pins on `vhost`/`vhost-user-backend`/`vm-memory` | **KEEP** — mechanically required by V1 |
| A1 | 14 RUSTSEC ignores from `tun-tap → tokio 0.1` | **KEEP, but the cause is now precisely located** |
| A2 | `RUSTSEC-2024-0436` (`paste`) | **DISMISSED** — crate left the graph |
| A3 | `RUSTSEC-2023-0089` (`atomic-polyfill`) | **KEEP** — still reachable via `postcard → heapless 0.7` |
| B1 | `vmcell-bench`'s own `hudsucker`/`hyper` requirements | **DISMISSED** — deleted; the break it caused is now unrepresentable |
| C1 | CI builds `e2fsprogs` from source | **KEEP** — runner image still below the floor |
| C2 | CH installed from git HEAD (README) | **DISMISSED** — replaced by the pinned release; closed a design gap |
| D1 | crosvm `--disable-sandbox` | **KEEP** — architectural, not a version artifact |
| D2 | `clear_ambient_caps` defaults `false` | **KEEP** — blocked on fd-passing, not on a dependency |
| D3 | Broker engine channel is JSON, not postcard | **KEEP** — serde-attribute semantics, not a version artifact |
| D4 | `/tmp/vmcell-vmid` / `-segid` outside `XDG_RUNTIME_DIR` | **KEEP** — deliberate cross-process rendezvous |
| D5 | Duplicate `ifreq` in guest-tools beside the steward's | **KEEP** — recorded deviation with a divergence guard |
| D6 | `jip-nftables` kept as an empty feature | **KEEP** — removal is semver-breaking |

---

## V1 — the vendored `vhost` patch. KEEP, and the recorded reason was wrong.

**What it is.** `vendor/vhost` (0.16.0) and `vendor/vhost-user-backend` (0.22.0), wired by a
workspace-root `[patch.crates-io]`, relax the `VHOST_USER_F_PROTOCOL_FEATURES` check on
`SET_VRING_ENABLE`, which QEMU sends *before* `SET_FEATURES` finalizes. The backend copy carries the
precise form (accept early, re-enforce once `features_acked`) plus a red-on-inverse test.

**Is upstream fixed?** **No.** Checked against the published `vhost` 0.17.0 and `vhost-user-backend`
0.23.0 *and* against `main` at `c96c3722` — all three still carry the unconditional
`self.check_feature(VhostUserVirtioFeatures::PROTOCOL_FEATURES)?;`. The patch stays.

**The reason recorded at the pin site was not the blocker.** It said a bump "silently drops the
patch". That is a hazard, not an obstacle — and `scripts/check-vendored-vhost.sh` was *designed* for
the bump, reading the pinned version out of the vendored crate's own manifest precisely so
`=0.16.0 → =0.17.0` is a supported move rather than a permanent "not applicable" green. This pass
performed the whole re-vendor: extracted 0.17.0/0.23.0, re-applied both patch hunks and the carried
test, updated the pins, and the gate stayed green.

**What actually blocks it:** `fuse-backend-rs` 0.14.0 — latest, and the in-process virtio-fs backend
behind `experiment-fuse` — requires `virtio-queue 0.17` and pins `vm-memory = "=0.17.1"` **exactly**.
`vhost` 0.17 and `vhost-user-backend` 0.23 both require `vm-memory 0.18` + `virtio-queue 0.18`, so
the four move as one set; and `fs/in_process.rs` hands a `virtio_queue::DescriptorChain` straight to
`fuse-backend-rs`'s `Reader::from_descriptor_chain`. Two majors cannot meet at that bridge. The bump
compiles under default features and fails under `--features experiment-fuse` — which `--all-features`
and the `cargo hack` powerset both select — with `expected DescriptorChain<_>, found DescriptorChain<...>`.

**Why the trade goes the other way.** `vhost` 0.17's headline fix is the `SHMEM` protocol feature-bit
position (21 → 22). vmcell negotiates no SHMEM on any device it ships (vhost-user-vsock, and the
smoltcp vhost-user-net NAT), so the fix is **inert here**, while the cost is breaking a shipped
feature. The re-vendor was reverted and the pin-site rationale replaced with the above.

**Unblocks when:** `fuse-backend-rs` publishes a release built on `vm-memory 0.18` / `virtio-queue
0.18`. Re-check upstream's `set_vring_enable` first; the re-vendor procedure itself is now proven.

## A1 — 14 of 15 advisory ignores are one crate, used for one call.

`deny.toml` carried 16 advisory ignores. Tracing every one to its root:

```
tun-tap 0.1.4 → tokio-core 0.1.18 → tokio 0.1.22 → {tokio-uds, tokio-io, tokio-tcp, tokio-udp,
    tokio-fs, tokio-codec, tokio-sync, tokio-timer, tokio-reactor, tokio-executor,
    tokio-threadpool, tokio-current-thread} + mio 0.6 → mio-uds → net2
```

That is **14 of the 16** carried before this pass (13 tokio-0.1 crates plus `net2`) — and, with
`paste` removed below, **14 of the 15 that remain**. They are not dismissible by bumping:
`tun-tap 0.1.4` **is** the latest release, and the crate is unmaintained.

What makes this worth recording: `tun-tap` is used at exactly **one** call site —
`crates/vmcell/src/net/tap.rs:237`, `tun_tap::Iface::without_packet_info(name, Mode::Tap)` — i.e. a
single `TUNSETIFF` ioctl. The trait seam above it was already scrubbed of `tun_tap` types (a recorded
v24 deviation; `vmcell-broker` compiles without the dependency at all and is the living gate on that).
So the whole tokio-0.1 subtree, and 14 permanent advisory exemptions, hang off one ioctl.

**Not done here, deliberately.** Replacing it is a source change to the privileged tap path, not a
dependency bump, and it must be done the way AGENTS.md requires — a `#[repr(C)]` `ifreq` defined once
with `size_of`/offset asserts against the ABI, never inline byte-math (the repo already has that shape
in `vmcell-steward::netif`, and the 18-byte-`ifreq`-writing-22-bytes incident is why the rule exists).
It needs live privileged validation, so it belongs in its own change with its own gate. Flagged as the
single highest-leverage dependency cleanup available: **−14 advisory ignores, −~25 lockfile crates,
+1 ioctl.**

## A2 — `paste`: dismissed.

`RUSTSEC-2024-0436` (`paste 1.0.15`, unmaintained) entered via the netlink stack. `rtnetlink`
0.21 → 0.23 with `netlink-packet-route` 0.30 → 0.33 dropped it; `paste` is no longer in the graph at
any target. The ignore was removed — a dead ignore is exactly the crate-less placeholder `deny.toml`'s
own header forbids. `cargo deny check advisories` stays green at 15 ignores.

## A3 — `atomic-polyfill`: still live.

Reachable only off-host-target, via `postcard 1.1.3 → heapless 0.7.17 → atomic-polyfill 1.0.3`.
`postcard` is already latest. Unblocks when postcard moves to `heapless` 0.9 (which uses
`portable-atomic`). Kept, rationale unchanged.

## B1 — `vmcell-bench`'s duplicate proxy crates: dismissed.

`crates/vmcell-bench/Cargo.toml` carried its own `hudsucker = "0.24"` and `hyper` requirements, used
only inside `mitm_proxy_config` to build a `vmcell::proxy::doubles::TestDouble`. That is the precise
anti-pattern `proxy::doubles`' module docs warn against — and vmcell's `hudsucker` 0.24 → 0.25 bump
broke it with the exact error those docs predict:

```
expected `vmcell::proxy::doubles::hudsucker::Body`, found `hudsucker::Body`
```

Both requirements were **deleted** rather than realigned, and the call site now names the crates
through `vmcell::proxy::doubles`' re-exports. The duplicate-version break is now unrepresentable
rather than merely repaired, the in-tree composition root demonstrates the documented contract instead
of contradicting it, and the lockfile shed a whole second tungstenite/sha1/digest subtree.

## C2 — Cloud Hypervisor from git HEAD: dismissed, and it closed a design gap.

The README said `cargo install --git …`. Upstream bumps the crate version immediately after cutting a
release, so that installs an **unreleased** `main` build reporting the *next* version — which is why
this host had a `cloud-hypervisor v54.0.0` when **no v54 tag exists** and v53.0 (2026-07-12) is
latest, and why the design's own Appendix C recorded "the live matrix ran on 54.0.0".

This is not cosmetic. `main` is ~237 commits past v53.0, and three of those land on surfaces vmcell
asserts against: vsock local-port ownership and RST-reply behavior (the steward's whole transport), CH
API errors remapped from HTTP 500 to 404/400/409, and additions to CH's own seccomp filter — which the
confinement battery inspects on a *running* CH. A suite passing against that build is not evidence
about the version CI pins.

Fixed on three fronts: the README installs the checksum-verified pinned release (matching `ci.yml`);
`pins.json` now commits `cloud_hypervisor: "v53.0"`, which is design §17's named "one-line close" and
makes the snapshot cache key's existing fold hash a real value; and the design's §17 gap and Appendix
C entry were updated from "wired and idle" to closed.

## The unchanged rows, in one line each

- **C1 — CI builds e2fsprogs from source.** The runner image ships 1.47.0; `MIN_E2FSPROGS_VERSION` is
  1.47.1 (the `-d <tarball>` form). Still required; the pin moved 1.47.2 → 1.47.4. (This host has
  1.47.2 with `-d`, so the ext4 battery runs here rather than recording a skip.)
- **D1 — crosvm `--disable-sandbox`.** Its multiprocess minijail is incompatible with single-process
  supervision; the Layer-2 deny-list carries `Enforcing` instead. A validated architectural reversal.
- **D2 — `clear_ambient_caps: false`.** Clearing it strips the `CAP_NET_ADMIN` the VMM needs for tap
  setup (Appendix A reversal 9). Blocked on fd-passing, not on any dependency.
- **D3 — broker engine channel is JSON.** The forwarded DTOs use `skip_serializing_if`/`default`,
  which postcard's non-self-describing format corrupts (Appendix A reversal 10). A format property,
  not a version artifact.
- **D4 — `/tmp/vmcell-vmid` / `/tmp/vmcell-segid`.** The recorded cross-process-rendezvous exception
  to the `XDG_RUNTIME_DIR` rule.
- **D5 — duplicate `ifreq` in guest-tools.** Recorded deviation; the divergence guard pins fields and
  ioctl numbers, not just total size.
- **D6 — `jip-nftables` empty feature.** The dependency is gone; the feature is kept because removing
  a public feature is semver-breaking even on a `publish = false` crate.

## Also checked, nothing carried

`virtiofsd` (1.14.0) and `vhost-device-vsock` (0.3.0) are both already at latest, as are all six
cargo dev tools (`just`, `cargo-nextest`, `cargo-hack`, `cargo-deny`, `cargo-semver-checks`,
`cargo-machete`) and `actionlint` (1.7.12). No pinning workaround exists for any of them.

One dependency was **replaced** rather than bumped, which is neither a workaround nor a version
move: the kernel tarball's XZ decode went from `lzma-rs` 0.3.0 (newest release **2023-01-04**) to
`lzma-rust2` 0.19.0 (**2026-08-16**), measured at **1.64×** on the real 142 MiB tarball with
byte-identical output, declared `default-features = false` so the crate's own
`forbid(unsafe_code)` applies. Details and the measurement table are in the implementation-notes
entry. `lzma-rs` stays in the lockfile regardless — `am-fs-erofs` depends on it.

One item worth naming that is *not* a workaround: `arrayref` was the subject of a supply-chain
incident (0.3.10 published malicious, since deleted). HEAD's lockfile carried the last-safe 0.3.9;
this pass's `cargo update` removed the crate from the graph entirely via `blake3` 1.8.7. Nothing to
carry, but worth the line.
