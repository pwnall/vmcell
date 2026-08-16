# vmcell — Handoff notes (v3): the v33 delta register, deltas 5–10

Written at `540d8a3`, with deltas 1–4 of design v33's §18 register landed, pushed, and
live-validated. This file is the pick-up point for whoever continues the pass. It carries three
things the other documents deliberately do not: **what is left**, **what the premises actually say
at HEAD** (re-verified, not remembered), and **how to work in this repo** — the operational
knowledge that is not a design fact and therefore has no home in
`docs/implementation-notes.md`.

Read `AGENTS.md` first; it is binding and this file does not repeat it.

> **FIRST ACTION FOR THE NEXT SESSION.** The commit carrying this file also carries a code fix
> (§5) whose verification is **incomplete**. Verified on that tree: `cargo test -p vmcell --lib`
> (528 pass), `just gates` (exit 0), `cargo fmt --all --check`, `typos`. **Not** verified: a full
> `just ci` (clippy across the feature powerset, rustdoc, `cargo deny`, `machete`, `semver-checks`)
> and the live suites. Two overlapping `just ci` runs deadlocked on the cargo build lock and were
> killed rather than waited out. So:
>
> ```bash
> set -o pipefail; timeout 3000 just ci > /tmp/ci.log 2>&1; echo "CI_EXIT=$?"; tail -20 /tmp/ci.log
> ```
>
> then the live suites per §3.10. **Never run two `just ci` invocations at once** — they block on
> the same lock and each looks hung.

---

## 1. Where the pass stands

| Commit | Delta | Live-validated |
|---|---|---|
| `d4eabdf` | Quality-gates v5's two one-time reconciliations | n/a (comments only) |
| `2d5296c` | 1 — the steward rename | yes |
| `d9addbb` | 2 — the feature vocabulary + the one intersection site (F6) | yes |
| `e83422e` | 3 — the two-directional conformance kit (§10.6) | yes |
| `540d8a3` | 4 — steward placement (§3.5, C8) | yes |

**Not started: deltas 5, 6, 7, 8, 9, 10.**

The register's ordering has been honored so far — 1 alone; then 2–3 against today's artifact set, so
the kit could go red on facts already in the tree; then 4, the unlock. The remaining internal
dependencies (§18's "Bundling and order"): **5 needs 4** (landed), **8 needs 7**, **9 needs 2–7**,
**10 needs 4** (landed). Deltas 8 and 10 are separable and ride the pass only if ready; 9 is the
capstone and necessarily lands last.

Contract-crate versions at HEAD: `vmcell` **0.16.0**, `vmcell-artifact-validator` **0.4.0**,
`vmcell-protocol` 0.5.0, `vmcell-steward` 0.3.0.

**Deltas 2–7 are ONE breaking release.** `vmcell`'s `0.15.0 → 0.16.0` ledger entry is written to
**grow** as each delta lands rather than minting a version per delta — it already carries deltas 2
and 4. Extend that entry; do not add `0.17.0` for delta 5.

The last live run at `540d8a3`: privileged **156/156**, unprivileged 4/4, daemon 14/14, validator
3/3, USB passthrough included. Skips were the expected three Firecracker capability-honest ones
(`unprivileged_vhost_user_net` ×4, `nested_virt` ×2, `virtio_fs_shares` ×1).

---

## 2. Verified premise anchors for deltas 5–10

These were **re-verified against HEAD `540d8a3` by six independent per-delta agents**, each of which
decomposed its delta's `*Premise:*` paragraph into individual clauses and checked every one. This
exists because §18's own convention says so: *"Every register so far has carried at least one
shipped-fact premise that was empirically false (v28: two; v30: five — the count is the argument).
… treat a stale premise as a stop-and-check."* Deltas 1–4 have also moved the tree under 5–10.

**Seventeen clauses are not confirmed as written** — seven STALE, ten moved by deltas 1–4 (two of
those change behavior), plus one unverifiable that gates an empirical claim. Everything else
verified CONFIRMED and is not repeated.

#### Stop-and-check: STALE clauses (7)

The premise states a fact that is false at HEAD, or a directive whose target does not exist.

| Δ | Clause | What is actually true |
|---|---|---|
| 5 | "the in-code *EXACTLY {overlay, /proc, /dev}* comment understates its own code and is corrected by this delta" | Already corrected, and not by a delta. `d4eabdf` (pre-delta-1) rewrote all three sites to the four-mount set: `crates/vmcell-steward/src/main.rs:172-174`, `:237-239`, `:279-281`. Delta 5 relocates already-true text; it corrects nothing. |
| 5 | "(§3.5 What) the `vsock_port` seam defaults to the shared const and the steward parses `vmcell_steward_port=` from /proc/cmdline" | **Host half FIXED after this verification ran** (same session, see §5 below): `VsockEndpoint::with_port` now substitutes the declared port at both control-plane dials (`crates/vmcell/src/orchestrator.rs` `steward()` and `connect_sessions()`), gated by `a_declared_service_port_is_honored_on_both_sides`. **The GUEST half is still delta 5's and does not exist**: zero hits for `vmcell_steward_port` under `crates/vmcell-steward`, so a non-default port is emitted and dialed but never bound. Until delta 5 lands the parse, `Service { port }` must use 5000. |
| 6 | *Migration:* "`build-kernels` callers add `--all` (CI recipes updated in the same commit)"; §10.5's "the CI nightly matrix passes `--all`" | No CI recipe and no justfile recipe invokes `build-kernels`. `.github/workflows/` holds only `ci.yml` and `fuzz.yml`; the sole CLI invocation is `ci.yml:370` (`vmcell … build`, not `build-kernels`). There is no nightly kernel matrix workflow. The real edit set is four prose/comment sites: `justfile:227`, `README.md:28/:390/:393`, `crates/vmcell/tests/usb_passthrough.rs:203`. |
| 8 | "the merged-tar tail exists" | The one inject+pack tail exists (`crates/vmcell/src/artifact/rootfs/mod.rs:471`) but it is not a *tar* tail: `tar2erofs.rs:364 tar_to_erofs` merges tar streams straight into `HashMap<PathBuf, fs_erofs::mkfs::Node>` and returns EROFS bytes, under `#[cfg(feature = "am-fs-erofs")]`. No merged tarball is ever materialized, so `mkfs.ext4 -d <tarball>` has nothing in-tree to consume, and §15.4's "pack from the merged tar" (design:4674) names an artifact that does not exist. |
| 8 | "…and synthesizes parents" | Parent synthesis exists (`tar2erofs.rs:396-423`) but lives **inside** the erofs-specific `tar_to_erofs`, not in a source-agnostic step — stated verbatim in-tree at `tar2erofs.rs:1133-1137` ("`build_node_map` does NOT create parent directories — only `tar_to_erofs` does"). An ext4 route reusing the shared parts gets a node map with holes. |
| 8 | "the merged tail already guarantees [parents] … and the delta's gate pins it" | True for the erofs path only, for the same reason. Neither `build_node_map` (`tar2erofs.rs:82`) nor the `pack_erofs_with_injection` prologue (`rootfs/mod.rs:471-549`) synthesizes parents. |
| 9 | Companion: §10.5's registry illustration gives `debian-systemd` the image `docker.io/library/debian` (design:3455) | Unrealizable. No digest of `docker.io/library/debian` ships systemd — proven for the pinned one against the cached layer. The example must name a different repo or extend the mmdebstrap producer; nothing in the tree resolves it. |
| 9 | Gate as written: "drop the unit file and the steward must be unreachable; the fail-loud message names the placement" | A `Service` cell with a missing steward produces a transport/connect timeout, not a placement refusal: `MicroVm::steward()` fails loud only when `steward_port()` is `None` (`orchestrator.rs:1511, :1558, :1768`), and `Service` has a port. The design says so itself (design:4653-4656). The only placement-naming message is `INELIGIBLE_PLACEMENT` on `snapshot()` (`orchestrator.rs:2374-2379`, raised at `:2098-2102` and `:2410`). Respecify the expected message before writing the gate. |

#### Stop-and-check: MOVED_BY_DELTAS_1_4 clauses (10)

The claim survives; the anchor or vocabulary moved. Two of these change behavior.

**Behavior changed — read these:**

- **Δ10 "exposing `init` over REST would be enough to express a control-plane-keeping cell" — FALSE as of delta 4.** `VmConfigBuilder::build()` derives `StewardPlacement::None` when `init` is `Some` and no placement was named (`crates/vmcell/src/config.rs:1630-1634`). A REST body of `{"init": "/sbin/init"}` alone silently produces exactly the steward-less cell the surviving half of the rule forbids. The daemon cannot delegate that rejection to the library.
- **Δ10 `StewardPlacement::Service{port}` / `::None` now exist** (`config.rs:148-201`), so the DTO has something to expose. Note `port` is **u32**, not u16, and the type derives only `Copy, Clone, Debug, PartialEq, Eq` — **no serde**; `crates/vmcell/src/config.rs` contains zero `Serialize` derives.

**Anchor/vocabulary drift only:**

- Δ5 "2,867-line `main.rs`" → 2869 at HEAD (2867 at `77a3868` → 2870 after `d4eabdf` → 2866 after delta 1's rename → 2869 after delta 4). Production is `:37-2100`; `#[cfg(test)] mod tests` is `:2102-2869` (768 lines). The premise figure is the whole file, not the production body.
- Δ5 "`VSOCK_PORT` private (`main.rs:523`)" → delta 4 retired the private const; `crates/vmcell-steward/src/main.rs:529` is `use vmcell_protocol::STEWARD_VSOCK_PORT as VSOCK_PORT;`. The one literal 5000 is `crates/vmcell-protocol/src/lib.rs:177`; `crates/vmcell/src/vmm/mod.rs:1202` is a const bound to it (deliberately not a `pub use`, per the delta-4 ledger).
- Δ7 "`--agent-musl` skips only the steward stage (`main.rs:1040-1042`)" → behavior and lines exact, but delta 1 renamed the flag to `--steward-musl` (`crates/vmcell-cli/src/main.rs:106`). Zero `agent_musl` occurrences remain in `crates/`. §4.2's prose (design:1216) already uses the new name.
- Δ8 cmdline anchor "`config.rs:372-379`" → now `crates/vmcell/src/config.rs:458-465` (shifted by deltas 1, 2, and 4's +477-line `StewardPlacement` block).
- Δ8 "zero `mkfs.ext4`/`mke2fs`/`e2fsprogs`/`debugfs` hits" → one tracked hit now: `_typos.toml:21`, a spell-check allowance pre-provisioned by delta 1's `2d5296c` for this delta. Substantive claim survives — no producer exists.
- Δ9 dependency "`why_absent(SnapshotRestore)` can carry `Source::Rootfs(\"debian-systemd\")`" → landed: `crates/vmcell/src/feature.rs:191-234, :527`, fixture at `:748/:762`. One intersection site, `resolve_cell_features` (`orchestrator.rs:2300-2317`).
- Δ9 dependency "`snapshot()` on a `Service` cell returns the C8 refusal" → landed: `config.rs:149-199`, `orchestrator.rs:2098-2102` and `:2410`, refusal text `:2374-2379`, tests `config.rs:4290-4346`.

#### One UNVERIFIABLE that gates an empirical claim

Δ8's "e2fsprogs ≥ 1.47.1 **with libarchive**" cannot be checked from a host carrying only 1.47.2. What is verified: libarchive is **dlopen'd, not linked** — `ldd /usr/sbin/mke2fs` lists no libarchive; `strings` carries `libarchive.so.13`, 18 `archive_*` symbols, and "you need libarchive to be able to process tarballs". **A probe implemented as `ldd | grep archive` misclassifies this host as lacking libarchive.**

---

### Delta 5 — the steward as a library; service mode (R5, §3.5, C1)

Split the 2869-line `main.rs` into a library plus a thin binary, and parameterize the PID-1 contract by placement so a `Service` steward runs under somebody else's init.

**Blockers**

1. **The port is plumbed nowhere.** See the STALE entry above. Delta 5 owns the guest half (the `vsock_port` seam, §3.5: strict-or-default-with-a-logged-warning); the **host half is named by no delta's *What***. Decide whether 5 takes it or record the deferral — until both land, `Service { port: != 5000 }` is an accepted input that is silently ignored, an AGENTS.md fail-loud violation delta 4 introduced.
2. **No shutdown path exists to parameterize.** `serve_vsock` (`crates/vmcell-steward/src/main.rs:784-889`) is an unconditional `loop {}` with no exit condition, spawned **detached** at `:448` (JoinHandle dropped). `Service`'s "stop accepting, tear down live sessions per C3, exit" has nothing to hook: it needs a shutdown flag threaded into the poll/accept loop plus a retained joinable handle. New mechanism, not a parameterization.
3. **The C3 teardown has no global handle.** The `Sessions` table is created **per connection** inside `serve_connection` (`main.rs:909`); `teardown_sessions` is called from that one function's exit (`:918`). The delta's own gate asserts "C3 residue gone" on the SIGTERM path, which needs a registry of live connections (or a broadcast every `serve_loop` observes) first.

**Notes that matter**

- **Two SIGTERM arms, not one.** Besides the main signal loop (`main.rs:441-461`), the degraded fallback at `:465-488` registers a `signal_hook::flag` on SIGTERM (`:474`) and its poll loop also exits into `power_off_never_returns()` at `:496`. A per-mode policy covering only the first arm leaves a `Service` steward powering off the machine when handler registration failed.
- **The fatal set is larger than the premise's four mounts.** Beyond tmpfs `/mnt` (`:188-200`), overlay (`:205-215`), `/proc` (`:255-265`), `/dev` (`:266-276`), `pivot_root` (`:224-229`) returns `Err`, and the bare `?` sites (`:185`, `:186`, `:201-203`, `:219`, `:232`, `:234`, `:235`) are equally fatal. `Pid1`-scoping must move all of them.
- **The steward cannot see `StewardPlacement`.** `crates/vmcell-steward/Cargo.toml` depends only on vmcell-protocol, postcard, vsock, rustix, signal-hook, libc, tracing, tracing-subscriber. Adding `vmcell` drags tokio in and reddens `scripts/check-lean-tree.sh:58`. The guest needs its own placement enum (design sketch: `GuestPlacement`) or a shared one in vmcell-protocol. `AgentOptions`/`AgentPlacement` are already grep-banned (`scripts/ban-legacy-terms.sh:141`) — steward-shaped names from the first commit.
- **No new dependency needed.** `rustix::process::getpid` and `rustix::process::set_child_subreaper` are both under the already-enabled `process` feature, `#[cfg(linux_kernel)]`, safe wrappers. Mode selection and the subreaper bit add zero deps, zero `unsafe`, leave `check-lean-tree.sh` green. That ban is crate-scoped, not target-scoped, so the lib/bin split is invisible to it.
- **The thin-main gate cannot live in `main.rs`** — a `#[cfg(test)] mod` is itself an item beyond `main()`, so the gate fails itself. Put it in `lib.rs` with `include_str!("main.rs")`, copying `crates/vmcell/src/vmm/cloud_hypervisor.rs:2049-2085` (`mod virtiofs_pacing_gate`): split at the first `#[cfg(test)]`, drop comments, collapse whitespace, assert an **exact** expected count so a scan matching nothing reddens. Reuse its sibling `capability_guard_gate`'s `production_code` normalizer.
- Lints are already in place: `lib.rs:11-40` carries a byte-identical deny family to `main.rs:6-36`. No new header, but `deny(missing_docs)` + `deny(unreachable_pub)` means every promoted item needs rustdoc, with full paths for intra-doc links in a merged `//!` block.
- `DEFAULT_MAX_REAPED_STATUSES`'s doc (`lib.rs:50-55`) is `Pid1`-worded and must reword for `Service`, where the bound is load-bearing only **with** the subreaper bit. `wait_for` (`lib.rs:311-343`) blocks on a Condvar with **no timeout**, which is why the delta's red-on-inverse hangs rather than fails.
- Adding `mini-init` to `GUEST_TOOLS_APPLETS` cascades, mostly by compile error: `crates/vmcell-guest-tools/src/main.rs:123/:136` (const-assert, compile error until added), `crates/vmcell/src/artifact/rootfs/mod.rs:618-623` (symlink emission, automatic), the manifest pin at `:762-790`, and `crates/vmcell-artifact-validator/src/checks.rs:281` — which goes **red against any rootfs packed before the applet existed**, so `just test-validator` needs the rebuild too.
- `mini-init` as `init=` is legal (`validate_init_path`, `config.rs:643-659`; `echo-server` is the precedent) but delta 4 changed the composition: every mini-init leg must call `.steward_placement(StewardPlacement::Service { port })` explicitly, or `build()` derives `None` and `steward()` fails loud before any transport.
- **Rebuild and re-bless are mandatory**: guest-side code in both vmcell-steward and vmcell-guest-tools, so `vmcell build --kernel-source host-make` then `just bless`. Delta 1's rebuild left a stale `target/vmcell-artifacts/guest_agent`; the stage now emits `steward` — delete stale artifacts.
- **CI is blind to this delta's real surface**: `just ci` runs the unit suite only; `crates/vmcell/tests/` is `#[ignore]`d behind KVM. Delta 4 shipped two message assertions green in CI and red on hardware.
- Versioning: extend `vmcell`'s existing 0.15.0→0.16.0 ledger entry (it already carries deltas 2 and 4). `vmcell-steward` is `publish = false` and not a §10.4 contract crate.

### Delta 6 — the artifact registry: rootfs + handler kinds, lazy, digest-only (R2+R7, §10.5, F7)

Mirror the working kernel registry onto rootfs and handler kinds, with one shared merge/collision/sort core.

**Blockers**

1. **Ordering conflict on `xattrs` — 6 vs 7.** §10.5's rootfs entry sketch (design:3455) carries `"xattrs": "preserve"` and delta 6's *What* says entries carry `xattrs` declarations, but `XattrPolicy` does not exist at HEAD and is delta 7's deliverable; §4.7 assigns the contradictory-pair reject to "a §18 delta-7 red-on-inverse leg" (design:1455). The register orders 6 before 7 and does not list "6 needs 7". Landing 6 first means either an accepted-then-ignored `xattrs` key or a typed refusal 7 immediately removes. Decide before cutting.
2. **The "unmoved default cache key" gate is unsatisfiable as literally written.** `fold_pins_identity` (`crates/vmcell/src/artifact/mod.rs:647-650`) folds the **raw** `COMMITTED_PINS` bytes (`include_str!`, `mod.rs:627`), so any pins.json edit moves `ResolvePinsStage::cache_key` **and** `fast_artifacts_fingerprint` (`mod.rs:210-227`, tag `vmcell-test-artifacts-fingerprint-v2` at `:215`). What is achievable: `RootfsStage::cache_key` folds the resolved `rootfs_image`/`rootfs_digest` **values** (`rootfs/mod.rs:268-284`), so it stays put if `rootfs.default` resolves to today's pair. Scope the assertion to the stage keys, and either bump the fingerprint tag to v3 (the v30-delta-1 precedent, `mod.rs:213-215`) or state why not.
3. **Where the legacy-singleton reject lives.** `merge_pins_documents` (`mod.rs:996-1010`) merges leaf-wise and recursively; `parse_pins_overlay`'s shape check is top-level only. An overlay `"rootfs": {"debian-systemd": {…}}` over a singleton baseline produces a **hybrid** object holding `image`/`digest` leaves and label keys, and it passes the shape check. The reject must run on the **merged** document inside the new rootfs resolver, and the committed baseline must move to map form in the same commit — otherwise the gate leg passes on the overlay and misses the real case.

**Notes that matter**

- **A third consumer of the flat rootfs keys, in a different role.** `resolve_builder_base` (`crates/vmcell/src/artifact/rootfs/mod.rs:428-449`) falls back from `builder_base_*` to `("rootfs_image","rootfs_digest")` to pick the **in-VM builder base image**, and is `pub` so out-of-crate builders resolve it identically. Reshaping `rootfs` into a map silently changes which image builds kernels/rootfses unless the fallback is re-pointed at `rootfs.default`. Full read set: `rootfs/mod.rs:272-277`, `:311-316`, `:433`; fixtures `crates/vmcell-rootfs-builder/src/lib.rs:335-362`, `crates/vmcell-kernel-builder/src/lib.rs:492`.
- **No `.features` sidecar producer exists at HEAD — only consumers.** `FeatureDeclaration::load_beside` is called at `orchestrator.rs:2281` (kernel) and `:2292` (rootfs); `render_manifest` (`feature.rs:402`) has zero production callers. Live consequence, and delta 6 is the natural fix site: the canonical `rootfs.erofs` has no sidecar → `FeatureDeclaration::baseline` → empty stances → nothing removes `Feature::XattrPreserved` (only an explicit `false` removes, `feature.rs:475-489`) → `FeatureSet::has(XattrPreserved)` reports **true** for an artifact whose packer strips every xattr (`xattrs: vec![]` at ten sites in `tar2erofs.rs`, pinned by `test_pax_xattrs_are_not_preserved` at `:817`).
- **Sidecar naming trap.** `load_beside` uses `artifact.with_extension("features")` (`feature.rs:385-390`), which eats a trailing dotted component — exactly why `kernel_filename_suffix` sanitizes `.`→`-` (`kernel.rs:208-226`). The mirrored rootfs/handler filename law must sanitize dots the same way or a label like `12.4` silently collides sidecars. The tree already holds two laws here: `resolved_config_path` (`kernel.rs:269-278`) deliberately **appends** `.config` instead. Pick knowingly and say which.
- **The gate that will fight you:** `scripts/ban-kernel-key-composers.sh` pins the sanctioned home by path suffix `/vmcell/src/artifact/kernel.rs` with exact counts (`sanctioned_artifact=2`, `sanctioned_pin=2`) and treats a moved home as "gate misconfigured", exit 1 — not a pass. Extracting a shared core out of kernel.rs trips it; update the counts in the same commit. A new rootfs/handler key law earns its own ban script plus a `test-` twin, both in the `gates` recipe (`justfile:298+`) and nowhere else.
- `KNOWN_PINS_NAMESPACES` grows 9 → 10 (`handlers`; `rootfs` exists). It is **not** the accept-list — the dispatch is (`mod.rs:679-682`) — but both move because two parity tests gate both directions: `mod.rs:3363` (roster ⊆ dispatch) and `mod.rs:3397` (dispatch ⊆ roster, by **source-text scan** of `match name {` arms, with an exact-count vacuity assert at `:3428-3431`). An arm written across multiple lines, or with the pattern not on the same line as `=>`, silently drops out of `arms` and trips that assert.
- `bundle`'s artifacts-dir walk (`crates/vmcell-cli/src/main.rs:555-575`) enumerates labelled kernels via `kernel_label_from_filename` + `kernel_artifact_key` + `config_artifact_key`. Labelled rootfs/handler artifacts need the mirrored walk or they silently drop from the manifest — the recorded N-BIN-4 defect class, re-armed. `main.rs:1219` already asserts `kernel_label_from_filename("rootfs.erofs") == None`.
- Internals are private and semver-free: `reject_sanitized_label_collision` (`mod.rs:1117`), `sort_kernel_registry` (`:1143`), `kernel_entry_fragments` (`:1156`). The eight key/name composers are all `pub` contract surface, so mirrored composers are additive contract additions needing the ledger. Do not mint a version — `vmcell` is 0.16.0 and the 0.15.0→0.16.0 entry says in its own words that it grows as each delta lands.
- Fuzz: a `registry_entry` `[[bin]]` target is directed; the roster law needs a `fuzz/Cargo.toml` entry plus its `fuzz_targets/<name>.rs` twin or `fuzz.yml` GUARD 5 fails. Precedent: delta 2's `feature_manifest`. Budget fine (16 × 300s vs a 14400s ceiling).
- §10.5's "(§4.2's `--tools` flag is the per-run override form)" reads as shipped but is not — `--tools` is delta 7's *What* and does not exist at HEAD.
- Delta 2's machinery is ready: `Feature::parse` (`feature.rs:160`, hard-errors on unknown tokens), `parse_manifest` (`:327`), `render_manifest` (`:402`). The registry's `"features": {…}` map is JSON while the sidecar is `name = true|false` lines — the JSON→`FeatureDeclaration` reader must reuse `Feature::parse`, not a second token table (F6).
- Planning sizes: `artifact/mod.rs` 3674 lines, `kernel.rs` 2149, `rootfs/mod.rs` 1267, `rootfs/oci.rs` 721, `tar2erofs.rs` 1366, `vmcell-cli/src/main.rs` 1392, `tests/kernel_toolkit.rs` 389 (the battery to mirror).

### Delta 7 — external repacking + per-artifact xattr policy (R6 first half; §4.2, §4.7)

Make `pack_erofs_with_injection` usable from outside a vmcell checkout (`--tools`, `--work-dir`) and thread an `XattrPolicy` through the one inject+pack tail.

**Blockers**

1. **The declaration surface belongs to delta 6, which is unstarted.** §4.7 (design:1443-1445) puts `XattrPolicy` in the registry entry and derives `Feature::XattrPreserved` at registry resolution. At HEAD the pins `rootfs` namespace is the flat v30 shape. Either land 7 after 6, or land the pack-tail parameter + applet + gates now with a CLI-flag declaration and defer the registry key — and record the split, because R7 explicitly distinguishes a path-shaped *override* from a digest-shaped *registration*.
2. **The live gate has no input as spelled.** §4.7 wants "packs a `Preserve` artifact from a base carrying a `security.capability`, boots it, reads the xattr back in-guest". The pinned base's cached layer (`target/vmcell-artifacts/oci-cache/sha256-e95a6c7e…`) has 3262 members and **zero** PAX xattr records; the six raw `security.capability` byte hits are inside file *contents*, and there is no `bin/ping` in the image. Combined with §4.7's "vmcell's own injected files carry no xattrs under either policy" and `ExtraFile` having no xattr field, **nothing in the default pipeline can produce an xattr for the readback to find.** Pick and state a source: a synthesized tar layer fixture (the `test_pax_xattrs_are_not_preserved` builder at `tar2erofs.rs:818-832` already produces exactly one), or a different digest-pinned base verified to carry one. The KVM-free `Preserve` twin is unaffected.

**Notes that matter**

- **Delta 2 already minted the vocabulary this delta must satisfy.** `Feature::XattrPreserved` exists (`crates/vmcell/src/feature.rs:90`), is in `Feature::ALL`, names itself `"xattr_preserved"` (`:132`), is `!is_backend_capability`, and has conformance id `"conformance.xattr_preserved"` (`crates/vmcell-artifact-validator/src/conformance.rs:228`) whose probe plan is `ProbePlan::Undecidable(NO_PROBE_YET)` (`:200-206`). The feature is declared-but-always-false today; delta 7 makes it true and gives it a real probe. `battery_check_ids()` is built from `Feature::ALL`, so the conformance arm is already rostered.
- **The eleventh node site the premise's "ten `xattrs: vec![]`" count misses.** The hardlink arm (`tar2erofs.rs:204-242`) builds a `Node::File` with `xattrs: xattrs.clone()` from the already-merged target (`:225`), not from its own PAX header. Trivially correct under `Strip`; under `Preserve` a hardlink member carrying its own SCHILY.xattr record gets the target's substituted silently. Decide explicitly and pin it.
- **Cache-key mechanics — two independent folds, only one is the one §4.7 names.** `OCI_ROOTFS_STAGE_VERSION` = 4 (`rootfs/mod.rs:238`) is pinned by the literal-value test `rootfs_stage_version_pins_the_delta6_bump` (`:961-967`), which asserts `== 4` and **will go red** on your bump — rename it and its message, do not delete it. Policy threads into `fold_rootfs_injection_identity` (`:348-…`), shared with `vmcell-rootfs-builder`. Separately, `fast_artifacts_fingerprint_with` (`artifact/mod.rs:210-247`) hashes `tar2erofs.rs`, `rootfs/mod.rs`, `rootfs/oci.rs` verbatim, so any packer edit invalidates `.build.stamp` and forces a live re-pack — the live suites see your change without a manual rebuild.
- **The `xattr` applet is a roster change with four consequences.** `GUEST_TOOLS_APPLETS` is `["ip","curl","kvm-ok","echo-server"]` (`crates/vmcell-protocol/src/lib.rs:162`). Adding an entry propagates to: the const-asserted dispatch table (`crates/vmcell-guest-tools/src/main.rs:123/:136`, missing arm = compile error); `rootfs_injection_manifest` (`rootfs/mod.rs:597`, loop `:618`), which makes `/vmcell-tools/xattr` a rejected `--inject` dest for free via `is_reserved_injection_path` (`:83-100`); the validator's `guest_tools_on_path` check (`crates/vmcell-artifact-validator/src/checks.rs:271-326`), which **fails against any rootfs packed before the roster grew** — `just test-validator` needs a rebuilt rootfs; and `guest_tools_closure_hash`, which folds vmcell-protocol, so the cache key does move (no stale-helper trap).
- **What `--tools`/`--work-dir` must sever.** The hard dependency is `crate::artifact::workspace_root()` (`pub(crate)`, `artifact/mod.rs:1303-1309`), which **silently falls back to the start dir** when no `crates/vmcell-protocol/Cargo.toml` marker is found — outside a checkout it returns CWD and fails only at `guest_tools_closure_hash(&ws_root)?` (`guest_tools.rs:59`) with a file-read error, not "you are not in a vmcell checkout". The red half of the gate needs that message improved, not relied on. Soft dependency: `artifacts_dir()` (`artifact/mod.rs:50-60`). Pins are `include_str!`-embedded (`COMMITTED_PINS`, `mod.rs:627`), so `ResolvePinsStage` is **not** a third checkout dependency — §4.2's "exactly one hard, plus one soft" is accurate. `StewardStage` is escapable (`steward.rs:46/:53`, skipped with `--steward-musl`).
- **The example workspace runs the CLI from inside the vmcell checkout**: `examples/downstream-kernel/ci-check.sh:97` does `cd "$repo"` and `:98` sets `cli=(cargo run … -p vmcell-cli …)`. The new from-outside-a-checkout gate must change directory out of it (or use an installed/copied binary) or it proves nothing. Today's two `oci2-erofs` legs (`:110-113`, `:114-117`) are fail-fast boundaries that never reach the packer.
- **Signature-change blast radius.** `pack_erofs_with_injection` gains a parameter: production callers `crates/vmcell/src/artifact/rootfs/oci.rs:230` and `crates/vmcell-rootfs-builder/src/lib.rs:281`; tests `rootfs/mod.rs:1168, :1190, :1246`; both `cfg` arms (`:471` and `:629`) change together. `RootfsStage` (`:213`) and `MmdebstrapRootfsStage` (`vmcell-rootfs-builder/src/lib.rs:65`) each gain a field — neither is `#[non_exhaustive]`, so it is a `constructible_struct_adds_field` break (delta 4 ledgered the same class for `VmConfig`). `cargo semver-checks` does **not** cover `vmcell-rootfs-builder`; that break is caught only by compilation.
- **Do not cite the non-feature arm as the refusal model.** `#[cfg(not(feature = "am-fs-erofs"))] pack_erofs_with_injection` (`rootfs/mod.rs:629-642`) returns the string-carrying `Error::Artifact`, not `CapabilityUnavailable`/`Unsupported` — AGENTS.md's feature-gate rule is not met at that site.
- `no_production_site_hand_spells_a_feature_string` (`feature.rs:1137-1186`) rejects any production `feature: "` literal equal to a `Feature::name()` — build the xattr refusal via `Error::unsupported(vmm, Feature::XattrPreserved)`.
- `ExtraFile`'s own doc ("Regular files only in v1: symlinks and xattrs stay out", `rootfs/mod.rs:24`) and the strip-rationale comment at the Regular arm (`tar2erofs.rs:121-127`, which covers all six tar-derived sites by intent, not co-location) both need revisiting by this delta.
- The erofs writer already has the plumbing: `am-fs-erofs` 0.1.1 carries `XattrSpec` (mkfs.rs:268), `xattrs` on every `Node` variant and on the inode plan, a POSIX-ACL helper and a long-prefix dictionary. Nothing to add there.
- Version state: `vmcell` 0.16.0 (`Cargo.toml:215`), `vmcell-artifact-validator` 0.4.0 (`:67`) — the design's "0.14 / validator 0.2" baseline is already superseded by deltas 1-4, as expected.

### Delta 8 — the ext4 producer (R6 second half, §4.7)

Produce an ext4 rootfs image behind the same Stage machinery, consumable as `RootfsSource::Block`.

**Blockers**

1. **Delta 7 has not landed and 8 needs 7** (the register's own "8 needs 7"). `XattrPolicy` has zero hits in `crates/`; `--tools`/`--work-dir` are absent. The "XattrPolicy-aware merged tail" the producer consumes does not exist, and 8's gate explicitly repeats 7's from-outside-a-checkout leg.
2. **There is no merged tar for `mkfs.ext4 -d`, and no source-agnostic parent synthesis** (see the two STALE entries). Delta 8 must first hoist merge + parent synthesis + libc6 scan out of the erofs-typed `tar_to_erofs` into a producer-neutral step, or serialize the node map back out to a tar. That refactor touches `pack_erofs_with_injection` — named §10.4 contract surface, so a deliberate ledgered `vmcell` bump, not an incidental edit.
3. **The design contradicts itself about whether a `Block` root is writable, and the code sides with read-only.** §4.7 (design:1478) justifies the producer by "workloads that need a writable, POSIX-complete root"; §5.2 (design:1566) says the same root "mounts strictly read-only". At HEAD: `build_kernel_cmdline` emits `ro` unconditionally (`config.rs:496`); `rw` is in `RESERVED_CMDLINE_KEYS` (`config.rs:585`) with the rationale at `:582-584` naming exactly the Block+noload corruption; and under `Pid1` the steward unconditionally tmpfs+overlay+pivot_roots with zero rootfs-source conditionality (`crates/vmcell-steward/src/main.rs:188-227`). Resolve which claim the delta implements — the "fixture tree that outgrows the tmpfs overlay" motivation is not reachable as the code stands.

**Notes that matter**

- **Empirically validated on this host (2026-08-15, uid 1000, no sudo):** e2fsprogs 1.47.2; `mkfs.ext4 -q -F -d good.tar good.img` populates root-owned (`0 0`) entries with modes preserved; a 20-byte `SCHILY.xattr.security.capability` PAX record round-trips byte-identically (`debugfs -R 'ea_list /usr/bin/ping'`); char device nodes keep major/minor (`05:01` for `/dev/console`); a missing parent directory fails loud with `__populate_fs_from_tar: … cannot find directory "./deep/nested"` and exit 1 — no implicit synthesis, no silent partial image. Reproduction material: `/tmp/claude-1000/-home-pwnall-workspace-vmcell/d43e72c1-63fe-49ad-9bb1-2798c98a47e5/scratchpad/mktar.py`, with `good.tar` and `orphan.tar` retained.
- **Journal, and why it bears on the writable-root question.** `mkfs.ext4 -d` produces `has_journal` by default. `rootflags=noload` suppresses journal recovery, and ext4 refuses a read-write mount when recovery is suppressed. If writable-root is the goal, the producer must emit `-O ^has_journal` (making noload a no-op) or the cmdline law changes. Treat the kernel-side half as a hypothesis to confirm on a live boot — no guest was booted.
- **Zygote/clone hazard created the moment `Block` becomes producible.** `clone_ineligible_feature` (`orchestrator.rs:2387-2427`) has arms for unprivileged net, segment, virtio-fs shares, placement resync and USB passthrough — and **no `RootfsSource` arm**. No clone path rewrites `cfg.rootfs` (`zygote.rs`/`lineage.rs` only construct `Erofs`). A zygote fan-out over a writable ext4 root passes eligibility and attaches one image read-write to N guests. `RootfsSource::Block::overlay` exists for exactly this (`config.rs:1944-1945`, "materialized by the CoW store") but nothing in production sets it. Either add an arm to the shared predicate (both `check_clone_eligible` at `zygote.rs:351` and the restore boundary read it) or wire per-clone overlay materialization.
- **Stage plumbing collision.** `RootfsStage::name()` returns `"rootfs"` and `out_path()` returns `<target>/rootfs.erofs` (`rootfs/mod.rs:242-248`). "Behind the same Stage" cannot mean the same `name()`/`out_path()` pair — §5.1 records exactly that hazard for `InVmKernelStage` vs `PrebuiltKernelStage`. Pick a distinct artifact key, or take it from delta 6's registry rootfs kind if 6 lands first. The cache key must fold producer identity plus `fold_rootfs_injection_identity` (`rootfs/mod.rs:332, 250-263`) or a policy/producer change reuses a stale image.
- **No external-tool version probe exists anywhere to copy — you are writing the first.** `virtiofsd` (`fs.rs:129`), `nft` (`net/tap.rs:542`), `make` (`artifact/kernel.rs:683,708,728`), `cargo` (`artifact/steward.rs:54`, `guest_tools.rs:66`) are all spawned bare with no version check; `git grep '"--version"' -- crates scripts` returns zero. The `VMCELL_*_BIN` resolver law is VMM-binary-only, so `mkfs.ext4` follows the bare-name shape. The gate spec already rules: spawned external binary = the QEMU/nft carve-out, no `deny.toml` change.
- **Already handled, do not re-solve:** CH forces the raw image type on the root disk, pre-empting the sector-0 superblock-write bug on the writable `Block` path (`cloud_hypervisor.rs:130-133`, `docs/implementation-notes.md:158-159`).
- **Stale comment on code you will edit:** `cloud_hypervisor.rs:184-185` claims a virtio-fs rootfs arm is "unreachable here … kept for match exhaustiveness", but `RootfsSource` has only `Erofs` and `Block` (`config.rs:692-705`). There is no VirtioFs variant.
- Sizing: the packer buffers whole file contents in memory (`Node::File { data: Vec<u8> }`) and returns `Vec<u8>`. `mkfs.ext4` needs a pre-sized target file (`-d` will not grow it), so the tool route needs an explicit image-size decision the erofs packer never faced. For the preferred crate route, check the `am-fs-*` family (`am-fs-erofs` 0.1.1 / `am-fs-core`, Cargo.lock:57-65) for an ext4 sibling before searching wider.
- There is no `just test-ext4` (nor `test-systemd`); the roster is test-unit, test-unit-undelegated, test-privileged, test-daemon, test-unprivileged, test-validator, test-crosvm, test-usb-passthrough (`justfile:104-246`).
- Delta 8 needs no new feature flag: `Feature::XattrPreserved` already exists (`feature.rs:90-91`, `ALL: [Feature; 12]` at `:99-112`), and there is no ext4/writable-root feature. The in-guest `xattr` applet the ext4 xattr leg needs is delta 7's — another reason 7 lands first.

### Delta 9 — the systemd proof cell (capstone; §15.4, opt-in)

Boot real Debian systemd as PID 1 with the steward as a service, proving R1+R2+R5+R6+R7 composed.

**Blockers**

1. **Deltas 5, 6, 7 are unstarted and 9 needs 2-7.** Missing at HEAD: the rootfs registry (no `resolve_rootfs_registry`; pins.json:28-30 still the singleton shape), `XattrPolicy` (zero occurrences), service-mode steward and the `mini-init` applet (`GUEST_TOOLS_APPLETS` still `["ip","curl","kvm-ok","echo-server"]`).
2. **The systemd-carrying artifact has no specified, reachable source.** The pinned base carries no `usr/lib/systemd/systemd`, no `systemctl`, no `usr/sbin/init` — verified exhaustively against the cached layer (3262 entries): only unit files, `libsystemd.so.0`, dpkg shims, plus `usr/lib/apt/apt.systemd.daily`. The OCI path has no package-install step (`rootfs/oci.rs:128-215`, `rootfs/mod.rs:526-560`). The alternative producer (`crates/vmcell-rootfs-builder/src/lib.rs`) hardcodes `--include=curl,ca-certificates` (`:253`), needs privileged mode plus a live mirror, and is not digest-registerable under R7. Decide provenance before writing the recipe. (§10.5's own example image is unrealizable — see STALE.)
3. **Enabling the steward unit is not expressible today.** `ExtraFile` is "Regular files only in v1: symlinks and xattrs stay out" (`rootfs/mod.rs:24`, struct `:37-46`) and the packer's symlink injection is reserved for the applet roster (`rootfs/mod.rs:608-623`, `tar2erofs.rs:316-320`). A `multi-user.target.wants/vmcell-steward.service` symlink cannot be baked via `ExtraFile`. Extend the injection surface or use a regular-file enablement shape — and pin whichever, because a silently-not-enabled unit looks exactly like the delta's own red-gate condition.
4. **Root filesystem writability.** `build_kernel_cmdline` emits `ro` unconditionally (`config.rs:493-496`) and `Erofs` is read-only; today's writable root comes from the PID-1 steward's tmpfs+overlay+pivot_root (`vmcell-steward/src/main.rs:172-234`), which `Service` placement removes by design. Real systemd on a bare read-only root needs `systemd.volatile=`, baked tmpfs units, or a writable `Block` image — and delta 8 is explicitly **not** a dependency of 9. Resolve before promising "boots real systemd as PID 1".
5. **A non-default `Service` port is host-only at HEAD** (the delta-5 STALE item). Until delta 5 lands the guest-side parse, the proof cell must use `Service { port: 5000 }` or the host dials a port nothing is bound to.

**Notes that matter**

- The steward binary is **already** injected into every rootfs unconditionally at `usr/sbin/vmcell-steward` (`rootfs/mod.rs:603`), so `ExtraFile` is needed only for the `.service` unit and its ExecStart target exists for free. That path is reserved against `ExtraFile` collisions; `/usr/lib/systemd/system/…` is not reserved, so the unit file injects cleanly.
- The same manifest overwrites `etc/ssl/certs/ca-certificates.crt` with vmcell's proxy CA (`rootfs/mod.rs:605-606`). On a full-Debian image that **replaces** the distro trust store — anything in the cell doing outbound TLS sees only the vmcell CA.
- The pack tail buffers the whole image in memory (`rootfs/mod.rs:25-26`). The current base is 81 MB uncompressed; a systemd-carrying Debian is several times that. Size the opt-in expectations for peak RSS.
- The xattr readback leg has no tool: no `xattr` applet in the roster, and Debian base does not ship `getfattr` (the `attr` package is absent from the layer). Depends on delta 7 shipping the applet, or on the chosen image carrying `attr`.
- **Kernel gap worth an early check:** `target/vmcell-artifacts/vmlinux.config` has CGROUPS, NET_NS, FHANDLE, EPOLL, SIGNALFD, TIMERFD, INOTIFY_USER, PROC_FS, SYSFS, TMPFS_XATTR/POSIX_ACL, SECCOMP, DMIID, AUTOFS_FS, UNIX all `=y`, plus microvm_config's DEVTMPFS(+MOUNT)/TMPFS/EXT4 — but `# CONFIG_CRYPTO_USER_API_HASH is not set` (`vmlinux.config:4873`), which systemd's README lists as required. If the cell wedges early, that is the first fragment to add, via the §5.6 kernel_fragments registry, not an ad-hoc edit.
- The unit must not carry `User=` (the steward never sets a uid; exec/session children inherit it — `vmcell-steward/src/main.rs:1211-1230` sets only env/PATH) and must not set `PrivateTmp=yes` (host-driven put_file/exec and the guest workload would see different `/tmp` namespaces).
- Templates to copy: `crates/vmcell/tests/rootfs_extra_files.rs` (a working live test that packs a rootfs with an `ExtraFile` and boots it); `justfile:216`/`justfile:246` for the opt-in recipe shape incl. the `VMCELL_SKIP_MANIFEST` export and the blessed-runner variable. Any new `scripts/*.sh` joins the one `gates` recipe.
- The conformance kit to run over the composition is already in place and bigger than a helper: `crates/vmcell-artifact-validator/src/conformance.rs` (1495 lines) exposes `Substrate::of/new`, `ConformanceSubject`, `probe_plan`, `judge`, `LiveProbe`, `battery_check_ids`, `ConformanceOptions`. Read it before designing the assertions — the four-leg matrix and paired positive-control ids are already specified there.
- Prose rosters to reconcile in implementation-notes when cutting: §15.4 (design:4676-4681) calls the cell a proof of "R1+R2+R5+R6+R7"; §18 says "9 needs 2-7". Both are satisfied by landing 2-7 first.
- Small stale doc-comment from delta 4, likely to mislead: `orchestrator.rs:674-678` still documents `control_plane_disabled` as "Set from `cfg.init` at construction", while `:1558`/`:1768` set it from `cfg.steward_placement.steward_port().is_none()`. Behavior right, comment pre-delta-4.
- CI reason nuance: CI already performs a digest-pinned OCI pull (`ci.yml:370`), so the opt-in reason is the extra image's size/time (this base is 29 MB gz / 81 MB raw), not network access.

### Delta 10 — daemon placement exposure (§11.5, separable)

Expose `StewardPlacement` over the daemon REST API so a `Service`-placement cell (which keeps the control plane) becomes expressible, scoping the "no `init=` over REST" rule.

**Blockers**

1. **The live gate cannot run at full strength until delta 5.** The delta's point is `Service{port}` **with a custom init**, but service mode is unstarted, so a REST cell with a custom `init` boots with no steward and `launcher.rs:242` (`vm.steward(None).await?`, the "Ready means ready" contract) errors the create. The register records only "10 needs 4". Either cut 10 after 5 (plus an artifact whose init starts the steward, i.e. delta 9's cell), or scope the live leg to `Service{port: 5000}` + `init: None` — deliberately legal per `config.rs:1636-1639` and `:1461-1464` — and record the scoping. Do not present a green `init: None` leg as proof the custom-init path works.
2. **Decide where the `StewardPlacement::None` rejection lives, and do not delegate it to the library** (see the MOVED entry: `build()` derives `None` from `init: Some`). The daemon must reject `init` without an explicit `Service` placement at its own boundary. Model: the existing fail-loud early check in `Registry::create` (`crates/vmcell-daemon/src/registry.rs:227-232`, the snapshot-eligibility 400). A 400 that fires only because the library refused downstream is a different rule with a different message.
3. **Decide the DTO shape before writing it.** `StewardPlacement` has no serde derives. Either mint a daemon-side mirror enum — the shape `NetMode` already uses (`dto.rs:63-84`, `#[serde(rename_all = "snake_case")]` plus a `snapshot_eligible()` helper, mapped in `launcher.rs::net_config`) — or add serde to the library type, which touches the §10.4 contract crate and costs a ledgered `vmcell` bump. The mirror is cheaper and precedented; the other choice silently converts a separable delta into a breaking-release delta.

**Notes that matter**

- **The existing round-trip test is not the gate, and would look like one.** `engine_rpc_round_trips_every_op` (`crates/vmcell-daemon/src/bridge/tests.rs:108`) sends `CreateVmRequest::create("vmlinux","rootfs.erofs")` — all defaults — and the fake's handler is `async fn create(&self, _req: CreateVmRequest)` (`bridge/tests.rs:30`), which **discards the request entirely**. No test in the tree proves any `CreateVmRequest` field survives the bridge. Adding fields and re-running it is theater in exactly the shape the register's completeness-audit convention warns about: the new test must have the fake capture the received request and compare field-for-field, with one field `Some` and a sibling `None`.
- **The C8 call-site gate will not fight you — and will not protect you.** `mod c8_call_site_gate` (`config.rs:4360-4460`) builds its corpus from `include_str!("orchestrator.rs")` + `include_str!("config.rs")` only (`:4362-4367`). A new `init`-or-placement reader in vmcell-daemon is invisible to it. Per the register's "a gate binds the call sites" convention, delta 10 names its own daemon-side call-site scan (or extends `production_lines()`'s file list).
- **OpenAPI will not block you either.** `crates/vmcell-daemon/src/openapi.rs` declares exactly one schema, `ErrorBody` (`:144, :207`); there is no `CreateVmRequest` schema, and P5's parity tests are route-level (`:220`, `:237`, `:312`). New request fields are undocumented but ungated. If you add a request schema, keep `every_ref_resolves_to_a_declared_schema` non-vacuous — its own comment (`:306-311`) records that it was vacuous once.
- **`semver-checks` does not cover this crate** (`justfile:507` gates `-p vmcell -p vmcell-artifact-validator`). Adding a public field to the non-`#[non_exhaustive]`, non-`Default` `CreateVmRequest` is source-breaking for out-of-tree Rust callers and nothing will tell you; it is wire-additive, which is what "old clients unchanged" actually means. Say which you mean in the ledger note. The crate's own `CreateVmRequest::create`/`::run` constructors (`dto.rs:168-176ff`) fill every field literally and need the new ones.
- **The typed client mirrors it for free**: `crates/vmcell-daemon-client/src/lib.rs:39` is `pub use vmcell_daemon::dto;`. Minting a second type in the client would be the defect. Its convenience constructors (`lib.rs:237, 253`) call the DTO constructors.
- **`init` is a guest path — do not route it through `resolve_artifact_path`.** Every other client-named thing in `create` is a store artifact name (`registry.rs:218-219, 237, 253`); `init` names a path inside the guest rootfs. The honoring site exists: `validate_init_path` (`config.rs:643-659`), and `RESERVED_CMDLINE_KEYS` (`config.rs:563-579`) already contains `"init"`, so the `extra_kernel_args` back door stays closed. `Registry` runs on the **broker (cap-holding) side** (`bridge.rs:76-82`), so this string crosses into the capped process — P2 holds (the broker parses the parent's JSON, not network input), but state it, because the reviewer will ask.
- **One free win**: `vmcell::Error::Config` already maps to `DaemonError::BadRequest` (`error.rs:112`), so three of the four refusals — `Pid1`+custom-init (`config.rs:1640-1650`), `Service{port: 0}` and `Service{port: u32::MAX}` (`:1655-1662`) — surface as 400 with the library's message and need no daemon code. Only the `StewardPlacement::None` refusal is genuinely daemon-side.
- **The text delta 10 must rewrite** is the doc comment on `CreateVmRequest::extra_kernel_args` (`dto.rs:152-158`); its stated failure mode ("it replaces the steward, so the daemon … could not `exec` or `stats` it") is exactly the half `Service{port}` repairs. There is no separate enforcement code — the rule is enforced structurally by the DTO having no `init` field.
- Total surface is small and every anchor is live: `dto.rs:113-159`, `registry.rs:217-275` (single `LaunchSpec` construction site at `:265`), `launcher.rs:18-39` and `:206-245`, `server.rs:187-189`. `launcher.rs` is 245 lines, `registry.rs` 1109, `dto.rs` 557, `bridge.rs` 814.
- Naming trap when reading: the **engine** channel is length-prefixed JSON (`bridge.rs:254-259`, reversal 10 cited at `:229`); the **broker control** channel is length-prefixed **postcard** (`crates/vmcell-broker/src/lib.rs:243, 292-309`). `CreateVmRequest` travels the JSON one (`EngineRequest::Create`, `bridge.rs:193-194`).
- Running the live leg: `just test-daemon` (`justfile:162-167`) builds `vmcelld`+`vmcelld-ctl`, wraps in `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh`, runs `-p vmcelld --run-ignored all` under the blessed runner; suite is `crates/vmcelld/tests/integration.rs` (1108 lines). Probe with `scripts/review-preflight-priv.sh` first.

---

## 3. Working advice — what this session learned the hard way

None of this is a design fact, so none of it belongs in `implementation-notes.md`. All of it cost
real time.

### 3.1 `just ci | tail` lies about its exit code

The recipe's status is `tail`'s, which is always 0. Several "CI green" readings early in this pass
were worthless. **Always capture it explicitly:**

```bash
set -o pipefail; timeout 3000 just ci > /tmp/ci.log 2>&1; echo "CI_EXIT=$?"; tail -20 /tmp/ci.log
```

The first honest run immediately surfaced four real failures that the piped runs had hidden. The
same trap applies to every `just <recipe> | tail` in a shell one-liner.

### 3.2 A gate you did not try to break is not a gate — and mine were wrong three times

This is the repo's own rule ("write the red-on-inverse first"), and it earned itself repeatedly.
Every gate written in this pass was **structurally unable to fail on its first cut**, in a way that
reading the code did not reveal:

* The F6 "no hand-spelled feature string" sweep keyed on `feature: "…"` **closing on one line**, so
  it walked straight past `MicroVm::snapshot`'s two-line prose refusal. A unit test caught what the
  gate missed — backwards.
* The F6 "one computation site" scan banned every `FeatureSet::intersect` call outside the
  orchestrator, which would have forbidden `vmcell-artifact-validator`'s `Substrate` **and every
  downstream consumer**. Only independent legitimate code running against it exposed the
  over-reach. It now scopes by derivation (`impl Vmm for`) rather than a crate list.
* The C8 discriminating leg — the single test §3.5 says catches a re-key onto `cfg.init` —
  hand-built the `MicroVm` and derived the predicate **itself**, so planting the exact regression it
  guards left it green. Routing it through `MicroVm::start` fixed it.

**Procedure that works:** copy the file, plant the violation, run the gate, confirm red, restore
from the copy, confirm green. Script it when a gate has N branches — deleting each branch in turn
and asserting the self-test reddens found that all 7 new `ban-legacy-terms` branches were
load-bearing, and that two of my first three "failures" were bugs in the *probe's* shell escaping,
not real gaps. Match branch lines as **fixed strings** (`grep -vF`), never as regexes.

### 3.3 CI cannot see the KVM-gated assertions

`just ci` runs the unit suite; the integration tests in `crates/vmcell/tests/` are `#[ignore]`d
behind KVM and only `just test-privileged` reaches them. Delta 4 shipped two message assertions that
were green in CI and **red on hardware**. If a change re-words any error message, grep
`crates/*/tests/` for assertions on it before believing CI.

### 3.4 A source-wide sweep needs an exclusion list that includes `vendor/` and `.claude/`

The delta-1 rename sweep corrupted `vendor/vhost/docs/vhost_architecture.drawio` (its `agent=`
attribute is draw.io's own **User-Agent** slot, and the file is a pinned vendored artifact) and
broke both `.claude/*.js` workflow scripts (their `agent(...)` is an undeclared **runtime global** —
the AI sub-agent spawner). **JS is not compiled, so `cargo check --workspace --all-targets` is
structurally blind to it.** Exclude `vendor/` and `.claude/` from any tree-wide textual sweep, and
after a sweep re-run `scripts/check-vendored-vhost.sh`.

Sentinel-protect before sweeping. The delta-1 protected set was: `hosted-compute-agent`,
`imp-guest-agent`, `User-Agent`, `user-agent`, `user_agent`, `Proxy-Agent`, `agent-ctl`, `agentic`,
`AGENT-<digit>`, `AGENTS`, `Agents`, `agents`. Even that missed the bare `agent=` XML attribute.

### 3.5 Don't rewrite history in the Cargo.toml ledgers

The ledger is a changelog. Its old entries name types **as they were called at those versions**
(`AgentClient` in the 0.3/0.4 entries). The rename sweep rewrote them; that was reverted. The new
entry is the one place the old→new mapping lives, and it says so. `#`-comments in a non-`.rs` file
are stripped by `ban-legacy-terms.sh`, so retired identifiers there do not trip the gate.

### 3.6 Retiring prose error strings creates a vacuity trap

F6 collapses ten prose refusals onto `Feature::name()`, so "the backend cannot snapshot" and "this
config carries a vhost-user device" **both** spell `snapshot_restore`. An exact matcher then
discriminates *less* than the substring it replaced — the substring was weak, but not vacuous. Every
converted leg needs its discrimination back explicitly. The four shapes used here:

1. **arm identity** against a named `Removal` const (`clone_ineligible_feature(&cfg) ==
   Some(INELIGIBLE_SEGMENT)`);
2. **two different shared consts** pinned apart via a `#[track_caller]` helper that composes the
   expected error from the const, so editing the const moves both sides;
3. asserting the `vmm` field's **provenance** alongside the feature (a config-sourced removal, not
   the backend's own);
4. explicit **pairing with the positive control** that must succeed, with a comment saying that the
   refusal/success pair is what makes the leg non-vacuous.

### 3.7 `cargo semver-checks` fires on shapes that break no consumer

Replacing a `pub const` with a `pub use` of the same value reads as
`pub_module_level_const_missing` — a removal — even though the path still resolves. For
`STEWARD_VSOCK_PORT` a const **bound to** `vmcell_protocol::STEWARD_VSOCK_PORT` was chosen over
ledgering a break that breaks nobody; there is still exactly one literal `5000` in the workspace.
Expect the tool to be right about real edges (it caught delta 3's missing validator bump before any
consumer could) and occasionally over-strict about aliasing.

### 3.8 `typos` reads a deliberate misspelling fixture as the defect

A test fixture that spells `snapshot_restore` with its last letter dropped trips the `typos` gate.
**Derive** the misspelling instead — `let real = Feature::SnapshotRestore.name(); let typo =
&real[..real.len() - 1];` — which is both drift-proof and gate-clean. Adding a `_typos.toml`
exception for a fixture is the wrong fix: an exception is a permanent blind spot, and someone will
later "correct" the fixture. (This paragraph originally quoted the misspelling literally and
reddened the gate on its own advice.)

### 3.9 Rustdoc intra-doc links in a module's `//!` block need full paths

`crates/vmcell/src/lib.rs` puts an outer `///` on each `pub mod`, which merges with the module
file's `//!` docs; a bare `[`Feature`]` there does not resolve and `-D warnings` hard-fails
`cargo doc`. Every sibling module already uses `[`crate::naming::…`]`-style full paths for this
reason. Follow the local convention.

### 3.10 Live suites: how to actually run them

Preflight first — never assume:

```bash
./scripts/review-preflight-priv.sh        # exit 0 = READY
just skip-manifest-reset
export VMCELL_TEST_USB_DEVICE=0bda:5634   # see below
systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged
just test-unprivileged                    # deliberately NOT under the runner
just test-daemon                          # wraps itself in the delegated scope
systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-validator
just skip-manifest-show
```

**The USB device on this box is the camera, `0bda:5634` (`uvcvideo`).** The two USB Ethernet
adapters (`0bda:8153`, `0bda:8156`) look ideal — the network is WiFi (`wlp170s0`), so they are free
— but **neither has a host driver bound** (they sit in USB configuration 2; `r8152` is loaded but
attached to nothing), so `usb_passthrough_qemu` panics with "no host driver bound, so the
restore-after-teardown assertion below would pass vacuously". That is the gate working. Probe with
plain `readlink` on `/sys/bus/usb/devices/*:*/driver` — `readlink -f` on a **dangling** link prints
the resolved path anyway and reads as a false positive. Avoid the two `0403:6001` FT232 UARTs: they
share one vid:pid and the resolver refuses an ambiguous match.

**Guest-side code is baked into `rootfs.erofs`.** Any change to `vmcell-steward` or
`vmcell-guest-tools` means nothing to a live suite until:

```bash
cargo build --release -p vmcell-cli && ./target/release/vmcell build --kernel-source host-make
```

The bare default is `prebuilt`, which silently swaps in a `vmlinux` lacking `CONFIG_KVM_INTEL` and
reddens `nested_virt`/`snapshot_restore`. Delta 5 changes the steward, so it **must** rebuild.
(Delta 1's rebuild left a stale `target/vmcell-artifacts/guest_agent` behind; the stage now emits
`steward`. Harmless, but delete stale artifacts so the directory listing stays honest.)

### 3.11 Subagents: scope by file, and expect them to find your blind spots

What worked: give one agent a **disjoint file set**, the exact rule with its rationale, the
verification commands to run, and an explicit instruction to *report* any conflict between the
design's text and the code's reality rather than silently resolving it. The delta-3 agent surfaced
two genuine contradictions in §10.6 that way. What does not work: two agents (or an agent and you)
editing the same crate — cargo's target lock serializes everything and a half-written `mod foo;`
blocks every build in the workspace. When an agent is mid-flight, **stop running cargo**; poll for
the file to appear instead.

A review agent over a large mechanical diff is very high value: the delta-1 reviewer found the
vendored-file corruption and the broken JS that the compiler could not see.

### 3.12 Small things

* `cargo test -p X --lib <name>` needs `-- <name>` for multiple filters, and `--lib` does **not**
  run `tests/`.
* `vmcell` has a **dev-dependency on `vmcell-artifact-validator`**, so a broken validator blocks
  `cargo test -p vmcell` too.
* `just gates` is fast (~seconds) and worth running alone before a full `just ci`.
* `cargo fmt --all` after any sweep: identifier length changes reflow imports and argument lists,
  and `just ci` fails on `fmt --check` before it reaches anything interesting.

---

## 4. Known-stale items not worth blocking on

* `docs/todo.md` still says "a host `agent::session` multiplexer" (line 21) and "no framing and no
  agent" (line 65). `docs/` was deliberately outside the delta-1 rename sweep. `docs/benchmark-results.md`
  **was** swept, because three production comments cite one of its headings by quoted title.
* `crates/vmcell-artifact-validator/src/classify.rs` fixtures say `init=/sbin/vmcell-steward` while
  `DEFAULT_INIT` is `/usr/sbin/vmcell-steward`, and one says "listening on vsock port 1024" while
  the port is 5000. Pre-existing, incidental to the classifier's serial-text matching.
* Roughly thirty production comments cite `§18, Delta register: changes from the validated v27
  build … delta N`. That register is superseded, and "delta 1" now names the steward rename in the
  **v33** register, so those citations actively mislead. Pre-existing and untouched.

---

## 5. Fixed after the premise verification ran

The verification in §2 was run against `540d8a3` and found one defect in delta 4 **as shipped**,
fixed in the same commit as this file:

`StewardPlacement::Service { port }` was an accepted input that was **silently ignored on the host
side**. `build()` accepted it and the cmdline builder emitted `vmcell_steward_port=<port>`, but
`VmInstance::vsock_endpoint()` hard-codes `STEWARD_VSOCK_PORT`, so `steward()` and
`connect_sessions()` kept dialing 5000. The token would have reached the guest while the host dialed
elsewhere, and the mismatch surfaces only as an opaque connect timeout — the exact failure mode
§3.5 says the health gate exists to diagnose. That violates F1 ("every accepted input is honored or
rejected at construction"), so it is a defect rather than a deferral.

`VsockEndpoint::with_port` now substitutes the declared port at both control-plane dials, on both
transports (AF_UNIX and AF_VSOCK, keeping the CID). `MicroVm::dial_vsock` already took an explicit
port and was never affected. A `Pid1` cell resolves to the same constant, so nothing moves for any
existing caller. `a_declared_service_port_is_honored_on_both_sides` pins both halves — the cmdline
token and the dialed endpoint — and reddens when the endpoint is reverted to the constant.

**The guest half remains delta 5's**, and is the one blocker listed against it: nothing under
`crates/vmcell-steward` reads `vmcell_steward_port`, so a non-default port is now emitted and dialed
but never *bound*. Until delta 5 lands that parse, `Service` cells must use the default port.

The lesson worth carrying: this was found by a **premise-verification pass over work that had
already shipped green** — full unit suite, full live suite, and `just ci`. Nothing in the test suite
was capable of noticing, because no test declared a non-default port. Re-verifying anchors is not
only for the delta you are about to cut.
