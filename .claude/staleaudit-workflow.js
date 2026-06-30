export const meta = {
  name: 'impl-notes-stale-audit',
  description: 'Audit docs/implementation-notes.md for stale current-state claims; finders propose, skeptics confirm',
  phases: [
    { title: 'Audit', detail: 'per-section finders flag stale current-state claims (read-only)' },
    { title: 'Confirm', detail: 'skeptic confirms each item is genuinely stale (default: keep)' },
  ],
}

const REPO = '/home/pwnall/workspace/imp-testing'
const NOTES = 'docs/implementation-notes.md'

// Verified current state — ground truth from the full code review + an actual
// privileged/rootless test run on 2026-06-29. Finders judge "stale" against THIS.
const GT = `
VERIFIED CURRENT STATE (full code review + an ACTUAL privileged+rootless run on a KVM host, 2026-06-29). Judge staleness against this:
- CH warm snapshot/restore WORKS end-to-end (snapshot_restore::cloud_hypervisor PASSES: create→restore→CID/MAC/vsock rotation→host-driven clock resync→CSPRNG reseed). The old "warm restore fails / CH guest vsock listener doesn't survive --restore" gap is RESOLVED. A note still calling CH warm restore an OPEN/remaining gap is STALE.
- Firecracker warm restore is BROKEN (snapshot_restore::firecracker FAILS: Agent("Connection dropped during exec") on the first post-restore exec). The "FC warm-restore EADDRINUSE — fixed" note may be benchmark-path only; a blanket "FC restore works" is STALE/contradicted.
- metrics_limits is RED on all 3 backends: memory.max is set to the cap but does NOT bind guest RAM (a 512 MiB guest under a 256 MiB cap self-OOMs; cgroup memory.events oom_kill=0; likely default shared=true shmem RAM reclaimed not OOM-capped). Any claim metrics_limits PASSES / memory limits are ENFORCED is STALE/contradicted.
- Rootfs guest tooling (ip/curl/kvm-ok) is RESOLVED via the in-rootfs imp-guest-tools helper; host_endpoint/egress_proxy/shares_ro_rw/nested_virt now PASS across backends. Any "rootfs missing iproute2/curl, tests exit 127" gap is STALE (resolved).
- Empirical suite result 2026-06-29: privileged 124 run / 120 passed / 4 failed (metrics_limits x3 + snapshot_restore::firecracker) / 8 skipped; rootless 8/8. Supersedes the older "82/88" snapshot (keep 82/88 as a dated historical record; annotate if it is presented as the CURRENT state).
- fail-loud capability contract (design §7.1) is STILL UNIMPLEMENTED: error.rs has NO CapabilityUnavailable variant; no HostCapabilities probe; no limits_enforced flag; requested cgroup limits warn-and-return-Ok. "pending migration" is accurate; "done/enforced" is stale.
- lazy_restore is plumbed for CH (prefault on/off via restore_mode) but NOT Firecracker (FC restore() ignores _cfg, hardcodes backend_type "File", still advertises lazy_restore:true). "lazy_restore fully plumbed" is stale for FC.
- smoltcp host-NAT MAC: unit test host_nat_mac_never_collides_with_guest_mac PASSES → the NET-2 vmid-254 host-MAC collision is FIXED/guarded. A note stating the collision exists as a CURRENT bug is stale (it is now a corrected/closed item).
- CI cargo-hack feature-powerset gate is still RED (host-common module-gating debt) and short-circuits later gates. Accurate.
- ResourceUsage net_rx/net_tx are still always 0 (unwired). Accurate as a current gap.
- /tmp/imp-vm-{pid}-{vmid} dirs leak on teardown (serial.log/api.sock.lock retained). New finding; not previously recorded.`

const RULES = `You are auditing ${NOTES} (a HISTORICAL implementation ledger) for STALE content, having just reviewed the whole codebase. Read your assigned section(s) of ${REPO}/${NOTES} in full, and cross-check current-state claims against the ACTUAL current code (use Read/Grep) and the ground truth below.

Flag a passage ONLY if it is one of:
  (a) a CURRENT-STATE claim that is now factually FALSE (the code or the empirical run contradicts it), or
  (b) a "remaining gap / deferred / known issue / open finding / TODO / the one core-feature gap" item that is now RESOLVED, or
  (c) a rationale/assertion the review found to be WRONG.

DO NOT flag: dated historical pass-narratives ("Pass 5 did X"), benchmark numbers/methodology, or correct current statements. History is kept. The most you do to a still-true-as-history-but-superseded line is action='annotate' (add a short "(superseded — see …)" note), NEVER delete it. Prefer action='update'/'mark-resolved'/'annotate' over 'delete'; reserve 'delete' for a line that is purely a now-false forward-looking claim with no historical value.

For each flagged item return: section_heading; anchor_quote (an EXACT, copy-pasteable substring — one or two FULL lines from the file, long enough to be UNIQUE — that I will use as an Edit old_string); current_claim (1 line); why_stale (cite the contradicting code file:line or the empirical fact); action (update|mark-resolved|annotate|delete); proposed_new_text (the full replacement for the anchored text; '' only for delete); confidence 0..1. If your section has nothing stale, return an empty items list. Be conservative and precise — wrongly deleting valid history is worse than missing a minor stale line.

${GT}`

const ITEM_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    items: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          section_heading: { type: 'string' },
          anchor_quote: { type: 'string', description: 'EXACT unique substring (full line[s]) to match for editing' },
          current_claim: { type: 'string' },
          why_stale: { type: 'string', description: 'contradicting code file:line or empirical fact' },
          action: { type: 'string', enum: ['update', 'mark-resolved', 'annotate', 'delete'] },
          proposed_new_text: { type: 'string' },
          confidence: { type: 'number' },
        },
        required: ['section_heading', 'anchor_quote', 'current_claim', 'why_stale', 'action', 'proposed_new_text', 'confidence'],
      },
    },
  },
  required: ['items'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    verdict: { type: 'string', enum: ['genuinely-stale', 'keep-as-is', 'partly-stale'] },
    anchor_is_exact: { type: 'boolean', description: 'whether anchor_quote is an exact, unique substring of the file' },
    corrected_action: { type: 'string', enum: ['update', 'mark-resolved', 'annotate', 'delete', 'none'] },
    refined_new_text: { type: 'string', description: 'corrected replacement text if needed; else echo proposed' },
    note: { type: 'string' },
  },
  required: ['verdict', 'anchor_is_exact', 'corrected_action', 'refined_new_text', 'note'],
}

const CHUNKS = [
  { key: 'top-summaries+remaining-divergences', range: 'lines 1–67', detail: 'the per-subsystem current-state summaries and "Remaining Divergences from the Design"' },
  { key: 'design-alignment+review34-remediation', range: 'lines 68–235', detail: 'Design Alignment passes 5/6/7/34, Review 34 remediation, "known remaining issue & deferrals", open findings, "End-to-end validation status + two remaining gaps"' },
  { key: 'priv-suite+buckets', range: 'lines 236–406', detail: '"Privileged-suite results 82/88", privileged-tap path, "Larger follow-ups", the Wrap-up and "three remaining buckets" (Bucket 1 rootfs tooling, Bucket 2 snapshot/restore vsock "the one core-feature gap", Bucket 3 metrics_limits)' },
  { key: 'integration-test-fixes', range: 'lines 407–520', detail: 'Integration-test fixes: guest-tools, "Snapshot/restore: three fixes (now passing end-to-end)", rootless egress, netns hygiene, "metrics_limits: delegated cgroup scope", kernel cache-key, "Validation status (this pass)"' },
  { key: 'benchmarks+benchfixes', range: 'lines 521–880', detail: 'Benchmark results, version survey, and "Bug + feature-gap fixes for benchmarking" (esp. CH eager-vs-lazy restore / "lazy_restore not plumbed" supersession, "Firecracker warm-restore EADDRINUSE — fixed"). Leave benchmark numbers/methodology alone; only flag restore/limit *current-state* claims.' },
  { key: 'session-wrapup+review37', range: 'lines 882–1086', detail: 'Session wrap-up, kernel-dimension, and the Review 37 / 37a sections (the last two are recent and should already be accurate — only flag a genuine contradiction).' },
]

phase('Audit')
const found = await parallel(
  CHUNKS.map((c) => () =>
    agent(
      `${RULES}\n\n=== YOUR SECTION: ${c.key} (${c.range}) ===\nFocus: ${c.detail}\nRead that part of ${REPO}/${NOTES} now (use Read with the right offset/limit) and return stale items.`,
      { label: `audit:${c.key}`, phase: 'Audit', schema: ITEM_SCHEMA }
    )
  )
)

const all = []
found.forEach((r, i) => {
  if (r && Array.isArray(r.items)) r.items.forEach((it, j) => all.push(Object.assign({}, it, { _id: `${CHUNKS[i].key}-${j}` })))
})
log(`Audit: ${all.length} candidate stale items across ${CHUNKS.length} sections.`)

phase('Confirm')
const confirmed = await parallel(
  all.map((it) => () =>
    agent(
      `You are a conservative skeptic protecting a HISTORICAL ledger (${REPO}/${NOTES}) from wrongful edits. A finder proposes this passage is STALE. DEFAULT to keep-as-is unless the contradiction is clear. Verify: (1) the anchor_quote is an EXACT, UNIQUE substring of the file (Read/Grep to check) so it can be edited safely; (2) the claim is genuinely a now-false CURRENT-STATE claim or a resolved gap — not valid history. Confirm the proposed action and refine the replacement text if it would erase history or is inexact.\n${GT}\n\nPROPOSED ITEM:\n- section: ${it.section_heading}\n- anchor_quote: <<<${it.anchor_quote}>>>\n- claim: ${it.current_claim}\n- why_stale: ${it.why_stale}\n- action: ${it.action}\n- proposed_new_text: <<<${it.proposed_new_text}>>>`,
      { label: `confirm:${it._id}`, phase: 'Confirm', effort: 'high', schema: VERDICT_SCHEMA }
    ).then((v) => Object.assign({}, it, { verdict: v }))
  )
)

const ok = confirmed.filter(Boolean)
const survivors = ok.filter((it) => it.verdict && it.verdict.verdict !== 'keep-as-is' && it.verdict.anchor_is_exact)
const dropped = ok.filter((it) => !it.verdict || it.verdict.verdict === 'keep-as-is' || !it.verdict.anchor_is_exact)
log(`Confirmed ${survivors.length} stale edits; ${dropped.length} kept/dropped (keep-as-is or inexact anchor).`)

return {
  counts: { candidates: all.length, confirmed: survivors.length, dropped: dropped.length },
  edits: survivors.map((it) => ({
    id: it._id,
    section: it.section_heading,
    anchor_quote: it.anchor_quote,
    action: (it.verdict.corrected_action && it.verdict.corrected_action !== 'none') ? it.verdict.corrected_action : it.action,
    new_text: it.verdict.refined_new_text || it.proposed_new_text,
    why_stale: it.why_stale,
    note: it.verdict.note,
    confidence: it.confidence,
  })),
  dropped: dropped.map((it) => ({ id: it._id, section: it.section_heading, claim: it.current_claim, reason: it.verdict ? it.verdict.note : 'no verdict' })),
}
