//! **E1 — structured serial fault capture**: the KVM-free gate on
//! [`vmcell::vmm::fault`], the one host-side reading of a guest's serial console, and on the
//! lifecycle site that now names the guest kernel's death instead of the host's expired budget
//! (§5.4, The guest-kernel contract and the bootstrap seed; §3.2, The host side: `StewardClient`
//! and `SessionMux`).
//!
//! # What each fixture is, and where it came from
//! A classifier is only as honest as the text it was tested on, so every fixture's provenance is
//! recorded here rather than implied:
//!
//! * [`REAL_HEALTHY_BOOT`] and [`REAL_KERNEL_PANIC`] were **captured live on 2026-08-21** from
//!   Cloud Hypervisor v53 booting this repository's freshly built
//!   `target/vmcell-artifacts/{vmlinux, rootfs.erofs}` (Linux 6.12.104) on the default
//!   `loglevel=6`, with the vmcell kernel command line §5.3 (The kernel command line) emits. The
//!   panic capture differs from the healthy one in exactly one token — `init=` names a path that
//!   does not exist — so the pair is a controlled experiment rather than two unrelated logs.
//! * [`OOPS_NULL_DEREF`], [`KASAN_SLAB_OOB`] and [`LOCKDEP_CIRCULAR`] are **transcribed from the
//!   kernel sources that print them** — `arch/x86/mm/fault.c` (`show_fault_oops`) plus
//!   `arch/x86/kernel/dumpstack.c` (`__die`/`oops_end`); `mm/kasan/report.c` (`print_report`);
//!   and `kernel/locking/lockdep.c` (`print_circular_bug`) — wearing the same `[ timestamp]`
//!   printk framing the live captures above show, because this host's kernel does not carry
//!   `CONFIG_KASAN`/`CONFIG_PROVE_LOCKING` and no cheap in-guest trigger exists for a
//!   deliberate oops. That boundary is stated rather than hidden: the panic class is
//!   live-validated, the other three are validated against the emitters' text.
//!
//! # Why the negative control is the load-bearing test
//! [`REAL_HEALTHY_BOOT`] is a *successful* vmcell boot, and it contains the word `panic` — the
//! `panic=1` token §5.3 puts on every command line, echoed back by the kernel's own
//! `Kernel command line:` line. A classifier grepping for `panic` fires on every healthy VM this
//! repository has ever booted. So does one grepping for `BUG`, `error` or `failed`: the same log
//! carries `Direct firmware load for regulatory.db failed with error -2`. A classifier that fires
//! on everything is worse than none, and this fixture is what makes that concrete.

#![allow(
    clippy::doc_markdown,
    reason = "kernel log fixtures quote raw printk text"
)]

mod common;

use std::time::Duration;
use vmcell::error::Error;
use vmcell::vmm::SerialLog;
use vmcell::vmm::fault::{
    GuestFault, NO_CONSOLE_EVIDENCE, SerialFault, classify_serial_fault, log_reports_panic,
};
use vmcell_protocol::{DEBUG_TRUNCATED_MARKER, MAX_DEBUG_RENDER_BYTES};

/// A **real, successful** vmcell boot, captured live (see the module header). At `loglevel=6` the
/// kernel's `KERN_INFO` chatter — including `VFS: Mounted root` — is suppressed and the steward
/// logs below `error`, so a healthy vmcell console genuinely ends mid-probe like this.
const REAL_HEALTHY_BOOT: &str = r#"[    0.000000] Linux version 6.12.104 (pwnall@pwnlet13) (gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.46) #1 SMP PREEMPT_DYNAMIC Thu Aug 20 11:58:06 PDT 2026
[    0.006469] ACPI: x2apic entry ignored
[    0.012861] Kernel command line: console=ttyS0 loglevel=6 random.trust_cpu=on random.trust_bootloader=on cryptomgr.notests raid=noautodetect root=/dev/vda rootfstype=erofs ro panic=1 init=/usr/sbin/vmcell-steward vmcell_vmid=1 kvm-intel.nested=0 kvm-amd.nested=0
[    0.012908] Unknown kernel command line parameters "vmcell_vmid=1", will be passed to user space.
[    0.012917] random: crng init done
[    0.023312] audit: type=2000 audit(1787304379.416:1): state=initialized audit_enabled=0 res=1
[    0.032209] SCSI subsystem initialized
[    0.073545] VFS: Disk quotas dquot_6.6.0
[    0.081008] kvm_amd: CPU 0 isn't AMD or Hygon
[    0.081405] Initialise system trusted keyrings
[    0.081746] NFS: Registering the id_resolver key type
[    0.082064] Key type id_resolver registered
[    0.082331] Key type id_legacy registered
[    0.088280] Key type asymmetric registered
[    0.088547] Asymmetric key parser 'x509' registered
[    0.093500] virtio_blk virtio0: [vda] 192176 512-byte logical blocks (98.4 MB/93.8 MiB)
[    0.094979] rtc_cmos rtc_cmos: only 24-hr supported
[    0.095667] Key type dns_resolver registered
[    0.100885] Loading compiled-in X.509 certificates
[    0.101809] cfg80211: Loading compiled-in X.509 certificates for regulatory database
[    0.102432] Loaded X.509 cert 'sforshee: 00b28ddf47aef9cea7'
[    0.102898] Loaded X.509 cert 'wens: 61c038651aabdcf94bd0ac7ff06c7248db18c600'
[    0.103359] platform regulatory.0: Direct firmware load for regulatory.db failed with error -2"#;

/// The **same boot, same host, same artifacts**, with `init=` pointing at a path that does not
/// exist — a real `kernel/panic.c` panic, captured live (see the module header).
const REAL_KERNEL_PANIC: &str = r#"[    0.000000] Linux version 6.12.104 (pwnall@pwnlet13) (gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.46) #1 SMP PREEMPT_DYNAMIC Thu Aug 20 11:58:06 PDT 2026
[    0.001940] ACPI: x2apic entry ignored
[    0.007497] Kernel command line: console=ttyS0 loglevel=6 random.trust_cpu=on random.trust_bootloader=on cryptomgr.notests raid=noautodetect root=/dev/vda rootfstype=erofs ro panic=-1 init=/usr/sbin/definitely-not-here vmcell_vmid=1 kvm-intel.nested=0 kvm-amd.nested=0
[    0.007541] Unknown kernel command line parameters "vmcell_vmid=1", will be passed to user space.
[    0.007550] random: crng init done
[    0.016715] audit: type=2000 audit(1787304414.033:1): state=initialized audit_enabled=0 res=1
[    0.024433] SCSI subsystem initialized
[    0.063886] VFS: Disk quotas dquot_6.6.0
[    0.072007] kvm_amd: CPU 0 isn't AMD or Hygon
[    0.072424] Initialise system trusted keyrings
[    0.072778] NFS: Registering the id_resolver key type
[    0.073106] Key type id_resolver registered
[    0.073374] Key type id_legacy registered
[    0.079364] Key type asymmetric registered
[    0.079629] Asymmetric key parser 'x509' registered
[    0.094783] virtio_blk virtio0: [vda] 192176 512-byte logical blocks (98.4 MB/93.8 MiB)
[    0.096627] rtc_cmos rtc_cmos: only 24-hr supported
[    0.097538] Key type dns_resolver registered
[    0.101238] Loading compiled-in X.509 certificates
[    0.102285] cfg80211: Loading compiled-in X.509 certificates for regulatory database
[    0.103004] Loaded X.509 cert 'sforshee: 00b28ddf47aef9cea7'
[    0.103478] Loaded X.509 cert 'wens: 61c038651aabdcf94bd0ac7ff06c7248db18c600'
[    0.103980] platform regulatory.0: Direct firmware load for regulatory.db failed with error -2
[    0.111784] Kernel panic - not syncing: Requested init /usr/sbin/definitely-not-here failed (error -2).
[    0.112136] CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.12.104 #1
[    0.112390] Hardware name: Cloud Hypervisor cloud-hypervisor, BIOS 0 
[    0.112628] Call Trace:
[    0.112737]  <TASK>
[    0.112825]  dump_stack_lvl+0x4d/0x70
[    0.112971]  panic+0x10d/0x2be
[    0.113099]  ? kernel_execve+0xaf/0x140
[    0.113247]  ? __pfx_kernel_init+0x10/0x10
[    0.113403]  kernel_init+0xd2/0x130
[    0.113539]  ret_from_fork+0x2c/0x50
[    0.113679]  ? __pfx_kernel_init+0x10/0x10
[    0.113838]  ret_from_fork_asm+0x1a/0x30
[    0.113995]  </TASK>
[    0.114104] Kernel Offset: disabled"#;

/// An x86-64 NULL-pointer oops, transcribed from its printing sites (see the module header). The
/// `BUG:`/`#PF:` lines come from `show_fault_oops`; the `Oops: 0000 [#1] …` header and the
/// register dump from `__die`.
const OOPS_NULL_DEREF: &str = r#"[    3.114521] BUG: kernel NULL pointer dereference, address: 0000000000000000
[    3.115002] #PF: supervisor read access in kernel mode
[    3.115330] #PF: error_code(0x0000) - not-present page
[    3.115660] PGD 0 P4D 0
[    3.115812] Oops: 0000 [#1] PREEMPT SMP NOPTI
[    3.116100] CPU: 0 UID: 0 PID: 1 Comm: vmcell-steward Not tainted 6.12.104 #1
[    3.116570] Hardware name: Cloud Hypervisor cloud-hypervisor, BIOS 0
[    3.116980] RIP: 0010:erofs_read_metabuf+0x2c/0x120
[    3.117410] Code: 48 8b 47 08 48 85 c0 74 0e 48 8b 00 c3 cc cc cc cc 0f 1f 40 00
[    3.117980] RSP: 0018:ffffc90000013d90 EFLAGS: 00010246
[    3.118400] RAX: 0000000000000000 RBX: ffff888100c40000 RCX: 0000000000000000
[    3.118990] Call Trace:
[    3.119130]  <TASK>
[    3.119260]  erofs_iget+0x51/0x1a0
[    3.119520]  ? __pfx_erofs_iget+0x10/0x10
[    3.119810]  </TASK>
[    3.120050] Kernel Offset: disabled"#;

/// A KASAN slab-out-of-bounds report, transcribed from `mm/kasan/report.c`'s `print_report` (see
/// the module header): the `=` rule, the `BUG: KASAN: <bug-type> in <symbol>` header, the access
/// description, then the allocation provenance.
const KASAN_SLAB_OOB: &str = r#"[    4.200980] ==================================================================
[    4.201700] BUG: KASAN: slab-out-of-bounds in erofs_read_metabuf+0x2c/0x120
[    4.202140] Read of size 8 at addr ffff888104a3c0f8 by task vmcell-steward/1
[    4.202610]
[    4.202780] CPU: 0 UID: 0 PID: 1 Comm: vmcell-steward Not tainted 6.12.104 #1
[    4.203300] Call Trace:
[    4.203440]  <TASK>
[    4.203570]  dump_stack_lvl+0x4d/0x70
[    4.203830]  print_report+0xce/0x660
[    4.204090]  kasan_report+0xd7/0x110
[    4.204350]  erofs_read_metabuf+0x2c/0x120
[    4.204640]  </TASK>
[    4.204780]
[    4.204910] Allocated by task 1:
[    4.205150]  kasan_save_stack+0x33/0x60
[    4.205420]  __kmalloc_cache_noprof+0x18f/0x2f0
[    4.205740]
[    4.205870] The buggy address belongs to the object at ffff888104a3c000
[    4.206380]  which belongs to the cache kmalloc-256 of size 256
[    4.206840] =================================================================="#;

/// A lockdep circular-dependency splat, transcribed from `kernel/locking/lockdep.c`'s
/// `print_circular_bug` (see the module header). Advisory: the kernel keeps running afterwards,
/// which is the whole reason [`GuestFault::Lockdep`] never aborts a wait.
const LOCKDEP_CIRCULAR: &str = r#"[   12.004311] ======================================================
[   12.004900] WARNING: possible circular locking dependency detected
[   12.005410] 6.12.104 #1 Not tainted
[   12.005700] ------------------------------------------------------
[   12.006100] vmcell-steward/1 is trying to acquire lock:
[   12.006520] ffff888100c41120 (&sb->s_type->i_mutex_key#3){++++}-{4:4}, at: erofs_iget+0x51/0x1a0
[   12.007190]
[   12.007190] but task is already holding lock:
[   12.007780] ffff888100c40890 (&mm->mmap_lock){++++}-{4:4}, at: do_user_addr_fault+0x2e2/0x6f0
[   12.008440]
[   12.008440] which lock already depends on the new lock.
[   12.009100]
[   12.009100] the existing dependency chain (in reverse order) is:
[   12.009800]
[   12.009800] other info that might help us debug this:
[   12.010500]  Possible unsafe locking scenario:
[   12.011100] stack backtrace:
[   12.011400] CPU: 0 UID: 0 PID: 1 Comm: vmcell-steward Not tainted 6.12.104 #1"#;

/// A [`SerialLog`] over a file this test wrote — the **real** production reader
/// ([`vmcell::vmm::RealSerialLog`]), not a fake, because the effect class under test is
/// "read a file the guest is writing" and a fake is blind to it (AGENTS.md rule 4).
///
/// Returns the guard alongside so the fixture tree is removed on the panic path too: a test's own
/// fixtures are residue.
fn serial_log_over(text: &str) -> (tempfile::TempDir, vmcell::vmm::RealSerialLog) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("serial.log");
    std::fs::write(&path, text).expect("write console fixture");
    (dir, vmcell::vmm::RealSerialLog { path })
}

// ---------------------------------------------------------------------------------------------
// The negative control, first: a classifier that fires on a healthy boot is worse than none.
// RED on any over-broad needle — `panic` (the `panic=1` cmdline token, echoed by the kernel),
// `BUG`, `error` or `failed` (the regulatory.db line) each redden this and nothing else.
// ---------------------------------------------------------------------------------------------
#[test]
fn a_real_healthy_boot_is_not_a_guest_fault() {
    // Non-vacuity: the control must actually carry the words an over-broad matcher would key on,
    // or it proves nothing. A fixture edit that drops them reddens here rather than silently
    // weakening every assertion below.
    assert!(
        REAL_HEALTHY_BOOT.contains("panic=1"),
        "the control must carry the cmdline `panic=` token an over-broad matcher trips on"
    );
    assert!(
        REAL_HEALTHY_BOOT.contains("failed with error -2"),
        "the control must carry an ordinary boot-time failure line"
    );
    assert!(
        REAL_HEALTHY_BOOT.contains("Linux version"),
        "the control must be a real boot"
    );

    assert_eq!(
        classify_serial_fault(REAL_HEALTHY_BOOT),
        None,
        "a successful vmcell boot must classify as no guest fault"
    );
    assert!(!log_reports_panic(REAL_HEALTHY_BOOT));
}

// An empty console and a console of unrelated text are the other two `None` shapes. A *fresh*
// boot's empty console means something to the artifact validator (§5.4: "not a direct-boot
// vmlinux"); it means nothing here, because this classifier answers "did the guest kernel die in a
// recognizable way", and silence is not a recognizable death.
#[test]
fn silence_and_unrelated_text_are_not_guest_faults() {
    assert_eq!(classify_serial_fault(""), None);
    assert_eq!(classify_serial_fault("   \n\n"), None);
    assert_eq!(
        classify_serial_fault("[    0.1] hello from a guest that is simply chatty\n"),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// One test per fault class. Each asserts the CLASS and the EVIDENCE line, so a classifier that
// returns the right variant while quoting the wrong line still reddens.
// ---------------------------------------------------------------------------------------------
#[test]
fn a_real_kernel_panic_is_classified_and_halts() {
    let fault = classify_serial_fault(REAL_KERNEL_PANIC).expect("the panic must classify");
    assert_eq!(fault.kind(), GuestFault::Panic);
    assert!(fault.halted(), "a panic means the kernel stopped");
    assert!(
        fault.evidence().contains("Kernel panic - not syncing"),
        "the evidence must quote the panic line, got {}",
        fault.evidence()
    );
    assert!(
        fault
            .evidence()
            .contains("Requested init /usr/sbin/definitely-not-here failed"),
        "the evidence must carry the panic's REASON, which is the actionable half: {}",
        fault.evidence()
    );
}

#[test]
fn an_oops_is_classified_and_does_not_halt() {
    let fault = classify_serial_fault(OOPS_NULL_DEREF).expect("the oops must classify");
    assert_eq!(fault.kind(), GuestFault::Oops);
    assert!(
        !fault.halted(),
        "an oops kills the faulting task; the kernel itself keeps running unless PID 1 died"
    );
    assert!(
        fault
            .evidence()
            .contains("BUG: kernel NULL pointer dereference"),
        "the evidence must quote the first oops line, got {}",
        fault.evidence()
    );
}

#[test]
fn a_kasan_report_is_classified() {
    let fault = classify_serial_fault(KASAN_SLAB_OOB).expect("the KASAN report must classify");
    assert_eq!(fault.kind(), GuestFault::Kasan);
    assert!(
        fault.evidence().contains("BUG: KASAN: slab-out-of-bounds"),
        "the evidence must name the KASAN bug type, got {}",
        fault.evidence()
    );
}

#[test]
fn a_lockdep_splat_is_classified_and_is_advisory() {
    let fault = classify_serial_fault(LOCKDEP_CIRCULAR).expect("the lockdep splat must classify");
    assert_eq!(fault.kind(), GuestFault::Lockdep);
    assert!(
        !fault.halted(),
        "lockdep is advisory: the kernel keeps running after a splat"
    );
    assert!(
        fault
            .evidence()
            .contains("possible circular locking dependency detected"),
        "got {}",
        fault.evidence()
    );
}

// The bare word `KASAN` is a kernel config-fragment LABEL this repo ships (§5.5), so it appears in
// the cmdline echo of every healthy KASAN build. RED on a classifier keyed on the word rather than
// on `mm/kasan/report.c`'s header.
#[test]
fn a_kasan_kernel_that_booted_fine_is_not_a_kasan_report() {
    let log = format!(
        "{REAL_HEALTHY_BOOT}\n[    0.3] Kernel command line: … CONFIG_KASAN=y kasan.fault=report\n"
    );
    assert!(log.contains("KASAN"), "the control must mention KASAN");
    assert_eq!(classify_serial_fault(&log), None);
}

// ---------------------------------------------------------------------------------------------
// Precedence: one console, several signatures, one answer.
// ---------------------------------------------------------------------------------------------

// The real shape of a KASAN find in a guest: report → oops → panic, one event, three lines of
// evidence, and only the FIRST names what to fix. RED on a classifier that answers `Panic` (which
// is what `contains_panic` alone could ever say) or `Oops`.
#[test]
fn the_cause_outranks_the_consequence() {
    let cascade = format!("{KASAN_SLAB_OOB}\n{OOPS_NULL_DEREF}\n{REAL_KERNEL_PANIC}");
    let fault = classify_serial_fault(&cascade).expect("classify");
    assert_eq!(
        fault.kind(),
        GuestFault::Kasan,
        "the KASAN report is the cause; the oops and the panic are its consequences"
    );

    let oops_then_panic = format!("{OOPS_NULL_DEREF}\n{REAL_KERNEL_PANIC}");
    assert_eq!(
        classify_serial_fault(&oops_then_panic)
            .expect("classify")
            .kind(),
        GuestFault::Oops
    );
}

// …but a lockdep splat is NOT the cause of a later panic: the kernel survived the splat and kept
// booting. RED on a precedence list ordered purely by specificity.
#[test]
fn a_fatal_panic_outranks_an_advisory_lockdep_splat() {
    let splat_then_panic = format!("{LOCKDEP_CIRCULAR}\n{REAL_KERNEL_PANIC}");
    assert_eq!(
        classify_serial_fault(&splat_then_panic)
            .expect("classify")
            .kind(),
        GuestFault::Panic,
        "an advisory splat must not be blamed for an unrelated later panic"
    );
}

// `kind()` and `halted()` answer two different questions and must be computed separately. RED on
// `halted == (kind == Panic)`, the collapse a single-enum design would force.
#[test]
fn halted_is_orthogonal_to_the_fault_class() {
    let kasan_then_panic = format!("{KASAN_SLAB_OOB}\n{REAL_KERNEL_PANIC}");
    let fault = classify_serial_fault(&kasan_then_panic).expect("classify");
    assert_eq!(fault.kind(), GuestFault::Kasan, "the cause");
    assert!(fault.halted(), "and the kernel still stopped");

    let kasan_only = classify_serial_fault(KASAN_SLAB_OOB).expect("classify");
    assert_eq!(kasan_only.kind(), GuestFault::Kasan);
    assert!(
        !kasan_only.halted(),
        "a KASAN report on its own does not stop the kernel"
    );
}

// The growth obligation, enforced by the compiler: a new `GuestFault` variant must be spliced into
// `FAULT_PRECEDENCE` (or `classify_serial_fault` can never return it) and given signatures. The
// exhaustive `match` below fails to compile until the new variant is named here, and the
// round-trip asserts it is reachable from the classifier.
#[test]
fn every_fault_class_is_reachable_and_carries_signatures() {
    for kind in [
        GuestFault::Kasan,
        GuestFault::Oops,
        GuestFault::Panic,
        GuestFault::Lockdep,
    ] {
        // The exhaustive arm: adding a variant reddens THIS line at compile time.
        let fixture = match kind {
            GuestFault::Kasan => KASAN_SLAB_OOB,
            GuestFault::Oops => OOPS_NULL_DEREF,
            GuestFault::Panic => REAL_KERNEL_PANIC,
            GuestFault::Lockdep => LOCKDEP_CIRCULAR,
            other => panic!("unhandled GuestFault variant {other:?}: give it a fixture here"),
        };
        assert!(
            !kind.signatures().is_empty(),
            "{kind} must carry at least one console signature"
        );
        assert!(
            !kind.explain().is_empty(),
            "{kind} must explain itself to an operator"
        );
        assert_eq!(
            classify_serial_fault(fixture).expect("classify").kind(),
            kind,
            "{kind} must be reachable from the classifier — is it in FAULT_PRECEDENCE?"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The console is guest-controlled: the evidence is capped, always.
// ---------------------------------------------------------------------------------------------

// A guest that prints one un-newlined megabyte satisfies any LINE-based bound. RED on evidence
// built with `to_string()` instead of `capped_debug`.
#[test]
fn evidence_from_a_flooding_guest_is_capped() {
    let flood = format!("[    9.9] Oops: 0000 [#1] {}", "A".repeat(1_000_000));
    let fault = classify_serial_fault(&flood).expect("classify");
    assert_eq!(fault.kind(), GuestFault::Oops);
    assert!(
        fault.evidence().len() <= MAX_DEBUG_RENDER_BYTES + DEBUG_TRUNCATED_MARKER.len(),
        "evidence is {} bytes; the guest must not be able to size a host log line",
        fault.evidence().len()
    );
    assert!(
        fault.evidence().ends_with(DEBUG_TRUNCATED_MARKER),
        "a capped render must SAY it was capped: {}",
        fault.evidence()
    );
}

// The evidence-free constructor is evidence-free by construction: a `SerialLog` that only knows
// the boolean must not be able to fabricate a quote.
#[test]
fn a_fake_that_knows_only_the_boolean_quotes_nothing() {
    let fake = vmcell::vmm::FakeSerialLog { panicked: true };
    let fault = fake.classify_fault().expect("the fake reports a panic");
    assert_eq!(fault.kind(), GuestFault::Panic);
    assert!(fault.halted());
    assert_eq!(fault.evidence(), NO_CONSOLE_EVIDENCE);
    assert_eq!(SerialFault::opaque_panic(), fault);

    let quiet = vmcell::vmm::FakeSerialLog { panicked: false };
    assert_eq!(quiet.classify_fault(), None);
}

// ---------------------------------------------------------------------------------------------
// The real file-reading path (`FakeVmm` and friends are fs-blind — AGENTS.md rule 4).
// ---------------------------------------------------------------------------------------------
#[test]
fn the_real_serial_log_reads_the_file_and_agrees_with_itself() {
    let (_guard, log) = serial_log_over(REAL_KERNEL_PANIC);
    assert!(log.contains_panic(), "the file-reading path must see it");
    let fault = log.classify_fault().expect("classify from the file");
    assert_eq!(fault.kind(), GuestFault::Panic);
    // ONE panic law: the boolean and the classifier can never disagree about what a panic is.
    assert_eq!(log.contains_panic(), fault.halted());

    let (_guard2, healthy) = serial_log_over(REAL_HEALTHY_BOOT);
    assert!(!healthy.contains_panic());
    assert_eq!(healthy.classify_fault(), None);
}

// "I could not look" is a fact about the HOST, not about the guest. RED on a reader that treats an
// absent console as an empty one and lets a missing file become guest evidence.
#[test]
fn an_absent_console_is_not_a_guest_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = vmcell::vmm::RealSerialLog {
        path: dir.path().join("never-created.log"),
    };
    assert!(!log.contains_panic());
    assert_eq!(log.classify_fault(), None);
}

// ---------------------------------------------------------------------------------------------
// THE LIFECYCLE SITE — the whole point of the item. KVM-free: the connect loop is driven against a
// vsock path that never appears, so what varies between these three tests is ONLY the console.
// ---------------------------------------------------------------------------------------------

/// Drive `StewardClient::connect` against a socket that does not exist, with `text` as the guest's
/// console, and return the error and how long it took.
async fn connect_against(text: &str, budget: Duration) -> (Error, Duration) {
    let (_guard, serial) = serial_log_over(text);
    let dir = tempfile::tempdir().expect("tempdir");
    let started = std::time::Instant::now();
    let res = vmcell::steward::StewardClient::connect(
        &dir.path().join("no-such.sock"),
        5000,
        budget,
        &vmcell::config::Timeouts::default(),
        &serial,
    )
    .await;
    let elapsed = started.elapsed();
    // `expect_err` would need `StewardClient: Debug`, which it deliberately is not (it owns a
    // live framed stream).
    let Err(err) = res else {
        panic!("the connect must fail: the socket path never exists");
    };
    (err, elapsed)
}

// THE NEGATIVE CONTROL, and it comes first: with a healthy console the host's own timeout must
// survive untouched. A wedged `vhost-device-vsock` daemon, a missing socket and a busy host are
// HOST problems, and turning one of those into a guest-fault report is the failure mode this whole
// item has to avoid. RED on a classifier that fires on ordinary boot text.
#[tokio::test]
async fn a_healthy_console_still_reports_the_hosts_own_timeout() {
    let (err, _elapsed) = connect_against(REAL_HEALTHY_BOOT, Duration::from_millis(300)).await;
    assert!(
        matches!(err, Error::Timeout(_)),
        "a healthy guest must leave the host's timeout in place, got {err:?}"
    );
}

// …and the positive result: the SAME failing connect, the SAME budget, one variable changed — the
// guest oopsed. Before this item that oops reached the caller as "Steward connection timed out",
// naming the host's budget instead of the guest's death. RED on a connect loop that returns
// `Error::Timeout` regardless of the console.
#[tokio::test]
async fn an_oopsed_guest_names_the_oops_instead_of_the_handshake_timeout() {
    let (err, _elapsed) = connect_against(OOPS_NULL_DEREF, Duration::from_millis(300)).await;
    let Error::GuestKernelFault {
        fault,
        op,
        evidence,
    } = err
    else {
        panic!("expected a typed guest-kernel fault, got {err:?}");
    };
    assert_eq!(fault, GuestFault::Oops);
    assert_eq!(op, "steward vsock handshake", "the host names its own half");
    assert!(
        evidence.contains("BUG: kernel NULL pointer dereference"),
        "the error must carry the actionable console line: {evidence}"
    );
}

// An ADVISORY splat must not abort a boot that is merely slow — §5.5 ships LOCKDEP kernels on
// purpose — but once the budget is gone it is still the best explanation the console offers. Both
// halves in one test: the elapsed time proves it did not fast-fail, the variant proves it was not
// discarded. RED on `aborts == fires`, in either direction.
#[tokio::test]
async fn an_advisory_splat_does_not_abort_the_wait_but_does_explain_it() {
    let budget = Duration::from_millis(400);
    let (err, elapsed) = connect_against(LOCKDEP_CIRCULAR, budget).await;
    assert!(
        elapsed >= budget,
        "an advisory splat must not cut the wait short (returned in {elapsed:?} of {budget:?})"
    );
    assert!(
        matches!(
            err,
            Error::GuestKernelFault {
                fault: GuestFault::Lockdep,
                ..
            }
        ),
        "an expired wait must still be explained by the console, got {err:?}"
    );
}

// A stopped kernel must fail FAST — no later poll can succeed — and must name the CAUSE, not
// `Panic`, when the console names one. The generous budget is the discriminator: a loop that
// dropped the halt check would spin the full 10 s and then classify.
#[tokio::test]
async fn a_stopped_kernel_fails_fast_and_still_names_the_cause() {
    let cascade = format!("{KASAN_SLAB_OOB}\n{REAL_KERNEL_PANIC}");
    let (err, elapsed) = connect_against(&cascade, Duration::from_secs(10)).await;
    assert!(
        elapsed < Duration::from_secs(1),
        "a stopped kernel must fail fast; returned in {elapsed:?}"
    );
    assert!(
        matches!(
            err,
            Error::GuestKernelFault {
                fault: GuestFault::Kasan,
                ..
            }
        ),
        "the halt aborts the wait; the KASAN report is what gets reported, got {err:?}"
    );
}

// The rendered message must carry all three halves — what the host wanted, what the guest did, and
// the proof — because that string is what lands in a CI log.
#[test]
fn the_rendered_error_names_the_operation_the_class_and_the_evidence() {
    let fault = classify_serial_fault(KASAN_SLAB_OOB).expect("classify");
    let rendered = fault.into_error("steward vsock handshake").to_string();
    assert!(rendered.contains("steward vsock handshake"), "{rendered}");
    assert!(rendered.contains("KASAN report"), "{rendered}");
    assert!(rendered.contains("slab-out-of-bounds"), "{rendered}");
}

// ---------------------------------------------------------------------------------------------
// THE LIVE LEG. Everything above is pure text; this boots a real guest, makes its real kernel
// panic, and reads the real console the real host wrote — the effect class every fake in this tree
// is blind to (AGENTS.md rule 4: `FakeVmm` never touches the filesystem).
//
// How the fault is driven, and why it is cheap: `init=` names a path the rootfs does not carry, so
// `kernel_init` panics with `Requested init … failed (error -2)` about 0.11 s into boot. No fault
// injection, no instrumented kernel, no privileged setup — the kernel does it to itself.
//
// Why `Service` and not the derived default: setting `init` derives
// `StewardPlacement::None` (§3.5), whose `steward()` refuses before it ever opens a socket, so the
// console would never be consulted. `Service` is the one placement that composes with a custom init
// (v33 delta 10) and it still EXPECTS a steward — which is exactly the shape this item is about:
// the host is waiting for a handshake that a dead guest can never complete.
//
// Named `…_unprivileged` because it is: CH, KVM group only, no network. That also selects it into
// `just test-unprivileged`, which needs no blessed runner.
// ---------------------------------------------------------------------------------------------
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn a_live_guest_kernel_panic_names_the_cause_unprivileged() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let cfg = vmcell::config::VmConfig::builder(
        common::get_vmlinux(),
        vmcell::config::RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .init("/usr/sbin/definitely-not-here")
    .steward_placement(vmcell::config::StewardPlacement::Service {
        port: vmcell_protocol::STEWARD_VSOCK_PORT,
    })
    .network_disabled()
    .build()
    .expect("a Service cell with a custom init is expressible (v33 delta 10)");

    let mut vm = common::start_vm(&vmm, cfg).await;

    // A budget far longer than the panic takes (~0.11 s), so "it returned early" is evidence rather
    // than a race: a host that ignored the console would sit here for the full 20 s.
    let budget = Duration::from_secs(20);
    let started = std::time::Instant::now();
    let outcome = vm.steward(Some(budget)).await;
    let elapsed = started.elapsed();

    // `expect_err` would need `&mut StewardClient: Debug`, which it is not.
    let Err(err) = outcome else {
        panic!("a guest whose PID 1 never existed cannot answer a steward handshake");
    };

    // The DATA PLANE: the console the guest actually wrote, read back through the production
    // reader, must be why this failed — and must carry the kernel's own words.
    let Error::GuestKernelFault {
        fault,
        op,
        evidence,
    } = &err
    else {
        // Before E1 this arm is where a live panic landed: `Error::Timeout("Steward connection
        // timed out")`, naming the host's budget while the guest's console said exactly what
        // happened.
        panic!("expected a typed guest-kernel fault from a panicked guest, got {err:?}");
    };
    assert_eq!(*fault, GuestFault::Panic);
    assert_eq!(op, "steward vsock handshake");
    assert!(
        evidence.contains("Kernel panic - not syncing"),
        "the evidence must be the guest's own console line: {evidence}"
    );
    assert!(
        evidence.contains("definitely-not-here"),
        "…including the reason, which is the actionable half: {evidence}"
    );
    assert!(
        elapsed < budget / 2,
        "a stopped kernel must end the wait early, not consume the budget (took {elapsed:?})"
    );

    vm.kill().await.expect("teardown");
}
