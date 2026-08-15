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
// with no extra args, so it tracks whatever the builder actually emits. The kernel's own parser
// folds `-` to `_` inside a parameter name (`kernel/params.c`'s `dash2underscore`), so the
// reference key is "text before the first `=`, with `-` folded to `_`", applied to the OUTPUT
// rather than restated as the predicate. It is red on the real historical defect (finding `m1`):
// drop the normalization from the predicate and `kvm_intel.nested=1` is accepted beside the owned
// `kvm-intel.nested=0`. It is likewise red if the `vmcell_` prefix rule is dropped. A second
// assertion pins the splice itself — the composed line is exactly the owned line with each accepted
// arg appended as ONE unmodified token, which is red if an arg carrying whitespace is ever accepted
// (it would forge a second boot token).
//
// A caller arg colliding with ANOTHER CALLER ARG is deliberately not a finding: `extra_kernel_args`
// is the caller's own list and repeating a key in it is their business, not an override of a token
// vmcell owns.
//
// WHAT IT CANNOT DO, stated so nobody reads more into a green run: it cannot discover a MISSING
// ALIAS. `rw` inverting the owned `ro`, or `quiet` overriding `loglevel=`, share no key with the
// token they override, so no duplicate-key oracle sees them — that is why the alias block in
// `RESERVED_CMDLINE_KEYS` is hand-maintained with its own negative test. Finding a missing alias
// needs a model of the kernel's semantics, which no byte-oriented fuzzer has.
//
// The configs built here carry NO shares, deliberately: `vmcell_share=` legitimately repeats once
// per share, so a shared-directory config would make the duplicate-key property false by design.

/// The kernel's own parameter-name normal form: the text before the first `=`, `-` folded to `_`.
fn cmdline_key(token: &str) -> String {
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
