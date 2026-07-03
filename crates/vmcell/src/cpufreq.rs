//! CPU-frequency pinning for benchmark noise-floor discipline.
//!
//! Latency benchmarks (design §13.2) are only meaningful with a controlled noise
//! floor; an unpinned CPU whose frequency scales between its minimum and turbo
//! ceiling adds variance that swamps the signal. This module reads the kernel's
//! cpufreq scaling settings, pins every online CPU to the `performance` governor
//! (and disables turbo for determinism) for the duration of a benchmark, and —
//! crucially — **restores the original settings on `Drop`, including on panic**.
//!
//! The sysfs reads/writes live behind the [`crate::cpufreq::CpuFreqSysfs`] trait so
//! the policy ([`crate::cpufreq::CpuFreqPin`]) is unit-tested against an in-memory
//! `RecordingCpuFreq` fake with no real `/sys` access. The real implementation is
//! [`crate::cpufreq::SysfsCpuFreq`].
//!
//! # Capabilities
//!
//! The governor and turbo files under `/sys/devices/system/cpu` are owned
//! `root:root` (mode `0644`), so writing them needs `CAP_DAC_OVERRIDE` — which
//! the privileged test runner (`vmcell-test-runner`) already grants alongside
//! `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`; **no extra capability is required**. Run a
//! benchmark through the runner to pin frequency. Without those rights (e.g. a
//! plain `cargo bench`) the writes fail with `EACCES`; [`crate::cpufreq::CpuFreqPin::engage`]
//! then degrades to a logged warning and a no-op guard rather than failing the
//! benchmark, because benchmarks are tracked metrics, not pass/fail gates.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// The governor that pins a CPU to its maximum sustained frequency.
const PERFORMANCE: &str = "performance";

/// Errors from reading or applying CPU-frequency scaling settings.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CpuFreqError {
    /// An I/O error reading or writing a cpufreq sysfs file.
    #[error("cpufreq I/O error on {path}: {source}")]
    Io {
        /// The sysfs path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The online-CPU list could not be parsed.
    #[error("could not parse online-CPU list {raw:?}: {reason}")]
    ParseOnline {
        /// The raw contents of `cpu/online`.
        raw: String,
        /// Why parsing failed.
        reason: String,
    },
    /// A turbo/boost write was requested on a host that exposes no turbo control
    /// (neither `intel_pstate/no_turbo` nor `cpufreq/boost`). Returned instead of a
    /// silent `Ok` so a knob write that changes nothing does not report success
    /// ("a write that fails must not lie", L-HOST-6).
    #[error("no turbo/boost control on this host")]
    NoTurboControl,
}

/// Abstraction over the cpufreq sysfs surface, so the [`CpuFreqPin`] policy is
/// testable against a recording fake instead of the live `/sys` tree.
///
/// Turbo is modelled driver-agnostically as "is turbo **enabled**", hiding the
/// `intel_pstate` `no_turbo` inversion and the `acpi-cpufreq` `boost` spelling.
pub trait CpuFreqSysfs: Send + Sync {
    /// Returns the online CPU indices.
    ///
    /// # Errors
    /// Returns [`CpuFreqError`] if the list cannot be read or parsed.
    fn online_cpus(&self) -> Result<Vec<u32>, CpuFreqError>;

    /// Returns the governors available for `cpu`.
    ///
    /// # Errors
    /// Returns [`CpuFreqError::Io`] if the file cannot be read.
    fn available_governors(&self, cpu: u32) -> Result<Vec<String>, CpuFreqError>;

    /// Returns the current scaling governor for `cpu`.
    ///
    /// # Errors
    /// Returns [`CpuFreqError::Io`] if the file cannot be read.
    fn read_governor(&self, cpu: u32) -> Result<String, CpuFreqError>;

    /// Sets the scaling governor for `cpu`.
    ///
    /// # Errors
    /// Returns [`CpuFreqError::Io`] if the file cannot be written (e.g. `EACCES`
    /// when the caller lacks `CAP_DAC_OVERRIDE`).
    fn write_governor(&self, cpu: u32, governor: &str) -> Result<(), CpuFreqError>;

    /// Returns whether turbo/boost is currently enabled, or `None` if the host
    /// exposes no turbo control.
    ///
    /// # Errors
    /// Returns [`CpuFreqError::Io`] if a present control file cannot be read.
    fn read_turbo(&self) -> Result<Option<bool>, CpuFreqError>;

    /// Enables or disables turbo/boost.
    ///
    /// # Errors
    /// Returns [`CpuFreqError::Io`] if the control file cannot be written.
    fn write_turbo(&self, enabled: bool) -> Result<(), CpuFreqError>;
}

/// Parses a Linux CPU range list such as `"0-3,5,7"` into explicit indices.
fn parse_cpu_list(raw: &str) -> Result<Vec<u32>, CpuFreqError> {
    let err = |reason: &str| CpuFreqError::ParseOnline {
        raw: raw.to_string(),
        reason: reason.to_string(),
    };
    let mut out = Vec::new();
    for part in raw.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u32 = lo.trim().parse().map_err(|_| err("bad range start"))?;
                let hi: u32 = hi.trim().parse().map_err(|_| err("bad range end"))?;
                if hi < lo {
                    return Err(err("descending range"));
                }
                out.extend(lo..=hi);
            }
            None => out.push(part.trim().parse().map_err(|_| err("bad index"))?),
        }
    }
    Ok(out)
}

/// The live `/sys/devices/system/cpu` implementation of [`CpuFreqSysfs`].
#[derive(Debug, Clone)]
pub struct SysfsCpuFreq {
    root: PathBuf,
}

impl Default for SysfsCpuFreq {
    fn default() -> Self {
        Self::system()
    }
}

impl SysfsCpuFreq {
    /// Returns the implementation rooted at the real `/sys/devices/system/cpu`.
    #[must_use]
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/sys/devices/system/cpu"),
        }
    }

    /// Returns an implementation rooted at `root` (for testing against a temp tree).
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn governor_path(&self, cpu: u32) -> PathBuf {
        self.root
            .join(format!("cpu{cpu}"))
            .join("cpufreq/scaling_governor")
    }

    fn available_path(&self, cpu: u32) -> PathBuf {
        self.root
            .join(format!("cpu{cpu}"))
            .join("cpufreq/scaling_available_governors")
    }

    fn read(path: &Path) -> Result<String, CpuFreqError> {
        std::fs::read_to_string(path).map_err(|source| CpuFreqError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Writes `value` to a sysfs attribute using `O_WRONLY` (no `O_TRUNC`): some
    /// kernel attributes reject the truncating open that `std::fs::write` issues.
    fn write(path: &Path, value: &str) -> Result<(), CpuFreqError> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|source| CpuFreqError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        f.write_all(value.as_bytes())
            .map_err(|source| CpuFreqError::Io {
                path: path.to_path_buf(),
                source,
            })
    }
}

impl CpuFreqSysfs for SysfsCpuFreq {
    fn online_cpus(&self) -> Result<Vec<u32>, CpuFreqError> {
        let raw = Self::read(&self.root.join("online"))?;
        parse_cpu_list(&raw)
    }

    fn available_governors(&self, cpu: u32) -> Result<Vec<String>, CpuFreqError> {
        Ok(Self::read(&self.available_path(cpu))?
            .split_whitespace()
            .map(str::to_string)
            .collect())
    }

    fn read_governor(&self, cpu: u32) -> Result<String, CpuFreqError> {
        Ok(Self::read(&self.governor_path(cpu))?.trim().to_string())
    }

    fn write_governor(&self, cpu: u32, governor: &str) -> Result<(), CpuFreqError> {
        Self::write(&self.governor_path(cpu), governor)
    }

    fn read_turbo(&self) -> Result<Option<bool>, CpuFreqError> {
        // `intel_pstate/no_turbo`: "0" ⇒ turbo enabled (inverted sense).
        let no_turbo = self.root.join("intel_pstate/no_turbo");
        if no_turbo.exists() {
            return Ok(Some(Self::read(&no_turbo)?.trim() == "0"));
        }
        // `cpufreq/boost` (acpi-cpufreq): "1" ⇒ turbo enabled.
        let boost = self.root.join("cpufreq/boost");
        if boost.exists() {
            return Ok(Some(Self::read(&boost)?.trim() == "1"));
        }
        Ok(None)
    }

    fn write_turbo(&self, enabled: bool) -> Result<(), CpuFreqError> {
        let no_turbo = self.root.join("intel_pstate/no_turbo");
        if no_turbo.exists() {
            return Self::write(&no_turbo, if enabled { "0" } else { "1" });
        }
        let boost = self.root.join("cpufreq/boost");
        if boost.exists() {
            return Self::write(&boost, if enabled { "1" } else { "0" });
        }
        // No turbo control: a write that changes nothing must not report success
        // (L-HOST-6). Fail loud so a direct caller learns the write was not applied;
        // `engage`/`Drop` never reach here, as they only write after `read_turbo`
        // returned `Some(_)` (a present control file).
        Err(CpuFreqError::NoTurboControl)
    }
}

/// An RAII guard that pins CPU frequency for a benchmark and **restores the
/// prior settings when dropped** — including on panic, which is the whole point:
/// a benchmark that panics must not leave the machine pinned to `performance`.
///
/// Construct with [`CpuFreqPin::engage`]; hold it for the benchmark's lifetime.
/// It only restores settings it actually changed (a CPU already on `performance`
/// is left untouched and not "restored"), so an unprivileged run that could not
/// write anything drops to a harmless no-op.
#[must_use = "dropping the CpuFreqPin immediately restores scaling; bind it (e.g. `let _pin = …`) for the benchmark's duration"]
pub struct CpuFreqPin<S: CpuFreqSysfs> {
    sysfs: S,
    /// `(cpu, original_governor)` for the CPUs this guard switched to performance.
    restore_governors: Vec<(u32, String)>,
    /// `Some(original_enabled)` iff this guard changed the turbo setting.
    restore_turbo: Option<bool>,
}

impl<S: CpuFreqSysfs> CpuFreqPin<S> {
    /// Pins every online CPU that supports it to the `performance` governor and
    /// disables turbo, recording the prior state for restoration on `Drop`.
    ///
    /// This is best-effort and **lenient by design**: a CPU whose governor cannot
    /// be read or written (e.g. lacking `CAP_DAC_OVERRIDE`), or that does not
    /// offer `performance`, is skipped with a `warn!` rather than aborting the
    /// benchmark. A CPU already on `performance` is left as-is and not recorded.
    /// Even a failure to *enumerate* the online CPUs degrades to a `warn!` and an
    /// empty no-op guard rather than aborting (CFG-4): §7.1 lists cpufreq as the
    /// best-effort exception that degrades **visibly**, never fatal. A benchmark is
    /// a tracked metric, not a pass/fail gate, so it must never fail to *run*
    /// because the noise floor could not be pinned.
    ///
    /// # Errors
    /// Currently infallible: enumeration, per-CPU, and turbo failures are all logged
    /// and degraded to a no-op guard. The `Result` is retained for signature
    /// stability and forward-compatibility with any future genuinely-fatal sub-case.
    pub fn engage(sysfs: S) -> Result<Self, CpuFreqError> {
        // §7.1 best-effort exception (CFG-4): a failure to enumerate the online CPUs
        // is NOT fatal — warn and degrade to an empty no-op guard (nothing pinned,
        // nothing to restore) instead of propagating the error and aborting the
        // benchmark, which was the single remaining intentional fatal path.
        let online = match sysfs.online_cpus() {
            Ok(cpus) => cpus,
            Err(e) => {
                warn!(
                    "cpufreq: cannot enumerate online CPUs ({e}); frequency NOT pinned — \
                     benchmark numbers will carry scaling noise (best-effort, §7.1)"
                );
                return Ok(Self {
                    sysfs,
                    restore_governors: Vec::new(),
                    restore_turbo: None,
                });
            }
        };
        let mut restore_governors = Vec::new();
        let mut skipped = 0usize;

        for cpu in online.iter().copied() {
            // Per-CPU read/availability failures are non-fatal: warn and skip.
            let available = match sysfs.available_governors(cpu) {
                Ok(g) => g,
                Err(e) => {
                    warn!("cpufreq: cpu{cpu}: cannot read available governors: {e}");
                    skipped += 1;
                    continue;
                }
            };
            if !available.iter().any(|g| g == PERFORMANCE) {
                warn!("cpufreq: cpu{cpu}: no `{PERFORMANCE}` governor; leaving as-is");
                skipped += 1;
                continue;
            }
            let current = match sysfs.read_governor(cpu) {
                Ok(g) => g,
                Err(e) => {
                    warn!("cpufreq: cpu{cpu}: cannot read governor: {e}");
                    skipped += 1;
                    continue;
                }
            };
            if current == PERFORMANCE {
                // Already pinned by someone else — do not record, so we do not
                // "restore" a setting we never changed.
                continue;
            }
            match sysfs.write_governor(cpu, PERFORMANCE) {
                Ok(()) => restore_governors.push((cpu, current)),
                Err(e) => {
                    warn!("cpufreq: cpu{cpu}: cannot set `{PERFORMANCE}` governor: {e}");
                    skipped += 1;
                }
            }
        }

        // Turbo is a single global knob; disabling it removes thermal-dependent
        // boost variance. Only record (and later restore) if we actually flip it.
        let mut restore_turbo = None;
        match sysfs.read_turbo() {
            Ok(Some(true)) => match sysfs.write_turbo(false) {
                Ok(()) => restore_turbo = Some(true),
                Err(e) => warn!("cpufreq: cannot disable turbo: {e}"),
            },
            Ok(Some(false)) => { /* already disabled — nothing to restore */ }
            Ok(None) => { /* host exposes no turbo control */ }
            Err(e) => warn!("cpufreq: cannot read turbo state: {e}"),
        }

        if restore_governors.is_empty() && restore_turbo.is_none() {
            warn!(
                "cpufreq: frequency NOT pinned ({} CPU(s) skipped); benchmark numbers will carry \
                 scaling noise — run through the privileged test runner (CAP_DAC_OVERRIDE) to pin",
                skipped
            );
        } else {
            info!(
                "cpufreq: pinned {} CPU(s) to `{PERFORMANCE}`, turbo {}",
                restore_governors.len(),
                if restore_turbo.is_some() {
                    "disabled"
                } else {
                    "unchanged"
                }
            );
        }

        Ok(Self {
            sysfs,
            restore_governors,
            restore_turbo,
        })
    }

    /// The number of CPUs this guard pinned (and will restore on drop).
    #[must_use]
    pub fn pinned_cpus(&self) -> usize {
        self.restore_governors.len()
    }

    /// Whether this guard changed any setting (governor or turbo).
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        !self.restore_governors.is_empty() || self.restore_turbo.is_some()
    }
}

impl<S: CpuFreqSysfs> Drop for CpuFreqPin<S> {
    fn drop(&mut self) {
        // Restore only what we changed. Never panic in drop; surface failures as
        // warnings so a restore problem is visible without unwinding.
        for (cpu, governor) in &self.restore_governors {
            if let Err(e) = self.sysfs.write_governor(*cpu, governor) {
                warn!("cpufreq: cpu{cpu}: failed to restore governor `{governor}`: {e}");
            }
        }
        if let Some(original) = self.restore_turbo {
            if let Err(e) = self.sysfs.write_turbo(original) {
                warn!("cpufreq: failed to restore turbo={original}: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    /// One recorded sysfs mutation, so tests can assert the engage→restore order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        Governor { cpu: u32, value: String },
        Turbo { enabled: bool },
    }

    #[derive(Debug)]
    struct Inner {
        online: Vec<u32>,
        available: Vec<String>,
        governors: BTreeMap<u32, String>,
        turbo: Option<bool>,
        /// CPUs whose governor write fails (simulating EACCES without caps).
        deny_write: Vec<u32>,
        /// When set, `online_cpus()` returns an error (simulating an unreadable
        /// `cpu/online`), so a test can drive the enumeration-failure path.
        fail_online: bool,
        log: Vec<Op>,
    }

    /// In-memory recording fake: clone shares one backing store, so a test can
    /// inspect final state and the write log after the guard has been dropped.
    #[derive(Clone)]
    struct RecordingCpuFreq {
        inner: Arc<Mutex<Inner>>,
    }

    impl RecordingCpuFreq {
        fn new(online: &[u32], default_governor: &str) -> Self {
            let governors = online
                .iter()
                .map(|c| (*c, default_governor.to_string()))
                .collect();
            Self {
                inner: Arc::new(Mutex::new(Inner {
                    online: online.to_vec(),
                    available: vec!["performance".into(), "powersave".into()],
                    governors,
                    turbo: Some(true),
                    deny_write: Vec::new(),
                    fail_online: false,
                    log: Vec::new(),
                })),
            }
        }

        fn fail_online(&self) {
            self.inner.lock().unwrap().fail_online = true;
        }

        fn set_governor(&self, cpu: u32, value: &str) {
            self.inner
                .lock()
                .unwrap()
                .governors
                .insert(cpu, value.to_string());
        }
        fn deny_write(&self, cpu: u32) {
            self.inner.lock().unwrap().deny_write.push(cpu);
        }
        fn set_turbo(&self, turbo: Option<bool>) {
            self.inner.lock().unwrap().turbo = turbo;
        }
        fn set_available(&self, available: &[&str]) {
            self.inner.lock().unwrap().available =
                available.iter().map(|s| s.to_string()).collect();
        }
        fn governor(&self, cpu: u32) -> String {
            self.inner
                .lock()
                .unwrap()
                .governors
                .get(&cpu)
                .cloned()
                .unwrap_or_default()
        }
        fn turbo(&self) -> Option<bool> {
            self.inner.lock().unwrap().turbo
        }
        fn log(&self) -> Vec<Op> {
            self.inner.lock().unwrap().log.clone()
        }
    }

    fn eacces(path: &Path) -> CpuFreqError {
        CpuFreqError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        }
    }

    impl CpuFreqSysfs for RecordingCpuFreq {
        fn online_cpus(&self) -> Result<Vec<u32>, CpuFreqError> {
            let inner = self.inner.lock().unwrap();
            if inner.fail_online {
                return Err(CpuFreqError::ParseOnline {
                    raw: "<injected>".to_string(),
                    reason: "simulated cpu/online read failure".to_string(),
                });
            }
            Ok(inner.online.clone())
        }
        fn available_governors(&self, _cpu: u32) -> Result<Vec<String>, CpuFreqError> {
            Ok(self.inner.lock().unwrap().available.clone())
        }
        fn read_governor(&self, cpu: u32) -> Result<String, CpuFreqError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .governors
                .get(&cpu)
                .cloned()
                .unwrap_or_default())
        }
        fn write_governor(&self, cpu: u32, governor: &str) -> Result<(), CpuFreqError> {
            let mut inner = self.inner.lock().unwrap();
            if inner.deny_write.contains(&cpu) {
                return Err(eacces(Path::new(&format!("cpu{cpu}/scaling_governor"))));
            }
            inner.governors.insert(cpu, governor.to_string());
            inner.log.push(Op::Governor {
                cpu,
                value: governor.to_string(),
            });
            Ok(())
        }
        fn read_turbo(&self) -> Result<Option<bool>, CpuFreqError> {
            Ok(self.inner.lock().unwrap().turbo)
        }
        fn write_turbo(&self, enabled: bool) -> Result<(), CpuFreqError> {
            let mut inner = self.inner.lock().unwrap();
            // Model a control-less host like the real `SysfsCpuFreq`: a write with no
            // turbo control fails loud rather than lying, and records nothing.
            if inner.turbo.is_none() {
                return Err(CpuFreqError::NoTurboControl);
            }
            inner.turbo = Some(enabled);
            inner.log.push(Op::Turbo { enabled });
            Ok(())
        }
    }

    #[test]
    fn parses_cpu_ranges() {
        assert_eq!(parse_cpu_list("0-7").unwrap(), (0..=7).collect::<Vec<_>>());
        assert_eq!(parse_cpu_list("0-3,5,7").unwrap(), vec![0, 1, 2, 3, 5, 7]);
        assert_eq!(parse_cpu_list("2").unwrap(), vec![2]);
        assert_eq!(parse_cpu_list("\n").unwrap(), Vec::<u32>::new());
        assert!(parse_cpu_list("3-1").is_err());
        assert!(parse_cpu_list("x").is_err());
    }

    #[test]
    fn engages_performance_on_every_online_cpu() {
        let fake = RecordingCpuFreq::new(&[0, 1, 2, 3], "powersave");
        let pin = CpuFreqPin::engage(fake.clone()).unwrap();
        for cpu in 0..=3 {
            assert_eq!(fake.governor(cpu), "performance", "cpu{cpu} must be pinned");
        }
        assert_eq!(pin.pinned_cpus(), 4);
        assert!(pin.is_pinned());
    }

    #[test]
    fn drop_restores_each_cpus_original_governor() {
        let fake = RecordingCpuFreq::new(&[0, 1, 2], "powersave");
        // cpu1 starts already on performance: it must NOT be recorded or restored.
        fake.set_governor(1, "performance");
        {
            let _pin = CpuFreqPin::engage(fake.clone()).unwrap();
            assert_eq!(fake.governor(0), "performance");
            assert_eq!(fake.governor(2), "performance");
        }
        // After drop: cpu0/cpu2 back to powersave; cpu1 untouched throughout.
        assert_eq!(fake.governor(0), "powersave");
        assert_eq!(fake.governor(2), "powersave");
        assert_eq!(fake.governor(1), "performance");
        // cpu1 must never appear in the write log (neither pinned nor restored).
        assert!(
            !fake
                .log()
                .iter()
                .any(|op| matches!(op, Op::Governor { cpu: 1, .. })),
            "an already-performance CPU must never be written"
        );
    }

    #[test]
    fn disables_then_restores_turbo() {
        let fake = RecordingCpuFreq::new(&[0], "powersave");
        {
            let _pin = CpuFreqPin::engage(fake.clone()).unwrap();
            assert_eq!(
                fake.turbo(),
                Some(false),
                "turbo must be disabled while pinned"
            );
        }
        assert_eq!(fake.turbo(), Some(true), "turbo must be restored on drop");
    }

    #[test]
    fn turbo_unsupported_is_never_written() {
        let fake = RecordingCpuFreq::new(&[0], "powersave");
        fake.set_turbo(None);
        {
            let _pin = CpuFreqPin::engage(fake.clone()).unwrap();
        }
        assert!(
            !fake.log().iter().any(|op| matches!(op, Op::Turbo { .. })),
            "no turbo control ⇒ no turbo write"
        );
    }

    #[test]
    fn permission_denied_cpu_is_skipped_not_restored() {
        let fake = RecordingCpuFreq::new(&[0, 1], "powersave");
        fake.deny_write(1); // simulate EACCES on cpu1 (no CAP_DAC_OVERRIDE)
        {
            let pin = CpuFreqPin::engage(fake.clone()).unwrap();
            assert_eq!(pin.pinned_cpus(), 1, "only cpu0 was pinnable");
            assert_eq!(fake.governor(0), "performance");
            assert_eq!(fake.governor(1), "powersave", "cpu1 unchanged");
        }
        // cpu1 was never changed, so drop must never write it (no-op-release guard).
        assert_eq!(fake.governor(0), "powersave", "cpu0 restored");
        assert!(
            !fake
                .log()
                .iter()
                .any(|op| matches!(op, Op::Governor { cpu: 1, .. })),
            "a CPU we failed to pin must never be 'restored'"
        );
    }

    #[test]
    fn no_performance_governor_degrades_to_noop() {
        let fake = RecordingCpuFreq::new(&[0], "ondemand");
        fake.set_available(&["ondemand", "conservative"]);
        fake.set_turbo(None);
        let pin = CpuFreqPin::engage(fake.clone()).unwrap();
        assert!(!pin.is_pinned(), "nothing pinnable ⇒ no-op guard");
        assert_eq!(fake.governor(0), "ondemand", "left untouched");
    }

    // CFG-4 (§7.1): a failure to *enumerate* the online CPUs must degrade to a
    // logged no-op guard, NOT propagate an error — cpufreq is the best-effort
    // benchmark knob that degrades visibly, never aborts. Goes red on the old
    // `let online = sysfs.online_cpus()?;` (which returned `Err` here, so `.expect`
    // below would panic and fail the test).
    #[test]
    fn online_enumeration_failure_degrades_to_noop_not_err() {
        let fake = RecordingCpuFreq::new(&[0, 1], "powersave");
        fake.fail_online();
        let pin = CpuFreqPin::engage(fake.clone())
            .expect("enumeration failure must degrade to a no-op guard, not Err");
        assert!(!pin.is_pinned(), "a no-op guard must report nothing pinned");
        assert_eq!(pin.pinned_cpus(), 0);
        // No CPU was touched: governors stay at their original value and no write was
        // logged, so the guard's Drop is inert too.
        assert_eq!(fake.governor(0), "powersave", "cpu0 untouched");
        assert_eq!(fake.governor(1), "powersave", "cpu1 untouched");
        assert!(
            fake.log().is_empty(),
            "no sysfs write may occur when enumeration fails"
        );
        drop(pin);
        assert!(
            fake.log().is_empty(),
            "dropping a no-op guard must not write anything"
        );
    }

    // L-HOST-5: the module headline claims settings are "restored on Drop, including
    // on panic". Drive that explicitly: engage a pin, panic inside catch_unwind, and
    // after the unwind confirm the governor was restored. Goes RED if restoration
    // were moved off the Drop path (e.g. into an explicit shutdown() that a panic
    // skips).
    #[test]
    fn pin_restores_governor_on_panic() {
        let fake = RecordingCpuFreq::new(&[0], "powersave");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _pin = CpuFreqPin::engage(fake.clone()).unwrap();
            assert_eq!(fake.governor(0), "performance", "pinned while alive");
            panic!("benchmark panicked while pinned");
        }));
        assert!(result.is_err(), "the closure must have unwound");
        // Drop ran during the unwind and restored the original governor.
        assert_eq!(
            fake.governor(0),
            "powersave",
            "governor must be restored even when the benchmark panics"
        );
    }

    // L-HOST-5 (restore-failure branch): if a restore write fails during Drop, the
    // guard must WARN, never panic — Drop must not unwind. Deny the restore write
    // after engage, then drop; reaching the assertions without a panic exercises the
    // `warn!` branch. Goes RED if Drop's restore used `.expect()`/`?` on the write.
    #[test]
    fn drop_warns_and_does_not_panic_when_restore_write_fails() {
        let fake = RecordingCpuFreq::new(&[0], "powersave");
        let pin = CpuFreqPin::engage(fake.clone()).unwrap();
        assert_eq!(fake.governor(0), "performance");
        // Make the restore write fail (simulate EACCES appearing mid-benchmark).
        fake.deny_write(0);
        drop(pin); // must warn, not panic
        // The restore could not be applied, so the governor stays at performance;
        // the load-bearing assertion is that we got here without unwinding.
        assert_eq!(fake.governor(0), "performance");
    }

    // L-HOST-6: a turbo write on a host with no turbo/boost control must FAIL loud,
    // not return a silent Ok — "a knob write that fails must not lie". Goes RED on
    // the old `Ok(())` no-op branch. Covers both the fake and the real sysfs impl.
    #[test]
    fn write_turbo_without_control_errors() {
        let fake = RecordingCpuFreq::new(&[0], "powersave");
        fake.set_turbo(None); // host exposes no turbo control
        assert!(
            matches!(fake.write_turbo(false), Err(CpuFreqError::NoTurboControl)),
            "a turbo write with no control must fail loud, not return Ok"
        );
        assert!(
            !fake.log().iter().any(|op| matches!(op, Op::Turbo { .. })),
            "a failed no-control turbo write must record nothing"
        );

        // The real sysfs impl over an empty root (neither intel_pstate/no_turbo nor
        // cpufreq/boost present) must likewise fail loud.
        let dir = tempfile::tempdir().expect("tempdir");
        let sysfs = SysfsCpuFreq::with_root(dir.path());
        assert!(
            matches!(sysfs.write_turbo(false), Err(CpuFreqError::NoTurboControl)),
            "SysfsCpuFreq with no turbo control must fail loud"
        );
    }
}
