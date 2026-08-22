//! The machine-readable `bench-vm` report — the alternative to scraping stdout.
//!
//! WHY THIS EXISTS. The 2026-08-21 A/B driver was shell, and it read `bench-vm`'s human table with
//! regexes. Three of them broke, each in a way that produced *numbers* rather than an error:
//! `crosvm`'s log spam interleaved with the table, the `Cold Boot (WARM-CACHE: …)` parenthetical
//! moved the column the value sat in, and padded phase names shifted the split. A regex that
//! matches the wrong line still yields a float, so the failure surfaced as a plausible measurement.
//! `bench-vm` emits these types under `--report json` instead; `--report text` stays the default so
//! nothing existing changes shape.
//!
//! TWO RULES THE TYPES CANNOT ENFORCE, stated here because they bind the emitting side:
//!
//! * every mode that prints a percentile today emits the matching [`Metric`] — a mode that prints a
//!   number no `Metric` carries is a hole to fill, never a regex to widen;
//! * metric names are stable snake_case identifiers, and phase-budget rows are qualified by path
//!   (`phase_cold_connect`, `phase_restore_teardown`) because the COLD and RESTORE paths print the
//!   same row names and a naive collector silently kept only the first.
//!
//! The codec is JSON, and the round-trip test in this module runs over `serde_json` — the codec
//! these types actually ship over. That is deliberate: this repo has already shipped a DTO whose
//! presence attributes (`skip_serializing_if`/`default`) survived JSON and were corrupted by
//! postcard, so a round-trip proof on the wrong codec proves nothing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The schema version [`BenchReport`] is emitted at and the only one [`BenchReport::from_json`]
/// accepts.
///
/// Bump it when a field changes meaning or disappears; a consumer that silently reads a report
/// from a different schema is the "control that did not apply" class one crate over.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// The unit a [`Metric`]'s percentiles are expressed in.
///
/// Carried per metric rather than encoded in the metric's name: a comparator that has to infer
/// "this one is bytes" from a substring is a regex again.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    /// Milliseconds.
    Millis,
    /// Microseconds.
    Micros,
    /// Bytes.
    Bytes,
    /// Mebibytes (2^20 bytes).
    Mib,
    /// A dimensionless count.
    Count,
    /// A percentage in `0.0..=100.0`.
    Percent,
}

/// How the VMM binary the run actually executed was resolved.
///
/// WHY THIS IS A TYPE AND NOT A BOOLEAN, let alone prose. The 2026-08-21 pass printed "via
/// `$VMCELL_CH_BIN`" from the *driver's* knowledge that it had exported the variable — while the
/// old arm, which predates the variable, resolved the name off `PATH`. The report must state what
/// the process did, so the string `via $VAR` can never be emitted for a run that searched `PATH`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BinSource {
    /// The named environment variable held the path this run executed.
    EnvVar {
        /// The variable's name, e.g. `VMCELL_CH_BIN`.
        name: String,
    },
    /// No override applied: the binary was found by searching `PATH` (or by the backend's own
    /// hardcoded default, which is the same fact from a consumer's point of view — nothing the
    /// driver set decided it).
    Path,
}

impl std::fmt::Display for BinSource {
    /// The one rendering of a resolution, shared by `bench-vm`'s text output and by the A/B
    /// guard's failure message — so the phrase "via $VAR" can only ever be printed for a run that
    /// actually read the variable. The 2026-08-21 driver printed that phrase from its own
    /// knowledge that it had exported the variable, for an arm that had never heard of it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvVar { name } => write!(f, "via ${name}"),
            Self::Path => write!(f, "found on PATH"),
        }
    }
}

/// One measured quantity: its sample count, its percentiles, and how many samples never became
/// measurements.
///
/// `dropped` and `warmup_failed` are on the metric rather than on the run because they scope the
/// percentiles beside them: a p50 over three surviving samples out of ten is a different claim
/// from a p50 over ten, and a comparator that cannot see the difference will happily rank them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Metric {
    /// Stable snake_case identifier, e.g. `cold_boot`, `phase_cold_connect`, `session_connect`.
    pub name: String,
    /// The unit `p50`/`p95`/`p99`/`max` are expressed in.
    pub unit: Unit,
    /// Number of samples the percentiles were computed over.
    pub n: usize,
    /// 50th percentile.
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Largest observed sample.
    pub max: f64,
    /// Iterations that produced no sample (a failed boot, a refused capability, a timeout).
    pub dropped: usize,
    /// Warmup iterations that failed. Kept separate from `dropped` because a failed warmup does not
    /// contaminate the percentiles, while a dropped measurement iteration does.
    pub warmup_failed: usize,
}

impl Metric {
    /// A metric with nothing dropped. Use [`Metric::with_dropped`] / [`Metric::with_warmup_failed`]
    /// for the lossy cases, so a caller that forgets one of them under-reports rather than
    /// silently mislabels.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        unit: Unit,
        n: usize,
        p50: f64,
        p95: f64,
        p99: f64,
        max: f64,
    ) -> Self {
        Self {
            name: name.into(),
            unit,
            n,
            p50,
            p95,
            p99,
            max,
            dropped: 0,
            warmup_failed: 0,
        }
    }

    /// Records `dropped` iterations that produced no sample.
    #[must_use]
    pub fn with_dropped(mut self, dropped: usize) -> Self {
        self.dropped = dropped;
        self
    }

    /// Records `warmup_failed` failed warmup iterations.
    #[must_use]
    pub fn with_warmup_failed(mut self, warmup_failed: usize) -> Self {
        self.warmup_failed = warmup_failed;
        self
    }
}

/// One `bench-vm` invocation's full result: what was run, what it ran against, and what it
/// measured.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BenchReport {
    /// Always [`REPORT_SCHEMA_VERSION`] on emit.
    pub schema_version: u32,
    /// The backend that ran, e.g. `cloud-hypervisor`, `qemu`.
    pub backend: String,
    /// The `--mode` that ran, e.g. `latency`, `vsock-rtt`.
    pub mode: String,
    /// The VMM binary path this process actually executed — resolved, not requested.
    pub vmm_binary: String,
    /// How `vmm_binary` was resolved. See [`BinSource`] for why this is not prose.
    pub vmm_binary_source: BinSource,
    /// The guest kernel image this run booted.
    pub kernel: PathBuf,
    /// The rootfs image this run booted.
    pub rootfs: PathBuf,
    /// The knobs that shape the numbers: `profile`, `verbosity`, `console`, `mem_mib`,
    /// `iterations`, `warmup`. A `BTreeMap` so the emitted JSON key order is stable and two
    /// reports diff cleanly.
    pub knobs: BTreeMap<String, String>,
    /// Every measured quantity, in emission order.
    pub metrics: Vec<Metric>,
    /// Self-skips and capability refusals, verbatim. A run that skipped half its matrix and a run
    /// that measured all of it must not be indistinguishable in the artifact.
    pub notes: Vec<String>,
}

impl BenchReport {
    /// The metric named `name`, if the run emitted one.
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<&Metric> {
        self.metrics.iter().find(|m| m.name == name)
    }

    /// Pretty-printed JSON, the form `bench-vm --report json` writes.
    ///
    /// # Errors
    ///
    /// [`ReportError::Json`] if serialization fails.
    pub fn to_json(&self) -> Result<String, ReportError> {
        serde_json::to_string_pretty(self).map_err(ReportError::Json)
    }

    /// Parses a report, **rejecting** any `schema_version` other than [`REPORT_SCHEMA_VERSION`].
    ///
    /// WHY REJECT RATHER THAN ADAPT. A comparator that reads an unknown schema leniently produces
    /// confident numbers out of fields whose meaning it guessed — the same shape as the control
    /// that silently did not apply. When a v2 exists, the compatibility decision is written here
    /// deliberately; until then, anything but 1 stops the run.
    ///
    /// # Errors
    ///
    /// [`ReportError::Json`] if the text is not a report; [`ReportError::SchemaVersion`] if it is a
    /// report from another schema.
    pub fn from_json(text: &str) -> Result<Self, ReportError> {
        let report: Self = serde_json::from_str(text).map_err(ReportError::Json)?;
        if report.schema_version != REPORT_SCHEMA_VERSION {
            return Err(ReportError::SchemaVersion {
                found: report.schema_version,
                expected: REPORT_SCHEMA_VERSION,
            });
        }
        Ok(report)
    }
}

/// What can go wrong reading or writing a [`BenchReport`].
#[derive(Debug)]
pub enum ReportError {
    /// The text is not a well-formed report (or the report could not be serialized).
    Json(serde_json::Error),
    /// The report is well-formed but from another schema version.
    SchemaVersion {
        /// The version the report carries.
        found: u32,
        /// The version this build understands.
        expected: u32,
    },
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "bench report is not well-formed JSON: {e}"),
            Self::SchemaVersion { found, expected } => write!(
                f,
                "bench report is schema v{found}, this build understands v{expected}. Rebuild the \
                 arm's `bench-vm` from a tree whose report schema matches, or compare reports of \
                 one schema only — reading a foreign schema leniently is how a comparison produces \
                 confident numbers from fields it guessed at."
            ),
        }
    }
}

impl std::error::Error for ReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::SchemaVersion { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report with every field populated and both [`BinSource`] variants exercised across the
    /// two metrics — an all-defaults fixture round-trips even when a field is dropped from the
    /// struct, which is the round-trip test that proves nothing.
    fn fixture(source: BinSource) -> BenchReport {
        let mut knobs = BTreeMap::new();
        knobs.insert("profile".to_string(), "release".to_string());
        knobs.insert("mem_mib".to_string(), "512".to_string());
        knobs.insert("iterations".to_string(), "10".to_string());
        BenchReport {
            schema_version: REPORT_SCHEMA_VERSION,
            backend: "cloud-hypervisor".to_string(),
            mode: "latency".to_string(),
            vmm_binary: "/usr/local/bin/cloud-hypervisor".to_string(),
            vmm_binary_source: source,
            kernel: PathBuf::from("/var/lib/vmcell/artifacts/vmlinux"),
            rootfs: PathBuf::from("/var/lib/vmcell/artifacts/rootfs.erofs"),
            knobs,
            metrics: vec![
                Metric::new("cold_boot", Unit::Millis, 10, 41.5, 55.0, 61.0, 61.0),
                Metric::new(
                    "phase_cold_connect",
                    Unit::Micros,
                    10,
                    900.0,
                    1_200.0,
                    1_500.0,
                    1_500.0,
                )
                .with_dropped(2)
                .with_warmup_failed(1),
            ],
            notes: vec!["SKIP qemu nested_virt".to_string()],
        }
    }

    #[test]
    fn round_trips_through_the_codec_it_ships_over() {
        for source in [
            BinSource::EnvVar {
                name: "VMCELL_CH_BIN".to_string(),
            },
            BinSource::Path,
        ] {
            let report = fixture(source);
            let json = report.to_json().expect("serialize");
            let back = BenchReport::from_json(&json).expect("parse");
            assert_eq!(report, back, "report did not survive a JSON round trip");
        }
    }

    #[test]
    fn json_keys_are_the_stable_names_consumers_read() {
        // The whole point of the report is that a consumer stops guessing. Renaming a field is a
        // break for the tracked-metrics job the spec anticipates, so the names are asserted rather
        // than left to whatever serde derives after the next refactor.
        let json = fixture(BinSource::EnvVar {
            name: "VMCELL_CH_BIN".to_string(),
        })
        .to_json()
        .expect("serialize");
        for key in [
            "\"schema_version\"",
            "\"backend\"",
            "\"mode\"",
            "\"vmm_binary\"",
            "\"vmm_binary_source\"",
            "\"kernel\"",
            "\"rootfs\"",
            "\"knobs\"",
            "\"metrics\"",
            "\"notes\"",
            "\"warmup_failed\"",
        ] {
            assert!(
                json.contains(key),
                "emitted report is missing {key}:\n{json}"
            );
        }
        // The tagged shape, both halves: an `EnvVar` carries the variable's name, and the tag is
        // the snake_case discriminant a jq filter matches on.
        assert!(json.contains("\"kind\": \"env_var\""), "{json}");
        assert!(json.contains("\"name\": \"VMCELL_CH_BIN\""), "{json}");
    }

    #[test]
    fn path_source_is_representable_without_a_variable_name() {
        let json = serde_json::to_string(&BinSource::Path).expect("serialize");
        assert_eq!(json, r#"{"kind":"path"}"#);
    }

    #[test]
    fn a_foreign_schema_version_is_refused_not_read() {
        let mut report = fixture(BinSource::Path);
        report.schema_version = REPORT_SCHEMA_VERSION + 1;
        let json = serde_json::to_string(&report).expect("serialize");
        match BenchReport::from_json(&json) {
            Err(ReportError::SchemaVersion { found, expected }) => {
                assert_eq!(found, REPORT_SCHEMA_VERSION + 1);
                assert_eq!(expected, REPORT_SCHEMA_VERSION);
            }
            other => panic!("expected a schema-version refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_path_resolution_never_renders_as_via_a_variable() {
        assert_eq!(
            BinSource::EnvVar {
                name: "VMCELL_CH_BIN".to_string()
            }
            .to_string(),
            "via $VMCELL_CH_BIN"
        );
        let path = BinSource::Path.to_string();
        assert_eq!(path, "found on PATH");
        assert!(
            !path.contains("via $"),
            "a PATH resolution rendered as an env-var one: {path}"
        );
    }

    #[test]
    fn metric_lookup_finds_by_exact_name() {
        let report = fixture(BinSource::Path);
        assert_eq!(report.metric("cold_boot").map(|m| m.p50), Some(41.5));
        // Qualified phase names exist precisely so COLD and RESTORE rows cannot collide; a prefix
        // match would re-open that.
        assert!(report.metric("cold").is_none());
        assert_eq!(
            report.metric("phase_cold_connect").map(|m| m.dropped),
            Some(2)
        );
    }
}
