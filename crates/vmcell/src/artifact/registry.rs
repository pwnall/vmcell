//! The **one** artifact-registry resolution law, parameterized per kind (design §10.5, v33 delta 6).
//!
//! vmcell registers three kinds of artifact by label — kernels, rootfses, and handlers — and until
//! v33 only the kernel had a registry at all. The asymmetry was never a decision (§10.5 opens by
//! saying so), and closing it by writing the merge/sort/collision logic twice more is how three
//! copies of one rule drift into three rules. So the shape the kernel registry already had is
//! extracted here once and each kind supplies only what genuinely differs: its pins namespace, how
//! one entry parses, and what filename a label lands on.
//!
//! What does **not** differ, and is therefore not a per-kind decision any more:
//!
//! * an absent namespace resolves to an empty registry, never an error (the error belongs to the
//!   verb that wanted a label, which can say which labels *do* exist);
//! * the order is **byte-lexicographic on the label**, applied explicitly rather than inherited
//!   from `serde_json`'s `BTreeMap` backing — a transitive dependency enabling `preserve_order`
//!   would otherwise silently switch every kind's build order to document order;
//! * two labels that sanitize to one on-disk filename are **rejected naming both**, at the one
//!   reader every producer goes through, so a colliding pair cannot reach a build by any route.

use crate::error::{Error, Result};

/// What one registry kind must state about itself for [`resolve_registry`] to apply the law.
pub(crate) struct RegistryKind<'a> {
    /// The pins namespace holding the label map, e.g. `"kernels"` or `"rootfs"`.
    pub namespace: &'a str,
    /// The on-disk artifact filename a label resolves to — the collision reject's key.
    ///
    /// A function rather than a format string because each kind sanitizes and extends differently
    /// (`vmlinux-6-12-94` vs `rootfs-debian-systemd.erofs`), and the sanitization law is the kind's
    /// own one-law composer, never re-spelled here.
    pub filename: &'a dyn Fn(&str) -> String,
    /// What the collision message tells the operator to do about the two labels it names.
    ///
    /// Per-kind because the consequence differs: a colliding kernel pair overwrites two sidecars
    /// as well as the image. The remedy never does — vmcell cannot pick a winner between two
    /// opaque strings, so the operator renames one.
    pub collision_consequence: &'a str,
}

/// Resolves one kind's registry from an already-merged pins document: parse, sort, reject
/// collisions.
///
/// `parse` sees the label and its raw spec and produces the kind's entry type — that is where each
/// kind's strictness lives, and it is the only per-entry judgement the law delegates.
///
/// # Errors
///
/// Whatever `parse` returns, plus [`Error::Artifact`] when two labels sanitize to one filename.
pub(crate) fn resolve_registry<T>(
    doc: &serde_json::Value,
    kind: &RegistryKind<'_>,
    parse: impl Fn(&str, &serde_json::Value) -> Result<T>,
    label_of: impl Fn(&T) -> &str,
) -> Result<Vec<T>> {
    let Some(entries) = doc.get(kind.namespace).and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };
    let mut resolved: Vec<T> = entries
        .iter()
        .map(|(label, spec)| parse(label, spec))
        .collect::<Result<Vec<_>>>()?;
    // Explicitly, not incidentally: see the module doc.
    resolved.sort_by(|a, b| label_of(a).cmp(label_of(b)));
    reject_sanitized_label_collision(&resolved, kind, &label_of)?;
    Ok(resolved)
}

/// Rejects two labels that sanitize to the **same** on-disk filename, naming both.
///
/// The filename laws sanitize `.`→`-` so a dotted label cannot make `Path::with_extension` eat its
/// trailing component — which means `6.12.94` and `6-12-94` are two distinct pins keys, two
/// distinct cache-key hashes, and **one** artifact. Nothing else notices: a build over both writes
/// them in label order, the second silently overwrites the first, and because each build's cache
/// key still says "this is mine" the two labels evict each other on every warm run, forever.
///
/// Checked on the SORTED registry so the pair is named in a stable order.
///
/// # Errors
/// [`Error::Artifact`] naming both colliding labels and the filename they share.
fn reject_sanitized_label_collision<T>(
    entries: &[T],
    kind: &RegistryKind<'_>,
    label_of: &impl Fn(&T) -> &str,
) -> Result<()> {
    let mut by_filename: std::collections::HashMap<String, &str> =
        std::collections::HashMap::with_capacity(entries.len());
    for entry in entries {
        let label = label_of(entry);
        let filename = (kind.filename)(label);
        if let Some(previous) = by_filename.insert(filename.clone(), label) {
            return Err(Error::Artifact(format!(
                "pins `{}` labels `{previous}` and `{label}` both sanitize to the one artifact \
                 filename `{filename}` (the `.`→`-` law, §10.5): {} — rename one label",
                kind.namespace, kind.collision_consequence
            )));
        }
    }
    Ok(())
}

/// The reserved label naming a kind's **default** artifact — the one a cell that names no label
/// gets, and the one whose pins flatten to the un-suffixed keys every pre-v33 consumer reads.
///
/// It is a real registry entry rather than a special case beside the registry: that is what makes
/// "the canonical artifacts stay byte-identical for a cell that names no label" (§10.5's
/// what-must-not-regress) a property of the *data* instead of a promise about the code.
pub const DEFAULT_LABEL: &str = "default";

/// The label a registry entry contributes to the one-law key composers: `None` for
/// [`DEFAULT_LABEL`], `Some(label)` otherwise.
///
/// The whole reason the default flattens to `rootfs_image` rather than `rootfs_default_image`:
/// every pre-v33 reader — including `resolve_builder_base`, which picks the image that builds
/// *kernels* — keeps working untouched, so reshaping the namespace cannot silently repoint a
/// consumer it was never about.
#[must_use]
pub fn registry_label(label: &str) -> Option<&str> {
    (label != DEFAULT_LABEL).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Entry {
        label: String,
    }

    fn kind() -> RegistryKind<'static> {
        RegistryKind {
            namespace: "things",
            filename: &|label: &str| format!("thing-{}", label.replace('.', "-")),
            collision_consequence: "one would overwrite the other",
        }
    }

    fn parse(label: &str, _spec: &serde_json::Value) -> Result<Entry> {
        Ok(Entry {
            label: label.to_string(),
        })
    }

    fn resolve(json: &str) -> Result<Vec<Entry>> {
        let doc: serde_json::Value = serde_json::from_str(json).expect("fixture json");
        resolve_registry(&doc, &kind(), parse, |e: &Entry| e.label.as_str())
    }

    // An absent namespace is an EMPTY registry, not an error: the error belongs to whichever verb
    // wanted a label, because only that verb can say which labels do exist. RED on a resolver that
    // errors here — every kind would then need a namespace in every overlay.
    #[test]
    fn an_absent_namespace_resolves_to_an_empty_registry() {
        assert_eq!(resolve("{}").expect("absent is empty"), vec![]);
        assert_eq!(
            resolve(r#"{"other": {"a": {}}}"#).expect("unrelated namespace"),
            vec![]
        );
        // A namespace of the wrong SHAPE is also empty here rather than an error: the overlay
        // parser's shape check is the one authority on shapes, and a second copy of that judgement
        // in the resolver is the duplicate that diverges.
        assert_eq!(
            resolve(r#"{"things": "scalar"}"#).expect("wrong shape"),
            vec![]
        );
    }

    // Byte-lexicographic on the label, applied EXPLICITLY. The input here is deliberately reversed
    // relative to the output, so the assertion cannot be satisfied by `serde_json`'s map backing
    // happening to be sorted — the "sorted on purpose vs sorted by accident" distinction §5.5 names.
    #[test]
    fn the_order_is_byte_lexicographic_on_the_label() {
        let entries = resolve(r#"{"things": {"6.6.143": {}, "zz": {}, "6.12.94": {}, "a": {}}}"#)
            .expect("resolves");
        let labels: Vec<&str> = entries.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            labels,
            vec!["6.12.94", "6.6.143", "a", "zz"],
            "byte order is not version order — `6.12.94` before `6.6.143` — and that is deliberate: \
             the labels are opaque strings and inventing a version collation would be a second, \
             guessing law"
        );
    }

    // The collision reject, and it must name BOTH labels plus the filename they share — an
    // operator who is told only "collision" has to go find the pair themselves. RED on a resolver
    // that keeps the last writer, which is the silent overwrite this exists to prevent.
    #[test]
    fn two_labels_sanitizing_to_one_filename_are_rejected_naming_both() {
        let err = resolve(r#"{"things": {"6.12.94": {}, "6-12-94": {}}}"#)
            .expect_err("a sanitized-filename collision must be refused, not resolved");
        let msg = err.to_string();
        for named in ["6.12.94", "6-12-94", "thing-6-12-94", "things"] {
            assert!(msg.contains(named), "the message must name {named}: {msg}");
        }
        // Positive control: the same two labels, one renamed, resolve fine — so the rejection is
        // about the collision and not about dotted labels in general.
        let ok = resolve(r#"{"things": {"6.12.94": {}, "6-12-95": {}}}"#).expect("no collision");
        assert_eq!(ok.len(), 2);
    }

    // `default` is the one label that contributes NO suffix, which is what makes a pre-v33
    // consumer's flat key keep working. RED on a mapping that returns `Some("default")` — every
    // existing `rootfs_image` reader would then be reading a key nothing emits.
    #[test]
    fn the_default_label_contributes_no_suffix() {
        assert_eq!(registry_label(DEFAULT_LABEL), None);
        assert_eq!(registry_label("debian-systemd"), Some("debian-systemd"));
        // Not case-folded and not trimmed: labels are opaque, and quietly accepting `Default` as
        // the default would make two entries mean one artifact.
        assert_eq!(registry_label("Default"), Some("Default"));
        assert_eq!(registry_label("default "), Some("default "));
    }
}
