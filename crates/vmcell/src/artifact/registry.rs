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
    /// The on-disk artifact **name** a label resolves to — the collision reject's key.
    ///
    /// A function rather than a format string because each kind sanitizes and extends differently
    /// (`vmlinux-6-12-94` vs `rootfs-debian-systemd`), and the sanitization law is the kind's own
    /// one-law composer, never re-spelled here.
    ///
    /// A kind whose artifact can carry more than one extension returns the **stem**, because that
    /// is what actually collides: `Path::with_extension` derives every sidecar from the image name,
    /// so two labels sharing a stem share one `.cache_key` whatever their images are called
    /// (§18 delta 8 — the `rootfs` kind is the first with two formats).
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
                 name `{filename}` (the `.`→`-` law, §10.5): {} — rename one label",
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

/// The **one** unknown-label refusal every registry selector shares (§10.5): it names the label
/// that was asked for, the labels that ARE registered, and the route that adds one.
///
/// `kind` is the noun the operator typed (`kernel`), `namespace` the pins key it lives under
/// (`kernels`); the two differ per kind and neither is derivable from the other, which is why both
/// are parameters rather than one string with a rule for turning it into the other.
///
/// # Why the shared core does not raise this itself
///
/// `resolve_registry` resolves an absent namespace to an **empty** registry, never an error,
/// because only the verb that wanted a label can say which labels exist — see the module doc. That
/// leaves the message to the verb, which is exactly the shape that drifts once each verb writes its
/// own `format!`: by v33 delta 6c there were **four** copies (the CLI's kernel, rootfs and handler
/// selectors, plus [`crate::artifact::build_labelled_kernel`]'s pre-flight), held together only by a
/// byte-equality test between two of them. `vmcell build-kernels <label>` and the library entry
/// point are two documented routes to the same build (§5.6/§10.4), so a consumer who reads one
/// sentence and gets the other has learned nothing about which route produced it.
///
/// Public because the fourth copy lives in this crate's own public entry point *and* the CLI is a
/// separate crate: a composer only one of the two can reach is a composer the other re-writes.
#[must_use]
pub fn unknown_label_error(kind: &str, namespace: &str, label: &str, registered: &[&str]) -> Error {
    Error::Artifact(format!(
        "unknown {kind} label `{label}`: the resolved pins `{namespace}` registry holds [{}] \
         (add yours through a pins overlay, §10.2)",
        registered.join(", ")
    ))
}

/// The **one explicitly named override key** an F7 dev path-override registers under (§10.5,
/// v33 delta 6c) — the third registration shape, on every kind that has one.
///
/// # Why an entry key and not a reserved label
///
/// §10.5 says only "under one explicitly named override key" and leaves the reading open between an
/// entry key (`{"acme": {"unpinned_path": "…"}}`) and a reserved *label*
/// (`{"unpinned:acme": {"path": "…"}}`). The entry key is the reading the rest of the paragraph
/// forces: it frames a shape as a property of *an entry* ("Three registration shapes exist,
/// exhaustively … Nothing else parses"), and a reserved label would move the shape into the label
/// namespace, where it would collide with a consumer's own label and would have to be re-reserved
/// on every verb that names a label — the reserved-suffix defect class, re-armed for no gain.
///
/// Both kinds spell it from this const, so the two parsers, the two flattener arms and the
/// `bundle` refusal cannot come to disagree about what an unpinned entry looks like.
pub const UNPINNED_PATH_KEY: &str = "unpinned_path";

/// Rejects a registration digest that is not `sha256:` followed by 64 **lowercase** hex digits —
/// the **one** registration-is-a-digest format law (F7, §10.5), shared by every kind that has one.
///
/// It was written twice before it was written once: `handlers` carried its own
/// `reject_unpinned_digest` and `rootfs` an inline copy with a different message, so the two kinds
/// already disagreed about what an operator is told about the same malformed value. F7 *is* this
/// rule, which makes a second copy of it the delta's own law drifting.
///
/// # Why lowercase, and why that is a tightening rather than a nicety
///
/// The looser `is_ascii_hexdigit` form both copies used accepted `sha256:ABCD…`. Nothing else in
/// the tree does: [`super::handler::sha256_hex`] emits lowercase and every verification site
/// (`verify_handler_digest`, `cached_blob_matches`) compares the strings **case-sensitively**. So an
/// uppercase registration parsed clean and could then never verify — the operator got a "digest
/// mismatch" after a network round trip, naming two digests that look identical until you notice the
/// case. That is an accepted-but-unhonorable input, which AGENTS.md's fail-loud rule forbids: it is
/// rejected here, at registration, with the lowercased form to paste.
///
/// # Errors
/// [`Error::Artifact`] naming the namespace, the label, the offending value — and, when only the
/// case is wrong, the exact string that would have been accepted.
pub(crate) fn reject_unpinned_digest(namespace: &str, label: &str, digest: &str) -> Result<()> {
    let hex = digest.strip_prefix("sha256:").unwrap_or_default();
    if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Ok(());
    }
    // The case-only failure gets the fix spelled out: `sha256:ABC…` and `sha256:abc…` name the same
    // bytes to a human and different strings to every comparison site in the tree.
    let remedy = if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!(
            " — this digest is well formed but UPPERCASE, and vmcell writes and compares digests \
             lowercase, so it would be accepted here and then never verify. Register it as \
             `sha256:{}`",
            hex.to_ascii_lowercase()
        )
    } else {
        String::new()
    };
    Err(Error::Artifact(format!(
        "pins `{namespace}.{label}.digest` must be `sha256:<64 lowercase hex>`, got `{digest}`: a \
         registry entry that resolves to a mutable tag means \"whatever is at that location \
         today\", which no consumer's provenance discipline can cite{remedy}"
    )))
}

/// Rejects an entry naming more than one registration shape, naming **every** shape it named
/// (§10.5's "Nothing else parses", F7).
///
/// The **one** shape-exclusivity predicate, shared by the `rootfs` and `handlers` parsers: the two
/// kinds accept different shape keys (`handlers` has `build`; `rootfs` does not) but the law over
/// them is identical, and a second copy of it is how the kind that gained a shape later ends up
/// enforcing a different rule than the kind that had one first.
///
/// Two shapes in one entry is not a preference to resolve — the two could disagree about which
/// bytes the label means, and whichever one loses is a registration the operator wrote and vmcell
/// silently ignored.
///
/// # Errors
/// [`Error::Artifact`] naming the namespace, the label, and every shape key present.
pub(crate) fn reject_multiple_registration_shapes(
    namespace: &str,
    label: &str,
    named: &[&str],
) -> Result<()> {
    if named.len() < 2 {
        return Ok(());
    }
    let shapes = named
        .iter()
        .map(|k| format!("`{k}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    Err(Error::Artifact(format!(
        "pins `{namespace}.{label}` names {} registration shapes — {shapes}: an entry names \
         EXACTLY ONE shape (§10.5, F7 — a digest, a workspace `build`, or the \
         `{UNPINNED_PATH_KEY}` dev override), or the shapes could disagree about which bytes the \
         label means and the loser is a registration vmcell silently ignored",
        named.len()
    )))
}

/// Parses an `unpinned_path` value into the local file the override points at — the **one** F7
/// dev-override parse, shared by both kinds (§10.5).
///
/// This is also the **one** place an unpinned registration is announced: resolution is the moment
/// the operator's durable-looking registration turns out to mean "whatever is at that path today",
/// and a `warn!` here reaches every route into the registry (the CLI, the toolkit entry points, the
/// daemon) without a second announcement site to keep in agreement.
///
/// # Errors
/// [`Error::Artifact`] naming the namespace and label when the value is not a non-empty string.
pub(crate) fn unpinned_path_registration(
    namespace: &str,
    label: &str,
    value: &serde_json::Value,
) -> Result<std::path::PathBuf> {
    let path = value
        .as_str()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            Error::Artifact(format!(
                "pins `{namespace}.{label}.{UNPINNED_PATH_KEY}` must be a non-empty string naming \
                 a local file, got {value}"
            ))
        })
        .map(std::path::PathBuf::from)?;
    tracing::warn!(
        "UNPINNED registration: `{}.{}` resolves through the `{}` dev override at {} — its \
         artifact identity is whatever is at that path today, not a digest any consumer can cite, \
         and `vmcell bundle` refuses it (§10.5, F7)",
        namespace,
        label,
        UNPINNED_PATH_KEY,
        path.display()
    );
    Ok(path)
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
