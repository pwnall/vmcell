//! A tiny pure parser for a resolved kernel `.config` (design §5.6, The downstream kernel toolkit).
//!
//! `make olddefconfig` **silently drops** any symbol whose dependencies are unmet — the classic way
//! a fragment author ships a kernel that quietly lacks the one symbol they added. So every
//! compiling producer copies the post-`olddefconfig` `.config` out beside the kernel as
//! `vmlinux-<label>.config` (§18 delta 3), and a fragment author asserts against **the result**,
//! not against the fragment they submitted:
//!
//! ```
//! use vmcell_artifact_validator::kconfig::{KconfigValues, KconfigValue};
//!
//! // As read from `vmlinux-ikconfig.config`. (Written with `\n` escapes on one line because
//! // rustdoc would treat a doctest line starting with `#` as a hidden line and strip it.)
//! let sidecar = "# Automatically generated file; DO NOT EDIT.\nCONFIG_IKCONFIG=y\n# CONFIG_IKCONFIG_PROC is not set\n";
//! let resolved = KconfigValues::parse(sidecar)?;
//! assert!(resolved.is_enabled("CONFIG_IKCONFIG"));
//! // Present-and-disabled is distinguishable from never-mentioned:
//! assert_eq!(resolved.get("CONFIG_IKCONFIG_PROC"), Some(&KconfigValue::No));
//! assert_eq!(resolved.get("CONFIG_KASAN"), None);
//! # Ok::<(), vmcell_artifact_validator::kconfig::KconfigParseError>(())
//! ```
//!
//! vmcell ships the **mechanism** (this parser); the assertion itself stays downstream (law G1).
//! It is pure `&str` → value, so it needs no KVM, no VM, and no filesystem: the caller reads the
//! sidecar and hands over the text.

use std::collections::BTreeMap;
use std::fmt;

/// One symbol's value in a `.config`.
///
/// Non-exhaustive: this crate is downstream contract surface (§10.4), and kconfig's own type set
/// (bool/tristate/string/int/hex) may need finer distinctions later without breaking consumers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KconfigValue {
    /// `CONFIG_X=y` — built in. The only accepted form for every §5.4 contract symbol.
    Yes,
    /// `CONFIG_X=m` — built as a module. vmcell's guest has no early userspace, so a module is
    /// **not** a satisfied §5.4 clause; [`KconfigValues::is_enabled`] deliberately reports it as
    /// enabled and callers that need built-in match on this variant.
    Module,
    /// `CONFIG_X=n`, or the canonical disabled form `# CONFIG_X is not set`.
    No,
    /// A non-tristate value: a string (unquoted and unescaped) or an int/hex kept verbatim as text.
    Other(String),
}

/// A resolved `.config`, parsed into symbol → value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KconfigValues {
    values: BTreeMap<String, KconfigValue>,
}

/// A `.config` line that is neither blank, nor a comment, nor a `CONFIG_…` assignment.
///
/// Rejecting is deliberate: a silently-empty parse of the wrong file (a gzip blob, a kernel
/// fragment with a typo'd symbol prefix) would make every downstream assertion fail as
/// "symbol absent", which names the wrong cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KconfigParseError {
    /// The 1-based line number that could not be parsed.
    pub line: usize,
    /// The offending line, trimmed.
    pub text: String,
}

impl fmt::Display for KconfigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "kernel .config line {} is not a comment or a CONFIG_<SYMBOL>=<value> assignment: {:?}",
            self.line, self.text
        )
    }
}

impl std::error::Error for KconfigParseError {}

/// The prefix every kconfig symbol carries in a `.config`.
const SYMBOL_PREFIX: &str = "CONFIG_";
/// The canonical disabled form `make olddefconfig` writes.
const NOT_SET_SUFFIX: &str = " is not set";

impl KconfigValues {
    /// Parse the text of a resolved `.config`.
    ///
    /// Accepted line shapes — everything a `make olddefconfig` output or a hand-written fragment
    /// contains: `CONFIG_X=y` / `=m` / `=n`, `CONFIG_X="a string"`, `CONFIG_X=0x1000`,
    /// `# CONFIG_X is not set`, a plain `#` comment, and blank lines. A repeated symbol takes the
    /// **last** value, which is kconfig's own append-a-fragment semantics.
    ///
    /// # Errors
    /// Returns [`KconfigParseError`] naming the line number and text of the first line that is
    /// none of the above — including a bare `CONFIG_X=` with no value.
    pub fn parse(text: &str) -> Result<Self, KconfigParseError> {
        let mut values = BTreeMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(comment) = line.strip_prefix('#') {
                // `# CONFIG_X is not set` is a value, not a comment; anything else really is one.
                let comment = comment.trim();
                if let Some(sym) = comment
                    .strip_suffix(NOT_SET_SUFFIX)
                    .filter(|s| s.starts_with(SYMBOL_PREFIX) && !s.contains(char::is_whitespace))
                {
                    values.insert(sym.to_string(), KconfigValue::No);
                }
                continue;
            }
            let err = || KconfigParseError {
                line: idx + 1,
                text: line.to_string(),
            };
            let (sym, value) = line.split_once('=').ok_or_else(err)?;
            if !sym.starts_with(SYMBOL_PREFIX) || sym.contains(char::is_whitespace) {
                return Err(err());
            }
            values.insert(sym.to_string(), parse_value(value).ok_or_else(err)?);
        }
        Ok(Self { values })
    }

    /// The value of `symbol` (full name, `CONFIG_` prefix included), or `None` when the `.config`
    /// never mentions it — which is what an `olddefconfig` drop of an unmet-dependency symbol looks
    /// like, and is deliberately distinct from [`KconfigValue::No`].
    #[must_use]
    pub fn get(&self, symbol: &str) -> Option<&KconfigValue> {
        self.values.get(symbol)
    }

    /// True when `symbol` is `=y` or `=m`. An absent, `=n`, or non-tristate symbol is false.
    #[must_use]
    pub fn is_enabled(&self, symbol: &str) -> bool {
        matches!(
            self.values.get(symbol),
            Some(KconfigValue::Yes | KconfigValue::Module)
        )
    }

    /// True when `symbol` is `=y` — the only form that satisfies a §5.4 contract clause (the guest
    /// has no early userspace, so a module is never loaded).
    #[must_use]
    pub fn is_builtin(&self, symbol: &str) -> bool {
        matches!(self.values.get(symbol), Some(KconfigValue::Yes))
    }

    /// Every parsed symbol and value, in sorted symbol order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &KconfigValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// How many symbols the `.config` defined.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True when the `.config` defined no symbols at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// The right-hand side of a `CONFIG_X=…` line. `None` rejects the line.
fn parse_value(raw: &str) -> Option<KconfigValue> {
    let raw = raw.trim();
    match raw {
        "" => None,
        "y" => Some(KconfigValue::Yes),
        "m" => Some(KconfigValue::Module),
        "n" => Some(KconfigValue::No),
        _ => Some(KconfigValue::Other(unquote(raw))),
    }
}

/// Unquote a kconfig string value, honoring the `\"` / `\\` escapes `scripts/kconfig` writes.
/// A non-quoted value (an int, a hex constant) is returned verbatim.
fn unquote(raw: &str) -> String {
    let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return raw.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    if escaped {
        out.push('\\');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic `make olddefconfig` excerpt: generated header, section comments, every value
    /// shape, and the §5.4 symbols the classifier cross-checks.
    const RESOLVED: &str = "\
#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 6.12.94 Kernel Configuration
#
CONFIG_CC_VERSION_TEXT=\"gcc (Debian 12.2.0-14) 12.2.0\"
CONFIG_GCC_VERSION=120200
CONFIG_PVH=y
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y

#
# File systems
#
CONFIG_EROFS_FS=y
# CONFIG_EROFS_FS_ZIP is not set
CONFIG_OVERLAY_FS=y
CONFIG_TMPFS=y
CONFIG_XFS_FS=m
CONFIG_LOCALVERSION=\"\"
CONFIG_PHYSICAL_START=0x1000000
";

    // Every value shape maps to the right variant. Guards a parser that treats `=m` as `=y`, or
    // that stores quotes as part of a string value.
    #[test]
    fn parse_maps_every_value_shape() {
        let c = KconfigValues::parse(RESOLVED).expect("realistic .config parses");
        assert_eq!(c.get("CONFIG_PVH"), Some(&KconfigValue::Yes));
        assert_eq!(c.get("CONFIG_XFS_FS"), Some(&KconfigValue::Module));
        assert_eq!(c.get("CONFIG_EROFS_FS_ZIP"), Some(&KconfigValue::No));
        assert_eq!(
            c.get("CONFIG_CC_VERSION_TEXT"),
            Some(&KconfigValue::Other("gcc (Debian 12.2.0-14) 12.2.0".into()))
        );
        assert_eq!(
            c.get("CONFIG_GCC_VERSION"),
            Some(&KconfigValue::Other("120200".into()))
        );
        assert_eq!(
            c.get("CONFIG_PHYSICAL_START"),
            Some(&KconfigValue::Other("0x1000000".into()))
        );
        assert_eq!(
            c.get("CONFIG_LOCALVERSION"),
            Some(&KconfigValue::Other(String::new()))
        );
    }

    // The whole point of the sidecar: `olddefconfig` dropping a symbol (absent) is distinguishable
    // from the author disabling it (`is not set`). Guards a parser that skips `#` lines wholesale.
    #[test]
    fn parse_distinguishes_dropped_from_disabled() {
        let c = KconfigValues::parse(RESOLVED).expect("parse");
        assert_eq!(c.get("CONFIG_EROFS_FS_ZIP"), Some(&KconfigValue::No));
        assert_eq!(c.get("CONFIG_IKCONFIG"), None, "never mentioned");
        assert!(!c.is_enabled("CONFIG_EROFS_FS_ZIP"));
        assert!(!c.is_enabled("CONFIG_IKCONFIG"));
    }

    // A plain comment is a comment; a `# CONFIG_X is not set` shape is a value. Guards a parser
    // that mistakes the generated header for a symbol.
    #[test]
    fn parse_ignores_real_comments() {
        let c = KconfigValues::parse(RESOLVED).expect("parse");
        assert!(c.iter().all(|(sym, _)| sym.starts_with("CONFIG_")));
        assert_eq!(c.len(), 12, "12 symbols in the fixture, no comment leakage");
        assert!(KconfigValues::parse("").expect("empty parses").is_empty());
    }

    // `is_enabled` accepts y and m; `is_builtin` accepts only y, because §5.4 requires built-in.
    // Guards collapsing the two predicates into one.
    #[test]
    fn enabled_and_builtin_differ_on_modules() {
        let c = KconfigValues::parse(RESOLVED).expect("parse");
        assert!(c.is_enabled("CONFIG_XFS_FS"));
        assert!(!c.is_builtin("CONFIG_XFS_FS"));
        assert!(c.is_enabled("CONFIG_PVH") && c.is_builtin("CONFIG_PVH"));
        assert!(!c.is_enabled("CONFIG_KASAN") && !c.is_builtin("CONFIG_KASAN"));
        // A string-valued symbol is not "enabled".
        assert!(!c.is_enabled("CONFIG_LOCALVERSION"));
    }

    // Garbage in a .config is rejected loudly, naming the line — never silently skipped (a wrong
    // file would otherwise parse as an empty config and blame every assertion on "symbol absent").
    #[test]
    fn parse_rejects_malformed_lines() {
        let err = KconfigValues::parse("CONFIG_PVH=y\nthis is not a config line\n")
            .expect_err("garbage must be rejected");
        assert_eq!(err.line, 2);
        assert!(err.to_string().contains("this is not a config line"));

        // A symbol without the CONFIG_ prefix: the wrong-file signal.
        assert_eq!(
            KconfigValues::parse("PVH=y\n")
                .expect_err("prefix required")
                .line,
            1
        );
        // A bare assignment with no value.
        assert_eq!(
            KconfigValues::parse("CONFIG_PVH=\n")
                .expect_err("empty value")
                .line,
            1
        );
    }

    // Kconfig's own append-a-fragment semantics: the last definition wins. Guards a parser that
    // keeps the first (which would report the pre-fragment value of an overridden symbol).
    #[test]
    fn parse_last_definition_wins() {
        let c = KconfigValues::parse("# CONFIG_IKCONFIG is not set\nCONFIG_IKCONFIG=y\n")
            .expect("parse");
        assert_eq!(c.get("CONFIG_IKCONFIG"), Some(&KconfigValue::Yes));
        assert_eq!(c.len(), 1);
    }

    // Escapes inside a quoted string survive. Guards a naive `trim_matches('"')`.
    #[test]
    fn parse_unquotes_string_escapes() {
        let c =
            KconfigValues::parse("CONFIG_CMDLINE=\"quiet \\\"x\\\" c:\\\\path\"\n").expect("parse");
        assert_eq!(
            c.get("CONFIG_CMDLINE"),
            Some(&KconfigValue::Other("quiet \"x\" c:\\path".into()))
        );
    }
}
