//! The served OpenAPI 3.1 document, generated from ONE route table (design §11.5, The HTTP REST API
//! and its OpenAPI document / invariant §13, Cross-cutting invariants).
//!
//! [`API_ROUTES`] is the single source of truth: the axum router ([`crate::server`]) mounts exactly
//! these routes and the OpenAPI document is built from them, so the served spec cannot drift from the
//! implementation. The parity tests here assert the document and the table agree, that every
//! non-open operation carries the bearer security requirement, and that the only unauthenticated
//! routes are `/healthz` and `/openapi.json` — a route that forgot auth is a RED test, not a hope.

use crate::dto::ErrorKind;
use serde_json::{Value, json};

/// One route: an OpenAPI-style path (`{param}`), its HTTP method, operation id, whether it requires
/// the bearer key, and a one-line summary.
#[derive(Debug, Clone, Copy)]
pub struct RouteDef {
    /// Uppercase HTTP method.
    pub method: &'static str,
    /// OpenAPI-style path with `{param}` placeholders.
    pub path: &'static str,
    /// Stable operation id.
    pub op_id: &'static str,
    /// Whether the bearer-auth layer guards this route.
    pub authenticated: bool,
    /// One-line summary for the OpenAPI doc.
    pub summary: &'static str,
}

/// The single source of truth for the API surface (design §11.5, The HTTP REST API and its OpenAPI document).
pub const API_ROUTES: &[RouteDef] = &[
    RouteDef {
        method: "PUT",
        path: "/v1/artifacts/{name}",
        op_id: "createArtifact",
        authenticated: true,
        summary: "Upload an artifact (create; 409 if it exists)",
    },
    RouteDef {
        method: "GET",
        path: "/v1/artifacts",
        op_id: "listArtifacts",
        authenticated: true,
        summary: "List artifacts",
    },
    RouteDef {
        method: "GET",
        path: "/v1/artifacts/{name}",
        op_id: "getArtifact",
        authenticated: true,
        summary: "Get one artifact's metadata",
    },
    RouteDef {
        method: "DELETE",
        path: "/v1/artifacts/{name}",
        op_id: "deleteArtifact",
        authenticated: true,
        summary: "Delete an artifact (409 if pinned by a live VM)",
    },
    RouteDef {
        method: "GET",
        path: "/v1/store",
        op_id: "storeUsage",
        authenticated: true,
        summary: "Report the artifact store's usage against its quota",
    },
    RouteDef {
        method: "POST",
        path: "/v1/vms",
        op_id: "createVm",
        authenticated: true,
        summary: "Create and boot a VM (optionally run a command)",
    },
    RouteDef {
        method: "GET",
        path: "/v1/vms",
        op_id: "listVms",
        authenticated: true,
        summary: "List the VMs the daemon owns",
    },
    RouteDef {
        method: "GET",
        path: "/v1/vms/{id}",
        op_id: "getVm",
        authenticated: true,
        summary: "Get one VM",
    },
    RouteDef {
        method: "POST",
        path: "/v1/vms/{id}/exec",
        op_id: "execVm",
        authenticated: true,
        summary: "Run a command in a VM over vsock",
    },
    RouteDef {
        method: "GET",
        path: "/v1/vms/{id}/stats",
        op_id: "statsVm",
        authenticated: true,
        summary: "Sample a VM's resource usage",
    },
    RouteDef {
        method: "POST",
        path: "/v1/vms/{id}/pause",
        op_id: "pauseVm",
        authenticated: true,
        summary: "Pause a Ready VM's vCPUs (409 if it is not Ready)",
    },
    RouteDef {
        method: "POST",
        path: "/v1/vms/{id}/resume",
        op_id: "resumeVm",
        authenticated: true,
        summary: "Resume a Paused VM's vCPUs (409 if it is not Paused)",
    },
    RouteDef {
        method: "POST",
        path: "/v1/vms/{id}/snapshot",
        op_id: "snapshotVm",
        authenticated: true,
        summary: "Write a warm snapshot into the artifact store",
    },
    RouteDef {
        method: "DELETE",
        path: "/v1/vms/{id}",
        op_id: "destroyVm",
        authenticated: true,
        summary: "Destroy a VM and remove its descriptor",
    },
    RouteDef {
        method: "GET",
        path: "/healthz",
        op_id: "health",
        authenticated: false,
        summary: "Liveness probe",
    },
    RouteDef {
        method: "GET",
        path: "/openapi.json",
        op_id: "openapi",
        authenticated: false,
        summary: "This OpenAPI document",
    },
];

/// The exact set of unauthenticated route paths (design §13, Cross-cutting invariants). Everything else is guarded.
pub const OPEN_ROUTES: &[&str] = &["/healthz", "/openapi.json"];

/// The name of the error-body schema in `components.schemas`. One const, so the definition site and
/// every `$ref` to it cannot drift (§11.5: the error body is documented as an OpenAPI component).
pub const ERROR_SCHEMA_NAME: &str = "ErrorBody";

/// The JSON-Pointer reference to [`ERROR_SCHEMA_NAME`] — built once, never spelled out at a call
/// site.
fn error_schema_ref() -> Value {
    json!({ "$ref": format!("#/components/schemas/{ERROR_SCHEMA_NAME}") })
}

/// The `ErrorBody` schema (design §11.5): the machine-matchable `error` kind plus the human
/// `message`, mirroring [`crate::dto::ErrorBody`].
///
/// The `error` enum is generated from [`ErrorKind::ALL`] — never a second literal list — so a new
/// kind cannot ship undocumented. Before this existed, `components` carried `securitySchemes` only
/// and every operation's `default` response had no `content`, which made P5's "every named schema
/// exists" assertion vacuous and left clients with no machine-readable error contract.
fn error_body_schema() -> Value {
    let kinds: Vec<&str> = ErrorKind::ALL.iter().map(|k| k.as_str()).collect();
    json!({
        "type": "object",
        "description": "The structured error body every non-2xx response carries.",
        "required": ["error", "message"],
        "properties": {
            "error": {
                "type": "string",
                "description": "The machine-matchable error kind; determines the HTTP status.",
                "enum": kinds,
            },
            "message": {
                "type": "string",
                "description": "The human-readable message (never a Debug struct-dump).",
            },
        },
    })
}

/// Builds the OpenAPI 3.1 document from [`API_ROUTES`] — the single generator, so the doc and the
/// router share one table (invariant §13, Cross-cutting invariants).
#[must_use]
pub fn openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
    for r in API_ROUTES {
        // Build the operation object by insertion (not index-assignment) to keep the crate-wide
        // `indexing_slicing` deny satisfied.
        let mut op = serde_json::Map::new();
        op.insert("operationId".into(), json!(r.op_id));
        op.insert("summary".into(), json!(r.summary));
        // The `default` response is the ERROR contract: every non-2xx reply is an `ErrorBody`
        // (`DaemonError`'s single `IntoResponse`), so it `$ref`s the one declared schema rather
        // than being a description-only stub a client cannot generate against.
        op.insert(
            "responses".into(),
            json!({
                "default": {
                    "description": "Error: the structured ErrorBody (kind + human message).",
                    "content": { "application/json": { "schema": error_schema_ref() } },
                }
            }),
        );
        if r.authenticated {
            op.insert("security".into(), json!([{ "bearerAuth": [] }]));
        }
        let entry = paths.entry(r.path.to_string()).or_insert_with(|| json!({}));
        if let Value::Object(map) = entry {
            map.insert(r.method.to_ascii_lowercase(), Value::Object(op));
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "vmcelld control-plane API",
            "description": "The vmcell daemon HTTP REST API (design §11).",
            "version": "1",
        },
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "bearerAuth": { "type": "http", "scheme": "bearer" }
            },
            "schemas": { ERROR_SCHEMA_NAME: error_body_schema() }
        }
    })
}

/// **The design-reference gate** (finding `served-openapi-cites-a-nonexistent-design-section`).
///
/// The daemon *serves* its OpenAPI document to clients, and that document's description pointed at
/// design section `D` — which has never existed. Four sibling citations in this tier dangled the same
/// way (`11.5.3`, `11.3.2`, `12.18`, and a superseded v27 `20.5`/`12.23` pair no reader can resolve
/// against the shipped design), so the instance is a class, and this gate closes the class: every
/// section citation in the daemon tier — code, rustdoc, and plain comments alike — must name a section
/// the newest design document actually declares.
///
/// It reads the design at **run time** rather than `include_str!`-ing a version-pinned file name, so
/// a reissue moves the gate's corpus without an edit here (the same "newest version you find" rule
/// AGENTS.md states for the versioned docs), and it derives the valid set from the document's own
/// headings rather than embedding a section count that would go stale silently.
#[cfg(test)]
mod design_reference_gate {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// The source roots this gate owns: this crate plus the client that re-exports its wire schema.
    /// Scoped to the tier deliberately — every crate carries its own citations, and a gate that
    /// reddened on a sibling crate's text would fire in the wrong place.
    fn tier_roots() -> Vec<PathBuf> {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        vec![
            manifest.join("src"),
            manifest.join("../vmcell-daemon-client/src"),
        ]
    }

    /// Every `.rs` file under `dir`, recursively.
    fn rust_sources(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}"));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(rust_sources(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
        out
    }

    /// The newest design document under `docs/` (`*design-v<N>.md`, highest `N` wins), as
    /// `(path, body)`. Fails loud rather than skipping: a gate that quietly finds no corpus is
    /// theater.
    fn newest_design() -> (PathBuf, String) {
        let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
        let mut best: Option<(u32, PathBuf)> = None;
        let entries = std::fs::read_dir(&docs).unwrap_or_else(|e| panic!("read {docs:?}: {e}"));
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(rest) = name.strip_suffix(".md") else {
                continue;
            };
            let Some((_, version)) = rest.split_once("-design-v") else {
                continue;
            };
            let Ok(version) = version.parse::<u32>() else {
                continue;
            };
            if best.as_ref().is_none_or(|(b, _)| version > *b) {
                best = Some((version, entry.path()));
            }
        }
        let (_, path) = best.unwrap_or_else(|| {
            panic!("no `*-design-v<N>.md` in {docs:?} — the gate has no corpus to check against")
        });
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        (path, body)
    }

    /// The section ids the design declares, from its own headings: `## 11.` → `11`,
    /// `### 11.5 …` → `11.5`. A lettered heading (`### Appendix A — …`) declares no section id and is
    /// skipped, which is exactly why a lettered citation must not resolve.
    fn declared_sections(body: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for line in body.lines() {
            let Some(rest) = line
                .strip_prefix("#### ")
                .or_else(|| line.strip_prefix("### "))
                .or_else(|| line.strip_prefix("## "))
            else {
                continue;
            };
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('.');
            if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit() || c == '.') {
                out.insert(token.to_string());
            }
        }
        out
    }

    /// Every section citation in `text`, as `(line number, id)`.
    ///
    /// A citation is the section sign followed immediately by an **alphanumeric** character, and the
    /// id runs to the first character that cannot be part of one — so `13,` / `18's` / `11.5)` all
    /// yield the id alone, and a lettered id like `D` yields `"D"`, which no numeric heading declares.
    /// The sign followed by a space, a `{`, or punctuation is prose or a format placeholder (this
    /// module's own messages interpolate one), never a citation.
    fn section_refs(text: &str) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            for tail in line.split('\u{a7}').skip(1) {
                if !tail.starts_with(|c: char| c.is_ascii_alphanumeric()) {
                    continue;
                }
                let id: String = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                    .collect();
                out.push((i + 1, id.trim_end_matches('.').to_string()));
            }
        }
        out
    }

    /// Asserts every citation in `text` resolves, naming the file for the operator.
    fn assert_refs_resolve(
        label: &str,
        text: &str,
        design: &Path,
        sections: &BTreeSet<String>,
    ) -> usize {
        let refs = section_refs(text);
        for (line, id) in &refs {
            assert!(
                sections.contains(id),
                "{label}:{line} cites design section {id} — {design:?} declares no such section. \
                 Cite the section that owns the fact; a lettered appendix is cited as \"Appendix X\" \
                 (never as a section number), and a superseded numbering (a v27 one) resolves for no \
                 reader."
            );
        }
        refs.len()
    }

    // The served document — the client-visible half of this finding. RED on the inverse (put the
    // lettered `D` back in the description): the document's citation resolves to nothing.
    #[test]
    fn the_served_document_cites_a_real_design_section() {
        let (design, body) = newest_design();
        let sections = declared_sections(&body);
        let doc = super::openapi_document().to_string();
        let cited = assert_refs_resolve("openapi_document()", &doc, &design, &sections);
        assert!(
            cited > 0,
            "the served document cites no design section at all — this gate would be vacuous"
        );
    }

    // The class: every citation in the daemon tier resolves. RED on the inverse (any of the five
    // dangling citations this finding closed — `12.18` in auth.rs, `11.5.3` in error.rs, `11.3.2` in
    // artifact_store.rs, the v27 pair in bridge/tests.rs, or the served `D` above).
    #[test]
    fn every_design_reference_in_the_daemon_tier_resolves() {
        let (design, body) = newest_design();
        let sections = declared_sections(&body);
        assert!(
            sections.len() > 50,
            "{design:?} yielded only {} section headings — the parser is not reading it, so every \
             assertion below would pass vacuously",
            sections.len()
        );
        let mut files = 0;
        let mut cited = 0;
        for root in tier_roots() {
            for file in rust_sources(&root) {
                let text =
                    std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
                let label = file.file_name().map_or_else(
                    || file.display().to_string(),
                    |n| n.to_string_lossy().to_string(),
                );
                cited += assert_refs_resolve(&label, &text, &design, &sections);
                files += 1;
            }
        }
        assert!(
            files >= 14 && cited > 100,
            "the scan read {files} files and {cited} citations — too few to be reading the tier"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // The document's path set equals the route table's path set (invariant §13, Cross-cutting invariants). RED on the
    // inverse: a route added to the table but not the doc, or vice versa.
    #[test]
    fn document_paths_match_route_table() {
        let doc = openapi_document();
        let doc_paths: BTreeSet<String> = doc["paths"]
            .as_object()
            .expect("paths object")
            .keys()
            .cloned()
            .collect();
        let table_paths: BTreeSet<String> = API_ROUTES.iter().map(|r| r.path.to_string()).collect();
        assert_eq!(
            doc_paths, table_paths,
            "doc paths must equal the route table"
        );
    }

    // Every route's (method, path) appears as an operation in the document.
    #[test]
    fn every_route_is_an_operation() {
        let doc = openapi_document();
        for r in API_ROUTES {
            let op = &doc["paths"][r.path][r.method.to_ascii_lowercase()];
            assert!(!op.is_null(), "{} {} missing from doc", r.method, r.path);
            assert_eq!(op["operationId"], r.op_id, "op id for {}", r.op_id);
        }
    }

    // Every authenticated operation carries the bearer security requirement, and the ONLY open
    // routes are the two named ones (invariant §13, Cross-cutting invariants). RED on a route that forgot auth.
    #[test]
    fn auth_coverage_matches_open_route_set() {
        let doc = openapi_document();
        let open: BTreeSet<&str> = OPEN_ROUTES.iter().copied().collect();
        for r in API_ROUTES {
            let op = &doc["paths"][r.path][r.method.to_ascii_lowercase()];
            let has_security = !op["security"].is_null();
            if r.authenticated {
                assert!(has_security, "{} {} must require auth", r.method, r.path);
                assert!(
                    !open.contains(r.path),
                    "{} must not be in OPEN_ROUTES",
                    r.path
                );
            } else {
                assert!(!has_security, "{} {} must be open", r.method, r.path);
                assert!(open.contains(r.path), "{} must be in OPEN_ROUTES", r.path);
            }
        }
        // Exactly the two documented opt-outs, no more.
        let table_open: BTreeSet<&str> = API_ROUTES
            .iter()
            .filter(|r| !r.authenticated)
            .map(|r| r.path)
            .collect();
        assert_eq!(
            table_open, open,
            "open route set must be exactly {OPEN_ROUTES:?}"
        );
    }

    // The vCPU verbs are on the table BY NAME (design §11.5, The HTTP REST API and its OpenAPI
    // document; §17, Open gaps and future capabilities — "Pause/resume routes"). The parity tests
    // above are relational — they hold just as well for a table that lost both rows — so this is the
    // roster assertion that a shipped route cannot silently leave. RED on the inverse: delete either
    // `RouteDef`.
    #[test]
    fn the_vcpu_verbs_are_documented_authenticated_operations() {
        let doc = openapi_document();
        for (op_id, path) in [
            ("pauseVm", "/v1/vms/{id}/pause"),
            ("resumeVm", "/v1/vms/{id}/resume"),
        ] {
            let row = API_ROUTES
                .iter()
                .find(|r| r.op_id == op_id)
                .unwrap_or_else(|| panic!("{op_id} must be in API_ROUTES"));
            assert_eq!(row.path, path, "{op_id} path");
            assert_eq!(row.method, "POST", "{op_id} is a POST (it changes state)");
            assert!(row.authenticated, "{op_id} must be behind the bearer layer");
            let op = &doc["paths"][path]["post"];
            assert_eq!(op["operationId"], op_id, "{op_id} must be in the document");
            assert!(
                !op["security"].is_null(),
                "{op_id} must carry the bearer requirement in the served document"
            );
        }
    }

    #[test]
    fn document_declares_bearer_security_scheme() {
        let doc = openapi_document();
        assert_eq!(
            doc["components"]["securitySchemes"]["bearerAuth"],
            json!({ "type": "http", "scheme": "bearer" })
        );
    }

    /// Collects every `$ref` string anywhere in the document.
    fn collect_refs(value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    if k == "$ref"
                        && let Some(s) = v.as_str()
                    {
                        out.insert(s.to_string());
                    }
                    collect_refs(v, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| collect_refs(v, out)),
            _ => {}
        }
    }

    // P5's "every named schema exists", made NON-vacuous (deviation d5): the document now names a
    // schema, and every `$ref` in it resolves to a declared one. RED on the inverse: drop the
    // `components.schemas` object (the lookup below fails) or drop the operations' `$ref` (the
    // "must reference at least one schema" assertion fails, which is exactly the vacuous state the
    // gate used to pass in).
    #[test]
    fn every_ref_resolves_to_a_declared_schema() {
        let doc = openapi_document();
        let declared: BTreeSet<String> = doc["components"]["schemas"]
            .as_object()
            .expect("components.schemas must exist")
            .keys()
            .cloned()
            .collect();
        let mut refs = BTreeSet::new();
        collect_refs(&doc, &mut refs);
        assert!(
            !refs.is_empty(),
            "a document with no $ref makes 'every named schema exists' vacuous"
        );
        for r in &refs {
            let name = r
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("unsupported $ref form {r}"));
            assert!(declared.contains(name), "$ref {r} names no declared schema");
        }
    }

    // Every operation carries the machine-readable error contract, so a generated client can decode
    // a failure instead of guessing. RED on the inverse: a `default` response with no `content`.
    #[test]
    fn every_operation_documents_the_error_body() {
        let doc = openapi_document();
        let want = json!(format!("#/components/schemas/{ERROR_SCHEMA_NAME}"));
        for r in API_ROUTES {
            let op = &doc["paths"][r.path][r.method.to_ascii_lowercase()];
            assert_eq!(
                op["responses"]["default"]["content"]["application/json"]["schema"]["$ref"], want,
                "{} {} must document its error body",
                r.method, r.path
            );
        }
    }

    // The schema's `error` enum IS the `ErrorKind` roster — recomputed through the real type, never
    // a literal list in the document. RED on the inverse: a hand-written enum in the schema drifts
    // the moment a kind is added or renamed.
    #[test]
    fn the_error_schema_enumerates_every_error_kind() {
        let doc = openapi_document();
        let listed: Vec<String> =
            doc["components"]["schemas"][ERROR_SCHEMA_NAME]["properties"]["error"]["enum"]
                .as_array()
                .expect("the error enum")
                .iter()
                .map(|v| v.as_str().expect("a string kind").to_string())
                .collect();
        let expected: Vec<String> = ErrorKind::ALL
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        assert_eq!(
            listed, expected,
            "the documented kinds must be ErrorKind::ALL"
        );
        assert!(
            listed.contains(&ErrorKind::NotFound.as_str().to_string()),
            "sanity: the roster is not empty"
        );
    }
}
