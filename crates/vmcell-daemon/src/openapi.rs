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
            "description": "The vmcell daemon HTTP REST API (design §D).",
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
