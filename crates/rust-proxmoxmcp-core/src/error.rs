//! Typed Proxmox VE API errors.
//!
//! Proxmox answers a failure with an HTTP status and, usually, a JSON body
//! carrying an `errors` map. Both halves are peer-controlled, so neither is
//! passed through verbatim: the text is bounded and stripped of control
//! characters before it can reach a log or an MCP error message.

use mecmcp_http::HttpError;

/// Longest error detail retained from a peer-supplied body.
const MAX_DETAIL_BYTES: usize = 512;

/// A failure talking to a Proxmox VE cluster.
#[derive(Debug, thiserror::Error)]
pub enum ProxmoxError {
    /// The outbound HTTP layer refused or failed the request.
    #[error("http: {0}")]
    Http(#[from] HttpError),
    /// The cluster answered with an error status.
    #[error("proxmox api error (status {status}): {message}")]
    Api {
        /// HTTP status returned by the cluster.
        status: u16,
        /// Bounded, control-stripped detail.
        message: String,
    },
    /// The cluster rejected our credentials (401 or 403 from a response).
    ///
    /// Distinct from [`ProxmoxError::Denied`], which is us rejecting the
    /// *caller's* token. This is the cluster rejecting *ours*.
    ///
    /// Carries no body: a 401 body has been observed to echo the presented
    /// credential back, and this error is rendered into logs and MCP results.
    #[error("proxmox api rejected the configured credentials")]
    Unauthorized,
    /// The caller's token does not permit this.
    ///
    /// Distinct from [`ProxmoxError::Unauthorized`], which is the *cluster*
    /// rejecting *our* credentials. This is us rejecting the caller's.
    #[error("denied: {0}")]
    Denied(String),
    /// The cluster has no such object.
    #[error("not found: {what}")]
    NotFound {
        /// What was looked up, in the server's own vocabulary.
        what: String,
    },
    /// A response did not have the shape the API documents.
    #[error("malformed proxmox response: {0}")]
    Malformed(String),
    /// A local configuration or credential problem, before any request is made.
    ///
    /// Distinct from [`ProxmoxError::Malformed`], which describes a response that
    /// arrived in the wrong shape. Nothing has been sent when this is returned.
    #[error("configuration error: {0}")]
    Config(String),
    /// The request named a cluster absent from the inventory.
    #[error("unknown cluster: {0}")]
    UnknownCluster(String),
}

impl ProxmoxError {
    /// The unified [`ProxmoxError::Denied`] text for an absent guest and an
    /// out-of-scope guest.
    ///
    /// Every call site that resolves a guest before authorizing it must use
    /// this one text for both cases, or a narrowed token can loop a vmid over
    /// the id space and use the distinct wording as an existence oracle for
    /// the whole cluster's inventory -- learning the shape of guests it was
    /// never granted. The real reason still reaches `tracing::debug` so an
    /// operator can tell the two apart.
    #[must_use]
    pub fn guest_out_of_scope(cluster: &str) -> Self {
        Self::Denied(format!(
            "guest is outside this caller's scope in cluster {cluster} (an unknown vmid gets \
             the same answer)"
        ))
    }

    /// Classify a non-success response.
    ///
    /// Both 401 and 403 mean the cluster rejected the credentials this server
    /// presented, so they are reduced to [`ProxmoxError::Unauthorized`] with
    /// the body discarded (a 401 body has been observed to echo the presented
    /// credential back). This is distinct from [`ProxmoxError::Denied`], which
    /// is this server refusing the caller's token — that variant never comes
    /// from a response.
    #[must_use]
    pub fn from_response(status: u16, body: &[u8]) -> Self {
        if status == 401 || status == 403 {
            return Self::Unauthorized;
        }
        Self::Api {
            status,
            message: extract_detail(body),
        }
    }
}

/// Render a peer-supplied body into bounded, inert detail.
///
/// Runs the parsed error body through `mecmcp_redact::redact_json_value`
/// before formatting, then runs the formatted result through `redact_text`
/// as a backstop. This detail is both the text an MCP caller sees and the
/// text logged, so it has to be safe for both.
fn extract_detail(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|mut value| {
            let errors = value.get_mut("errors")?;
            mecmcp_redact::redact_json_value(errors);
            let errors = errors.as_object()?;
            let mut parts: Vec<String> = errors
                .iter()
                .map(|(field, reason)| match reason.as_str() {
                    Some(reason) => format!("{field}: {reason}"),
                    None => format!("{field}: {reason}"),
                })
                .collect();
            parts.sort();
            Some(parts.join("; "))
        })
        .unwrap_or_else(|| text.into_owned());

    sanitise(&mecmcp_redact::redact_text(&detail))
}

/// Truncate on a character boundary and drop control characters.
fn sanitise(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .collect();
    let mut end = MAX_DETAIL_BYTES.min(cleaned.len());
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_proxmox_error_map_to_api_variant() {
        let body = br#"{"data":null,"errors":{"vmid":"invalid format"}}"#;
        let error = ProxmoxError::from_response(400, body);
        match error {
            ProxmoxError::Api { status, message } => {
                assert_eq!(status, 400);
                assert!(message.contains("vmid"), "message was {message}");
                assert!(message.contains("invalid format"), "message was {message}");
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn maps_401_to_unauthorized_without_echoing_body() {
        let error = ProxmoxError::from_response(401, b"authentication failure: token 'secret'");
        assert!(matches!(error, ProxmoxError::Unauthorized));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn redacts_secrets_in_the_errors_map_before_rendering() {
        let body = br#"{"data":null,"errors":{
            "password":"FAKE-cluster-password-7d6c5b4a",
            "detail":"backup admin password: FAKE-free-text-9f8e7d6c"
        }}"#;
        let error = ProxmoxError::from_response(400, body);
        let rendered = error.to_string();
        assert!(
            !rendered.contains("FAKE-cluster-password-7d6c5b4a"),
            "denylisted-key secret survived: {rendered}"
        );
        assert!(
            !rendered.contains("FAKE-free-text-9f8e7d6c"),
            "shape-matched secret in free text survived: {rendered}"
        );
        assert!(rendered.contains("detail"), "field name should survive");
    }

    #[test]
    fn bounds_and_sanitises_unstructured_error_text() {
        let body = format!("x\u{0007}{}", "y".repeat(4096));
        let error = ProxmoxError::from_response(500, body.as_bytes());
        let rendered = error.to_string();
        assert!(rendered.len() <= 640, "rendered {} bytes", rendered.len());
        assert!(!rendered.contains('\u{0007}'), "control byte survived");
    }
}
