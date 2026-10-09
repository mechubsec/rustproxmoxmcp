//! Per-cluster hardened HTTP client.
//!
//! Isolation between clusters is structural rather than scheduled: each cluster
//! gets its own [`HttpClient`], so `max_concurrent_requests` and
//! `max_queued_requests` bound that cluster alone. A wedged endpoint returns
//! `QueueFull` immediately instead of consuming a pool shared with healthy ones.
//!
//! Requests are built with [`HttpRequest::from_absolute_url`], not
//! [`HttpRequest::with_base_and_path`], because `get_json`/`delete_json` need
//! a query string and `with_base_and_path` has no way to attach one -- it
//! only sets the path. The URL handed to `from_absolute_url` is still
//! assembled from a [`mecmcp_openapi::ExpandedPath`] (path segments are
//! injection-checked the same as before) plus the operator-configured
//! cluster endpoint and locally percent-encoded query pairs; nothing
//! device- or model-supplied reaches this constructor unvalidated.

use crate::error::ProxmoxError;
use crate::inventory::Cluster;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_secret::OutboundSecret;
use std::time::Duration;

/// Requests in flight to one cluster.
const MAX_CONCURRENT: usize = 8;
/// Callers permitted to wait behind those.
const MAX_QUEUED: usize = 32;
/// Whole-request deadline, covering permit acquisition and send.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body accepted, enforced as it streams.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A client bound to one cluster.
///
/// Each cluster gets its own HTTP client with isolated rate limits, so a
/// slow or wedged cluster cannot exhaust the request pool shared with
/// healthy ones.
pub struct ProxmoxClient {
    cluster: Cluster,
    http: HttpClient,
    authorization: OutboundSecret,
}

impl ProxmoxClient {
    /// Build a client for one cluster, loading its credential.
    ///
    /// # Errors
    ///
    /// Returns [`ProxmoxError`] when:
    /// - The credential cannot be loaded from env or file
    /// - The CA PEM is unreadable
    /// - The endpoint is not HTTPS
    /// - The HTTP client fails to initialize
    pub fn new(cluster: Cluster) -> Result<Self, ProxmoxError> {
        // Reject plaintext endpoints early, before any HTTP client setup.
        if !cluster.endpoint.starts_with("https://") {
            return Err(ProxmoxError::Config(format!(
                "endpoint must use https, got: {}",
                cluster.endpoint
            )));
        }

        let secret = cluster.load_secret()?;
        let authorization = OutboundSecret::new_unchecked(cluster.authorization_value(&secret));

        let mut extra_root_certificates = Vec::new();
        if let Some(path) = &cluster.ca_pem_path {
            // Public trust material. Operators ship this bundle at 0644.
            // `read_hardened_file` rejects every group and other bit, so this
            // stays a plain read and the startup credential pass omits the path.
            let pem = std::fs::read_to_string(path).map_err(|error| {
                ProxmoxError::Config(format!("ca_pem_path {}: {error}", path.display()))
            })?;
            extra_root_certificates.push(pem);
        }

        let config = HttpClientConfig {
            request_timeout: REQUEST_TIMEOUT,
            max_concurrent_requests: MAX_CONCURRENT,
            max_queued_requests: MAX_QUEUED,
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: concat!("rust-proxmoxmcp/", env!("CARGO_PKG_VERSION")).to_owned(),
            extra_root_certificates,
            ..HttpClientConfig::default()
        };

        let http = HttpClient::new(config)?;
        Ok(Self {
            cluster,
            http,
            authorization,
        })
    }

    /// Issue a GET against a path template and return the unwrapped `data`.
    ///
    /// The template is expanded by `mecmcp-openapi`, which rejects a parameter
    /// that would span a segment, start a query, navigate the hierarchy,
    /// collapse a segment, or carry a control byte. Nothing is sanitised: a
    /// rewritten value is a value the caller did not send.
    ///
    /// Query parameters are percent-encoded and appended to the expanded path.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ProxmoxError::Malformed`] for a rejected parameter, a response
    ///   without a `data` member, or invalid JSON
    /// - [`ProxmoxError::Unauthorized`] for 401 or 403 status
    /// - [`ProxmoxError::Api`] for any other error status
    /// - [`ProxmoxError::Http`] for network or protocol errors
    pub async fn get_json(
        &self,
        path_template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, ProxmoxError> {
        let expanded = mecmcp_openapi::expand_path(path_template, params)
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

        let mut url = format!("{}{expanded}", self.cluster.endpoint.trim_end_matches('/'));

        // Append query parameters if present.
        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let request = HttpRequest::from_absolute_url(Method::Get, &url)?
            .header("Accept", "application/json")?
            .secret_header("Authorization", &self.authorization)?;

        let response = self.http.send(request).await?;
        if response.status() >= 400 {
            return Err(ProxmoxError::from_response(
                response.status(),
                response.body(),
            ));
        }

        let parsed: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;
        parsed
            .get("data")
            .cloned()
            .ok_or_else(|| ProxmoxError::Malformed("response has no 'data' member".into()))
    }

    /// Issue a DELETE against a path template and return the unwrapped `data`.
    ///
    /// The template is expanded by `mecmcp-openapi`, which rejects a parameter
    /// that would span a segment, start a query, navigate the hierarchy,
    /// collapse a segment, or carry a control byte. Nothing is sanitised: a
    /// rewritten value is a value the caller did not send.
    ///
    /// Query parameters are percent-encoded and appended to the expanded path.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ProxmoxError::Malformed`] for a rejected parameter, a response
    ///   without a `data` member, or invalid JSON
    /// - [`ProxmoxError::Unauthorized`] for 401 or 403 status
    /// - [`ProxmoxError::Api`] for any other error status
    /// - [`ProxmoxError::Http`] for network or protocol errors
    pub async fn delete_json(
        &self,
        path_template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, ProxmoxError> {
        let expanded = mecmcp_openapi::expand_path(path_template, params)
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

        let mut url = format!("{}{expanded}", self.cluster.endpoint.trim_end_matches('/'));

        // Append query parameters if present.
        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let request = HttpRequest::from_absolute_url(Method::Delete, &url)?
            .header("Accept", "application/json")?
            .secret_header("Authorization", &self.authorization)?;

        let response = self.http.send(request).await?;
        if response.status() >= 400 {
            return Err(ProxmoxError::from_response(
                response.status(),
                response.body(),
            ));
        }

        let parsed: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;
        parsed
            .get("data")
            .cloned()
            .ok_or_else(|| ProxmoxError::Malformed("response has no 'data' member".into()))
    }

    /// Issue a POST against a path template and return the unwrapped `data`.
    ///
    /// Proxmox takes mutating parameters as an
    /// `application/x-www-form-urlencoded` body, not JSON, so `form` is encoded
    /// that way. The template is expanded by `mecmcp-openapi` under the same
    /// rules as [`Self::get_json`]: nothing is sanitised, because a rewritten
    /// value is a value the caller did not send.
    ///
    /// Most mutating endpoints answer `{"data": "UPID:..."}` — the operation is
    /// asynchronous and the UPID is the handle to it. A few answer
    /// `{"data": null}`, so a null `data` member is returned as
    /// [`serde_json::Value::Null`] rather than treated as an error; only a
    /// *missing* member is malformed.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ProxmoxError::Malformed`] for a rejected parameter, a response
    ///   without a `data` member, or invalid JSON
    /// - [`ProxmoxError::Unauthorized`] for 401 or 403 status
    /// - [`ProxmoxError::Api`] for any other error status
    /// - [`ProxmoxError::Http`] for network or protocol errors
    pub async fn post_form(
        &self,
        path_template: &str,
        params: &[(&str, &str)],
        form: &[(&str, &str)],
    ) -> Result<serde_json::Value, ProxmoxError> {
        let expanded = mecmcp_openapi::expand_path(path_template, params)
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

        let url = format!("{}{expanded}", self.cluster.endpoint.trim_end_matches('/'));

        let body = form
            .iter()
            .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&");

        let request = HttpRequest::from_absolute_url(Method::Post, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/x-www-form-urlencoded")?
            .secret_header("Authorization", &self.authorization)?
            .body(body.into_bytes());

        let response = self.http.send(request).await?;
        if response.status() >= 400 {
            return Err(ProxmoxError::from_response(
                response.status(),
                response.body(),
            ));
        }

        let parsed: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;
        parsed
            .get("data")
            .cloned()
            .ok_or_else(|| ProxmoxError::Malformed("response has no 'data' member".into()))
    }

    /// Send a form-encoded `PUT` and return the `data` member.
    ///
    /// Proxmox updates an existing object with `PUT`; `POST` on the same path
    /// creates one. The two are not interchangeable, so a config update cannot
    /// reuse [`Self::post_form`].
    ///
    /// # Errors
    ///
    /// As [`Self::post_form`].
    pub async fn put_form(
        &self,
        path_template: &str,
        params: &[(&str, &str)],
        form: &[(&str, &str)],
    ) -> Result<serde_json::Value, ProxmoxError> {
        let expanded = mecmcp_openapi::expand_path(path_template, params)
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

        let url = format!("{}{expanded}", self.cluster.endpoint.trim_end_matches('/'));

        let body = form
            .iter()
            .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&");

        let request = HttpRequest::from_absolute_url(Method::Put, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/x-www-form-urlencoded")?
            .secret_header("Authorization", &self.authorization)?
            .body(body.into_bytes());

        let response = self.http.send(request).await?;
        if response.status() >= 400 {
            return Err(ProxmoxError::from_response(
                response.status(),
                response.body(),
            ));
        }

        let parsed: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;
        parsed
            .get("data")
            .cloned()
            .ok_or_else(|| ProxmoxError::Malformed("response has no 'data' member".into()))
    }

    /// The cluster this client is bound to.
    #[must_use]
    pub fn cluster(&self) -> &Cluster {
        &self.cluster
    }
}

/// Percent-encode a string for use in a URL query parameter or path segment.
///
/// Encodes all characters except unreserved ones (alphanumeric, `-`, `.`, `_`, `~`).
pub(crate) fn percent_encode(s: &str) -> String {
    s.as_bytes()
        .iter()
        .map(|&byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Cluster;
    use std::path::PathBuf;

    #[test]
    fn missing_ca_pem_reports_config_error_not_malformed_response() {
        // Write a minimal token file so the secret loads but CA PEM does not.
        use std::io::Write;
        let mut token_file = tempfile::NamedTempFile::new().expect("temp file");
        token_file.write_all(b"test-secret-value").expect("write");
        std::fs::set_permissions(
            token_file.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("chmod");

        let cluster = Cluster {
            endpoint: "https://pve3.example.org:8006".to_owned(),
            token_id: "root@pam!mcp".to_owned(),
            token_secret_env: None,
            token_secret_file: Some(token_file.path().to_path_buf()),
            ca_pem_path: Some(PathBuf::from("/nonexistent/ca.pem")),
            protected_vmids: Vec::new(),
            protected_tags: vec!["protected".to_owned()],
        };
        let result = ProxmoxClient::new(cluster);
        let rendered = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("should fail to load missing CA PEM"),
        };
        assert!(
            !rendered.contains("malformed"),
            "error should not mention 'malformed', got: {rendered}"
        );
        assert!(
            rendered.contains("configuration error") || rendered.contains("config"),
            "error should mention configuration, got: {rendered}"
        );
        assert!(
            rendered.contains("/nonexistent/ca.pem"),
            "error should mention the file path, got: {rendered}"
        );
    }
}
