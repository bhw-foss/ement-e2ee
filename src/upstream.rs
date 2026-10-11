use std::time::Duration;

use anyhow::Context;
use reqwest::Url;

/// HTTP client for the real homeserver.
#[derive(Clone)]
pub struct Upstream {
    pub base: Url,
    pub http: reqwest::Client,
}

impl Upstream {
    pub fn new(base: Url) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // No overall timeout: /sync long-polls for 30s and media may be large.
            // Individual JSON helpers set their own timeouts.
            .build()
            .context("failed to build upstream HTTP client")?;
        Ok(Self { base, http })
    }

    /// Put a path (with optional query) onto the homeserver base URL.
    pub fn url(&self, path_and_query: &str) -> Url {
        let mut url = self.base.clone();
        // Set the components instead of using Url::join: join resolves a path
        // like "//other.host/x" as a network-path reference and would send
        // the request (and its access token) to other.host.
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        url.set_path(path);
        url.set_query(query);
        url
    }

    /// JSON request with Bearer auth; used for the proxy's own Matrix calls.
    pub async fn json_request(
        &self,
        method: reqwest::Method,
        path_and_query: &str,
        token: &str,
        body: Option<&serde_json::Value>,
    ) -> anyhow::Result<(reqwest::StatusCode, serde_json::Value)> {
        let mut req = self
            .http
            .request(method, self.url(path_and_query))
            .bearer_auth(token)
            .timeout(Duration::from_secs(60));
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.context("upstream request failed")?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("failed to read upstream body")?;
        let value: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).context("upstream returned non-JSON body")?
        };
        Ok((status, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(base: &str) -> Upstream {
        Upstream::new(base.parse().unwrap()).unwrap()
    }

    #[test]
    fn url_joins_path_and_query_onto_base() {
        let up = upstream("https://matrix.example.org");
        assert_eq!(
            up.url("/_matrix/client/v3/sync?since=s1&timeout=30000").as_str(),
            "https://matrix.example.org/_matrix/client/v3/sync?since=s1&timeout=30000"
        );
        // A port and a trailing slash on the base change nothing.
        let up = upstream("http://127.0.0.1:8008/");
        assert_eq!(
            up.url("/_matrix/client/versions").as_str(),
            "http://127.0.0.1:8008/_matrix/client/versions"
        );
    }

    #[test]
    fn url_keeps_percent_encoding_intact() {
        // Room and event IDs arrive percent-encoded and must reach the
        // homeserver exactly as the client sent them.
        let up = upstream("https://matrix.example.org");
        let path = "/_matrix/client/r0/rooms/%21abc%3Aexample.org/event/%24a%2Fb";
        assert_eq!(up.url(path).path(), path);
    }

    #[test]
    fn url_cannot_be_redirected_to_another_host() {
        // The request path is attacker-influenced (any local process can talk
        // to the proxy); it must never change where the token is sent.
        let up = upstream("https://matrix.example.org");
        for path in ["//evil.example/_matrix", "/\\evil.example/x", "/@evil.example/x"] {
            assert_eq!(
                up.url(path).host_str(),
                Some("matrix.example.org"),
                "{path}"
            );
        }
    }
}
