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

    /// Join a path (with optional query) onto the homeserver base URL.
    pub fn url(&self, path_and_query: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path("");
        // path_and_query always starts with '/'; Url::join handles it.
        url.join(path_and_query).unwrap_or_else(|_| {
            let mut u = self.base.clone();
            u.set_path(path_and_query);
            u
        })
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
