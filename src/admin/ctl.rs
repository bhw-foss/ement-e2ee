use anyhow::Context;
use clap::Subcommand;

use crate::CtlArgs;

#[derive(Subcommand)]
pub enum CtlCommand {
    /// Show proxy status: sessions, cross-signing, backup.
    Status,
    /// Join the existing encrypted identity: decrypt cross-signing + backup
    /// secrets with your recovery key, self-sign this device, and restore
    /// room keys from the server-side backup.
    Bootstrap {
        /// Act on this user's session (needed only with multiple accounts).
        #[arg(long)]
        user_id: Option<String>,
        /// Read the recovery key from a file instead of prompting.
        #[arg(long)]
        recovery_key_file: Option<std::path::PathBuf>,
    },
}

pub async fn run(args: CtlArgs) -> anyhow::Result<()> {
    let client = Client::new(&args.proxy);
    match args.command {
        CtlCommand::Status => {
            let resp = client.get("status").await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        CtlCommand::Bootstrap {
            user_id,
            recovery_key_file,
        } => {
            let recovery_key = match recovery_key_file {
                Some(path) => std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?
                    .trim()
                    .to_owned(),
                None => rpassword::prompt_password("Recovery key (or passphrase): ")
                    .context("failed to read recovery key")?,
            };
            let mut body = serde_json::json!({ "recovery_key": recovery_key });
            if let Some(user_id) = user_id {
                body["user_id"] = user_id.into();
            }
            let resp = client.post("bootstrap", &body).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

/// Minimal HTTP client for the admin API.
pub struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(proxy: &str) -> Self {
        Self {
            base: format!("{}/_ement", proxy.trim_end_matches('/')),
            http: reqwest::Client::new(),
        }
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .http
            .get(format!("{}/{path}", self.base))
            .send()
            .await
            .context("could not reach proxy (is `ement-e2ee serve` running?)")?;
        Self::to_json(resp).await
    }

    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}/{path}", self.base))
            .json(body)
            .send()
            .await
            .context("could not reach proxy (is `ement-e2ee serve` running?)")?;
        Self::to_json(resp).await
    }

    async fn to_json(resp: reqwest::Response) -> anyhow::Result<serde_json::Value> {
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            let message = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("{status}: {message}");
        }
        Ok(body)
    }
}
