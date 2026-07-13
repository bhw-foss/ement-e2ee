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
    /// Interactive (emoji/SAS) device verification.
    Verify {
        #[command(subcommand)]
        action: VerifyAction,
    },
}

#[derive(clap::Args)]
pub struct VerifyCommon {
    /// Act on this user's session (needed only with multiple accounts).
    #[arg(long)]
    user_id: Option<String>,
    /// The other user of the verification (defaults to your own user, i.e.
    /// verifying one of your own devices).
    #[arg(long)]
    with_user: Option<String>,
}

#[derive(Subcommand)]
pub enum VerifyAction {
    /// List verification flows.
    List {
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Request verification of one of your own devices (e.g. Element).
    Start {
        /// The device ID to verify with (see Element: Settings > Sessions).
        device: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Show a flow's state, including the emoji once SAS is running.
    Show {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Accept an incoming verification request.
    Accept {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Transition an accepted flow into emoji (SAS) verification.
    StartSas {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Accept a SAS the other side started.
    SasAccept {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Confirm that the emoji match.
    Confirm {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Cancel a flow.
    Cancel {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
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
        CtlCommand::Verify { action } => run_verify(&client, action).await?,
    }
    Ok(())
}

fn common_body(common: &VerifyCommon) -> serde_json::Value {
    let mut body = serde_json::json!({});
    if let Some(user_id) = &common.user_id {
        body["user_id"] = user_id.clone().into();
    }
    if let Some(with_user) = &common.with_user {
        body["with_user"] = with_user.clone().into();
    }
    body
}

fn common_query(common: &VerifyCommon) -> String {
    let mut parts = Vec::new();
    if let Some(user_id) = &common.user_id {
        parts.push(format!("user_id={user_id}"));
    }
    if let Some(with_user) = &common.with_user {
        parts.push(format!("with_user={with_user}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

fn print_flow(value: &serde_json::Value) {
    // Emoji first and prominently, if present.
    if let Some(formatted) = value.pointer("/sas/emoji/formatted").and_then(|v| v.as_str()) {
        println!("\nCompare these emoji with the other device:\n");
        println!("{formatted}\n");
    }
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

async fn run_verify(client: &Client, action: VerifyAction) -> anyhow::Result<()> {
    match action {
        VerifyAction::List { common } => {
            let resp = client.get(&format!("verify{}", common_query(&common))).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        VerifyAction::Start { device, common } => {
            let mut body = common_body(&common);
            body["device_id"] = device.into();
            let resp = client.post("verify/start", &body).await?;
            print_flow(&resp);
            println!("\nNow accept the request on the other device, then run:");
            if let Some(flow) = resp.get("flow_id").and_then(|v| v.as_str()) {
                println!("  ement-e2ee ctl verify show {flow}");
            }
        }
        VerifyAction::Show { flow, common } => {
            let resp = client
                .get(&format!("verify/{flow}{}", common_query(&common)))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::Accept { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/accept"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::StartSas { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/start-sas"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::SasAccept { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/sas-accept"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::Confirm { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/confirm"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::Cancel { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/cancel"), &common_body(&common))
                .await?;
            print_flow(&resp);
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
