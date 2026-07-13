use anyhow::Context;
use clap::Subcommand;

use crate::CtlArgs;

#[derive(Subcommand)]
pub enum CtlCommand {
    /// Show proxy status: sessions, cross-signing, backup.
    Status,
}

pub async fn run(args: CtlArgs) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    match args.command {
        CtlCommand::Status => {
            let resp: serde_json::Value = client
                .get(format!("{}/_ement/status", args.proxy.trim_end_matches('/')))
                .send()
                .await
                .context("could not reach proxy (is `ement-e2ee serve` running?)")?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}
