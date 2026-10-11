mod admin;
mod config;
mod crypto;
mod error;
mod proxy;
mod session;
mod upstream;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod testutil;

use std::sync::Arc;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[derive(Parser)]
#[command(name = "ement-e2ee", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy (default when no subcommand is given).
    Serve(ServeArgs),
    /// Talk to a running proxy's admin API.
    Ctl(CtlArgs),
}

#[derive(Args, Default, Clone)]
pub struct ServeArgs {
    /// Path to config file (default: ~/.config/ement-e2ee/config.toml)
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Listen address, e.g. 127.0.0.1:8009
    #[arg(long)]
    listen: Option<std::net::SocketAddr>,
    /// Upstream homeserver URL, e.g. https://matrix.example.org
    #[arg(long)]
    homeserver: Option<String>,
    /// Directory for crypto stores (default: ~/.local/share/ement-e2ee)
    #[arg(long)]
    store_dir: Option<std::path::PathBuf>,
    /// Log filter, e.g. info or ement_e2ee=debug
    #[arg(long)]
    log_level: Option<String>,
}

#[derive(Args)]
pub struct CtlArgs {
    /// Base URL of the running proxy.
    #[arg(long, default_value = "http://127.0.0.1:8009")]
    proxy: String,
    #[command(subcommand)]
    command: admin::ctl::CtlCommand,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new().context("failed to start tokio runtime")?;
    match cli.command {
        Some(Command::Ctl(args)) => runtime.block_on(admin::ctl::run(args)),
        Some(Command::Serve(args)) => runtime.block_on(serve(args)),
        None => runtime.block_on(serve(cli.serve)),
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let config = Config::load(&args)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone())),
        )
        .init();

    tracing::info!(listen = %config.listen, homeserver = %config.homeserver, "starting ement-e2ee");

    let state = proxy::AppState::new(Arc::new(config)).await?;
    let listen = state.config.listen;
    let router = proxy::router(state);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once(&"ement-e2ee").chain(args)).unwrap()
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_is_the_default_command() {
        let cli = parse(&["--homeserver", "https://matrix.org", "--log-level", "debug"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.serve.homeserver.as_deref(), Some("https://matrix.org"));
        assert_eq!(cli.serve.log_level.as_deref(), Some("debug"));

        let cli = parse(&["serve", "--listen", "127.0.0.1:9000", "--store-dir", "/tmp/s"]);
        let Some(Command::Serve(args)) = cli.command else {
            panic!("expected serve");
        };
        assert_eq!(args.listen, Some("127.0.0.1:9000".parse().unwrap()));
        assert_eq!(args.store_dir, Some("/tmp/s".into()));
    }

    #[test]
    fn readme_ctl_invocations_parse() {
        for args in [
            &["ctl", "status"][..],
            &["ctl", "bootstrap"],
            &["ctl", "bootstrap", "--recovery-key-file", "key.txt"],
            &["ctl", "bootstrap", "--user-id", "@me:example.org"],
            &["ctl", "verify", "list"],
            &["ctl", "verify", "start", "ELEMENTDEVICEID"],
            &["ctl", "verify", "show", "flow1"],
            &["ctl", "verify", "accept", "flow1"],
            &["ctl", "verify", "start-sas", "flow1"],
            &["ctl", "verify", "sas-accept", "flow1"],
            &["ctl", "verify", "confirm", "flow1", "--with-user", "@you:example.org"],
            &["ctl", "verify", "cancel", "flow1"],
            &["ctl", "keys", "export", "keys.txt"],
            &["ctl", "keys", "import", "keys.txt", "--user-id", "@me:example.org"],
            &["ctl", "--proxy", "http://127.0.0.1:9000", "status"],
        ] {
            let cli = parse(args);
            assert!(matches!(cli.command, Some(Command::Ctl(_))), "{args:?}");
        }
    }

    #[test]
    fn ctl_talks_to_the_default_listen_address() {
        let Some(Command::Ctl(args)) = parse(&["ctl", "status"]).command else {
            panic!("expected ctl");
        };
        assert_eq!(args.proxy, "http://127.0.0.1:8009");
    }

    #[test]
    fn bad_invocations_are_rejected() {
        for args in [
            &["ctl"][..],
            &["ctl", "verify"],
            &["ctl", "verify", "start"],
            &["ctl", "keys", "export"],
            &["serve", "--listen", "not-an-address"],
            &["frobnicate"],
        ] {
            let result = Cli::try_parse_from(std::iter::once(&"ement-e2ee").chain(args));
            assert!(result.is_err(), "{args:?}");
        }
    }
}
