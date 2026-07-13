use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

use crate::ServeArgs;

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<SocketAddr>,
    homeserver: Option<String>,
    store_dir: Option<PathBuf>,
    log_level: Option<String>,
    store_passphrase: Option<String>,
    admin_token: Option<String>,
}

#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub homeserver: reqwest::Url,
    pub store_dir: PathBuf,
    pub log_level: String,
    pub store_passphrase: Option<String>,
    pub admin_token: Option<String>,
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("ement-e2ee/config.toml"))
}

impl Config {
    pub fn load(args: &ServeArgs) -> anyhow::Result<Self> {
        let path = args.config.clone().or_else(default_config_path);
        let file: FileConfig = match &path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("failed to read {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("invalid config {}", p.display()))?
            }
            Some(p) if args.config.is_some() => {
                anyhow::bail!("config file {} does not exist", p.display())
            }
            _ => FileConfig::default(),
        };

        let homeserver = args
            .homeserver
            .clone()
            .or(file.homeserver)
            .context("no homeserver configured (set `homeserver` in config.toml or pass --homeserver)")?;
        let mut homeserver: reqwest::Url = homeserver
            .parse()
            .context("homeserver is not a valid URL")?;
        // Normalize: no trailing slash, no path.
        if homeserver.path() != "/" && !homeserver.path().is_empty() {
            anyhow::bail!("homeserver URL must not have a path: {homeserver}");
        }
        homeserver.set_path("");

        let store_dir = args
            .store_dir
            .clone()
            .or(file.store_dir)
            .or_else(|| dirs::data_dir().map(|d| d.join("ement-e2ee")))
            .context("could not determine store directory")?;

        Ok(Self {
            listen: args
                .listen
                .or(file.listen)
                .unwrap_or_else(|| "127.0.0.1:8009".parse().unwrap()),
            homeserver,
            store_dir,
            log_level: args
                .log_level
                .clone()
                .or(file.log_level)
                .unwrap_or_else(|| "info".to_owned()),
            store_passphrase: file.store_passphrase,
            admin_token: file.admin_token,
        })
    }
}
