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

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a config file and return args pointing at it. Always passing an
    /// explicit --config keeps these tests away from the developer's own
    /// ~/.config/ement-e2ee/config.toml.
    fn args_for(dir: &tempfile::TempDir, text: &str) -> ServeArgs {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        ServeArgs {
            config: Some(path),
            ..Default::default()
        }
    }

    fn load_error(text: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        format!("{:#}", Config::load(&args_for(&dir, text)).unwrap_err())
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(&dir, r#"homeserver = "https://matrix.example.org""#);
        let config = Config::load(&args).unwrap();
        assert_eq!(config.homeserver.as_str(), "https://matrix.example.org/");
        // Loopback only unless the user says otherwise.
        assert_eq!(config.listen, "127.0.0.1:8009".parse().unwrap());
        assert_eq!(config.log_level, "info");
        assert!(config.store_dir.ends_with("ement-e2ee"));
        assert_eq!(config.store_passphrase, None);
        assert_eq!(config.admin_token, None);
    }

    #[test]
    fn full_config_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(
            &dir,
            r#"
            listen = "127.0.0.1:9999"
            homeserver = "https://matrix.example.org/"
            store_dir = "/var/lib/ement"
            log_level = "ement_e2ee=debug"
            store_passphrase = "hunter2"
            admin_token = "s3cret"
            "#,
        );
        let config = Config::load(&args).unwrap();
        assert_eq!(config.listen, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(config.homeserver.as_str(), "https://matrix.example.org/");
        assert_eq!(config.store_dir, PathBuf::from("/var/lib/ement"));
        assert_eq!(config.log_level, "ement_e2ee=debug");
        assert_eq!(config.store_passphrase.as_deref(), Some("hunter2"));
        assert_eq!(config.admin_token.as_deref(), Some("s3cret"));
    }

    #[test]
    fn command_line_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_for(
            &dir,
            r#"
            listen = "127.0.0.1:9999"
            homeserver = "https://file.example.org"
            log_level = "warn"
            "#,
        );
        args.listen = Some("127.0.0.1:1234".parse().unwrap());
        args.homeserver = Some("https://cli.example.org".to_owned());
        args.store_dir = Some(PathBuf::from("/tmp/cli-store"));
        args.log_level = Some("trace".to_owned());
        let config = Config::load(&args).unwrap();
        assert_eq!(config.listen, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(config.homeserver.host_str(), Some("cli.example.org"));
        assert_eq!(config.store_dir, PathBuf::from("/tmp/cli-store"));
        assert_eq!(config.log_level, "trace");
    }

    #[test]
    fn homeserver_is_required_and_validated() {
        assert!(load_error("").contains("no homeserver configured"));
        assert!(load_error(r#"homeserver = "not a url""#).contains("not a valid URL"));
        // A path would be silently dropped when requests are forwarded.
        assert!(
            load_error(r#"homeserver = "https://example.org/matrix""#)
                .contains("must not have a path")
        );
    }

    #[test]
    fn mistakes_in_the_file_are_reported() {
        // Typos must not be silently ignored (think `admin_tokn`).
        let error = load_error(
            r#"
            homeserver = "https://matrix.example.org"
            admin_tokn = "s3cret"
            "#,
        );
        assert!(error.contains("admin_tokn"), "{error}");
        assert!(load_error("homeserver = ").contains("invalid config"));
        assert!(load_error(r#"listen = "localhost""#).contains("invalid config"));
    }

    #[test]
    fn explicit_config_path_must_exist() {
        let args = ServeArgs {
            config: Some(PathBuf::from("/nonexistent/ement-e2ee.toml")),
            ..Default::default()
        };
        let error = format!("{:#}", Config::load(&args).unwrap_err());
        assert!(error.contains("does not exist"), "{error}");
    }
}
