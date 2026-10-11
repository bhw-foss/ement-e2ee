use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::ServeArgs;

pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8009);

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<SocketAddr>,
    homeserver: Option<String>,
    store_dir: Option<PathBuf>,
    log_level: Option<String>,
    store_passphrase: Option<String>,
    store_passphrase_command: Option<String>,
    admin_token: Option<String>,
}

impl FileConfig {
    /// Read the config file. An explicitly given path must exist; the default
    /// one may be absent (everything can come from the command line).
    fn read(explicit: Option<&Path>) -> anyhow::Result<Self> {
        let path = explicit.map(Path::to_owned).or_else(default_config_path);
        match &path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("failed to read {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("invalid config {}", p.display()))
            }
            Some(p) if explicit.is_some() => {
                anyhow::bail!("config file {} does not exist", p.display())
            }
            _ => Ok(Self::default()),
        }
    }
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

/// Expand a leading `~` the way a shell would; TOML values never pass
/// through one.
pub fn expand_tilde(path: PathBuf) -> PathBuf {
    let Ok(rest) = path.strip_prefix("~") else {
        return path;
    };
    match dirs::home_dir() {
        Some(home) => home.join(rest),
        None => path,
    }
}

/// Normalize a homeserver base URL: no path, no trailing slash.
pub fn parse_homeserver(homeserver: &str) -> anyhow::Result<reqwest::Url> {
    let mut url: reqwest::Url = homeserver
        .parse()
        .context("homeserver is not a valid URL")?;
    if url.path() != "/" && !url.path().is_empty() {
        anyhow::bail!("homeserver URL must not have a path: {url}");
    }
    url.set_path("");
    Ok(url)
}

/// Run `store_passphrase_command` and take its output as the passphrase.
fn passphrase_from_command(command: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::null())
        // Let the command's own diagnostics reach the log.
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("failed to run store_passphrase_command")?;
    if !output.status.success() {
        anyhow::bail!("store_passphrase_command failed ({})", output.status);
    }
    let passphrase = String::from_utf8(output.stdout)
        .context("store_passphrase_command printed invalid UTF-8")?;
    let passphrase = passphrase.trim_end_matches(['\n', '\r']);
    if passphrase.is_empty() {
        anyhow::bail!("store_passphrase_command printed nothing");
    }
    Ok(passphrase.to_owned())
}

impl Config {
    pub fn load(args: &ServeArgs) -> anyhow::Result<Self> {
        let file = FileConfig::read(args.config.as_deref())?;

        let homeserver = args
            .homeserver
            .clone()
            .or(file.homeserver)
            .context("no homeserver configured (set `homeserver` in config.toml or pass --homeserver)")?;
        let homeserver = parse_homeserver(&homeserver)?;

        let store_dir = args
            .store_dir
            .clone()
            .or(file.store_dir.map(expand_tilde))
            .or_else(|| dirs::data_dir().map(|d| d.join("ement-e2ee")))
            .context("could not determine store directory")?;

        let store_passphrase = match (file.store_passphrase, file.store_passphrase_command) {
            (Some(_), Some(_)) => anyhow::bail!(
                "set either store_passphrase or store_passphrase_command, not both"
            ),
            (passphrase, None) => passphrase,
            (None, Some(command)) => Some(passphrase_from_command(&command)?),
        };

        Ok(Self {
            listen: args.listen.or(file.listen).unwrap_or(DEFAULT_LISTEN),
            homeserver,
            store_dir,
            log_level: args
                .log_level
                .clone()
                .or(file.log_level)
                .unwrap_or_else(|| "info".to_owned()),
            store_passphrase,
            admin_token: file.admin_token,
        })
    }
}

/// What `ctl` needs to reach a running proxy: where it listens and how to
/// authenticate to its admin API. Read from the same config file as `serve`,
/// without touching the settings only the proxy itself needs.
#[derive(Debug)]
pub struct AdminEndpoint {
    pub url: String,
    pub admin_token: Option<String>,
}

impl AdminEndpoint {
    pub fn load(config: Option<&Path>, proxy: Option<&str>) -> anyhow::Result<Self> {
        let file = FileConfig::read(config)?;
        let url = match proxy {
            Some(proxy) => proxy.trim_end_matches('/').to_owned(),
            None => format!("http://{}", connect_addr(file.listen.unwrap_or(DEFAULT_LISTEN))),
        };
        Ok(Self {
            url,
            admin_token: file.admin_token,
        })
    }

    /// The listen address a config file sets (or the default).
    pub fn listen(config: &Path) -> anyhow::Result<SocketAddr> {
        Ok(FileConfig::read(Some(config))?.listen.unwrap_or(DEFAULT_LISTEN))
    }
}

/// The address to connect to for a proxy listening on `listen`: a wildcard
/// bind is reached through loopback.
pub fn connect_addr(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
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
    fn tilde_in_store_dir_means_home() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(
            expand_tilde("~/.local/share/ement-e2ee".into()),
            home.join(".local/share/ement-e2ee")
        );
        assert_eq!(expand_tilde("~".into()), home);
        // Only a leading `~` component is special.
        assert_eq!(expand_tilde("/srv/~/x".into()), PathBuf::from("/srv/~/x"));
        assert_eq!(expand_tilde("~other/x".into()), PathBuf::from("~other/x"));
        assert_eq!(expand_tilde("relative/x".into()), PathBuf::from("relative/x"));

        let dir = tempfile::tempdir().unwrap();
        let args = args_for(
            &dir,
            r#"
            homeserver = "https://matrix.example.org"
            store_dir = "~/stores"
            "#,
        );
        assert_eq!(Config::load(&args).unwrap().store_dir, home.join("stores"));
    }

    #[test]
    fn passphrase_can_come_from_a_command() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(
            &dir,
            r#"
            homeserver = "https://matrix.example.org"
            store_passphrase_command = "printf 'correct horse\\n'"
            "#,
        );
        // The trailing newline every such tool prints is not part of it.
        assert_eq!(
            Config::load(&args).unwrap().store_passphrase.as_deref(),
            Some("correct horse")
        );
    }

    #[test]
    fn passphrase_command_failures_stop_startup() {
        // Starting with no passphrase would silently create a second,
        // unencrypted store next to the real one.
        let config = |command: &str| {
            format!(
                "homeserver = \"https://matrix.example.org\"\nstore_passphrase_command = \"{command}\""
            )
        };
        assert!(load_error(&config("exit 3")).contains("store_passphrase_command failed"));
        assert!(load_error(&config("true")).contains("printed nothing"));
        assert!(load_error(&config("echo")).contains("printed nothing"));
        let both = format!("{}\nstore_passphrase = \"x\"", config("echo y"));
        assert!(load_error(&both).contains("not both"));
    }

    #[test]
    fn ctl_finds_the_proxy_from_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(
            &dir,
            r#"
            listen = "127.0.0.1:9123"
            homeserver = "https://matrix.example.org"
            admin_token = "s3cret"
            store_passphrase_command = "exit 1"
            "#,
        );
        let path = args.config.as_deref();
        // Neither the homeserver nor the passphrase command matter to ctl.
        let endpoint = AdminEndpoint::load(path, None).unwrap();
        assert_eq!(endpoint.url, "http://127.0.0.1:9123");
        assert_eq!(endpoint.admin_token.as_deref(), Some("s3cret"));

        // --proxy overrides the address but the token still applies.
        let endpoint = AdminEndpoint::load(path, Some("http://127.0.0.1:1/")).unwrap();
        assert_eq!(endpoint.url, "http://127.0.0.1:1");
        assert_eq!(endpoint.admin_token.as_deref(), Some("s3cret"));
    }

    #[test]
    fn wildcard_listen_is_reached_via_loopback() {
        assert_eq!(
            connect_addr("0.0.0.0:8009".parse().unwrap()),
            "127.0.0.1:8009".parse().unwrap()
        );
        assert_eq!(
            connect_addr("[::]:8009".parse().unwrap()),
            "[::1]:8009".parse().unwrap()
        );
        assert_eq!(
            connect_addr("192.168.1.5:8009".parse().unwrap()),
            "192.168.1.5:8009".parse().unwrap()
        );
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
