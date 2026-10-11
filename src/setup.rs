//! `ement-e2ee setup`: go from an installed binary to a running proxy.
//! Finds the homeserver, writes the config, installs the systemd user
//! service, and prints what to evaluate in Emacs.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use reqwest::Url;

use crate::config::{self, DEFAULT_LISTEN};

const UNIT_NAME: &str = "ement-e2ee.service";

#[derive(clap::Args)]
pub struct SetupArgs {
    /// Your Matrix user ID, e.g. @you:example.org. The homeserver is
    /// discovered from it (asked for if omitted).
    #[arg(long)]
    user_id: Option<String>,
    /// Homeserver base URL, skipping discovery.
    #[arg(long)]
    homeserver: Option<String>,
    /// Address the proxy should listen on.
    #[arg(long, default_value_t = DEFAULT_LISTEN)]
    listen: SocketAddr,
    /// Where to write the config (default: ~/.config/ement-e2ee/config.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Replace an existing config file.
    #[arg(long)]
    force: bool,
    /// Do not install or start the systemd user service.
    #[arg(long)]
    no_service: bool,
    /// Install and start the service without asking first.
    #[arg(long)]
    yes: bool,
}

pub async fn run(args: SetupArgs) -> anyhow::Result<()> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let user_id = match (&args.user_id, &args.homeserver) {
        (Some(user_id), _) => Some(user_id.clone()),
        // With an explicit homeserver the ID is only needed for the snippet.
        (None, Some(_)) => None,
        (None, None) => Some(prompt("Matrix user ID (e.g. @you:example.org): ")?),
    };
    let server_name = user_id.as_deref().map(server_name).transpose()?;

    let config_path = args
        .config
        .clone()
        .or_else(config::default_config_path)
        .context("could not determine the config directory; pass --config")?;

    let listen = if config_path.exists() && !args.force {
        // Somebody's settings: leave them alone and work with them.
        let existing = config::AdminEndpoint::listen(&config_path)?;
        println!(
            "Keeping the existing config at {} (use --force to replace it).",
            config_path.display()
        );
        existing
    } else {
        let homeserver = match (&args.homeserver, server_name) {
            (Some(homeserver), _) => config::parse_homeserver(homeserver)?,
            (None, Some(server_name)) => {
                let origin: Url = format!("https://{server_name}")
                    .parse()
                    .with_context(|| format!("{server_name} is not a valid server name"))?;
                println!("Looking up the homeserver for {server_name}…");
                discover(&http, &origin).await?
            }
            (None, None) => unreachable!("a user ID is asked for when no homeserver is given"),
        };
        check_homeserver(&http, &homeserver).await?;
        println!("Homeserver: {homeserver}");
        write_config(&config_path, &render_config(args.listen, &homeserver))?;
        println!("Wrote {}", config_path.display());
        args.listen
    };

    let custom_config = args.config.as_deref();
    if args.no_service {
        println!(
            "\nStart the proxy with:\n\n  {}",
            serve_command(custom_config)?
        );
    } else {
        install_service(&http, custom_config, listen, args.yes).await?;
    }

    println!(
        "\nConnect ement through the proxy by evaluating this in Emacs:\n\n{}\n",
        elisp_snippet(user_id.as_deref(), listen)
    );
    println!(
        "Once ement is connected, join your encrypted identity and verify the device:\n\n  \
         ement-e2ee ctl bootstrap\n  ement-e2ee ctl verify\n\n\
         `ement-e2ee ctl debug check` shows whether everything is in order."
    );
    Ok(())
}

fn prompt(question: &str) -> anyhow::Result<String> {
    print!("{question}");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    let read = std::io::stdin().read_line(&mut answer)?;
    anyhow::ensure!(read > 0, "no answer (standard input is closed)");
    Ok(answer.trim().to_owned())
}

/// The server name part of a Matrix user ID.
fn server_name(user_id: &str) -> anyhow::Result<String> {
    let parsed: &ruma::UserId = user_id
        .try_into()
        .with_context(|| format!("{user_id:?} is not a Matrix user ID (expected @name:server)"))?;
    Ok(parsed.server_name().to_string())
}

/// Client-server discovery per the spec's `.well-known` flow: ask `origin`
/// (https://<server name>) where the homeserver lives; if it says nothing,
/// the homeserver is `origin` itself.
pub async fn discover(http: &reqwest::Client, origin: &Url) -> anyhow::Result<Url> {
    let well_known = origin.join("/.well-known/matrix/client")?;
    let advertised = match http.get(well_known).send().await {
        Ok(response) if response.status().is_success() => response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| {
                body.pointer("/m.homeserver/base_url")?
                    .as_str()
                    .map(ToOwned::to_owned)
            }),
        // No .well-known, or the host does not answer at all: fall through.
        _ => None,
    };
    match advertised {
        Some(base_url) => config::parse_homeserver(base_url.trim_end_matches('/'))
            .with_context(|| format!("{origin} advertises an unusable homeserver URL")),
        None => config::parse_homeserver(origin.as_str()),
    }
}

/// Make sure a Matrix homeserver answers at `homeserver` before writing it
/// into a config that would otherwise fail later and less obviously.
pub async fn check_homeserver(http: &reqwest::Client, homeserver: &Url) -> anyhow::Result<()> {
    let url = homeserver.join("/_matrix/client/versions")?;
    let response = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("could not reach {homeserver}"))?;
    let status = response.status();
    let is_matrix = status.is_success()
        && response
            .json::<serde_json::Value>()
            .await
            .is_ok_and(|body| body.get("versions").is_some());
    anyhow::ensure!(
        is_matrix,
        "{homeserver} does not look like a Matrix homeserver ({status} on /_matrix/client/versions); \
         pass --homeserver with the right URL"
    );
    Ok(())
}

pub fn render_config(listen: SocketAddr, homeserver: &Url) -> String {
    let homeserver = homeserver.as_str().trim_end_matches('/');
    format!(
        r#"# ement-e2ee configuration (written by `ement-e2ee setup`)

# Where the proxy listens; point (ement-connect :uri-prefix ...) here.
listen = "{listen}"

# Your real homeserver (the client-server API base URL).
homeserver = "{homeserver}"

# Where crypto stores and media key caches live.
# store_dir = "~/.local/share/ement-e2ee"   # default

# tracing filter: error | warn | info | debug | trace, or e.g. "ement_e2ee=debug"
# log_level = "info"

# Optional: encrypt the sqlite crypto store. Either the passphrase itself or,
# better, a command that prints it (a password manager, secret-tool, ...).
# store_passphrase_command = "pass show ement-e2ee/store"
# store_passphrase = "..."

# Optional: require a token on the /_ement admin API (`ement-e2ee ctl` reads
# it from this file).
# admin_token = "..."
"#
    )
}

/// Write the config, readable by the owner only: it may hold secrets.
pub fn write_config(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

fn exe_path() -> anyhow::Result<PathBuf> {
    std::env::current_exe().context("could not determine the path of this executable")
}

/// The command line that starts the proxy with this setup's config.
fn serve_command(custom_config: Option<&Path>) -> anyhow::Result<String> {
    Ok(exec_start(&exe_path()?, custom_config))
}

fn exec_start(exe: &Path, custom_config: Option<&Path>) -> String {
    // systemd and shells both understand double-quoted words.
    let quote = |path: &Path| {
        let text = path.display().to_string();
        if text.contains(char::is_whitespace) {
            format!("\"{text}\"")
        } else {
            text
        }
    };
    match custom_config {
        Some(config) => format!("{} serve --config {}", quote(exe), quote(config)),
        None => format!("{} serve", quote(exe)),
    }
}

pub fn render_unit(exe: &Path, custom_config: Option<&Path>) -> String {
    format!(
        "# systemd user unit (written by `ement-e2ee setup`)\n\
         [Unit]\n\
         Description=Transparent E2EE proxy for ement.el\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exec_start(exe, custom_config)
    )
}

/// What to evaluate in Emacs. ement asks for the password itself.
pub fn elisp_snippet(user_id: Option<&str>, listen: SocketAddr) -> String {
    format!(
        "  (ement-connect :user-id \"{}\"\n                 :uri-prefix \"http://{}\")",
        user_id.unwrap_or("@you:example.org"),
        config::connect_addr(listen)
    )
}

fn systemctl(args: &[&str]) -> anyhow::Result<bool> {
    let status = std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(status) => Ok(status.success()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).context("failed to run systemctl"),
    }
}

async fn install_service(
    http: &reqwest::Client,
    custom_config: Option<&Path>,
    listen: SocketAddr,
    assume_yes: bool,
) -> anyhow::Result<()> {
    let serve = serve_command(custom_config)?;
    if !systemctl(&["show-environment"])? {
        println!(
            "\nNo systemd user session here, so no service was installed. Start the proxy with:\n\n  \
             {serve}\n\n\
             (On WSL2, systemd is enabled with `[boot] systemd=true` in /etc/wsl.conf \
             followed by `wsl.exe --shutdown`.)"
        );
        return Ok(());
    }
    if !assume_yes {
        let answer = prompt("\nInstall and start the systemd user service? [Y/n] ")?;
        if matches!(answer.to_lowercase().as_str(), "n" | "no") {
            println!("Skipped. Start the proxy with:\n\n  {serve}");
            return Ok(());
        }
    }

    let unit_path = dirs::config_dir()
        .context("could not determine the config directory")?
        .join("systemd/user")
        .join(UNIT_NAME);
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&unit_path, render_unit(&exe_path()?, custom_config))
        .with_context(|| format!("failed to write {}", unit_path.display()))?;
    println!("Wrote {}", unit_path.display());

    for args in [
        &["daemon-reload"][..],
        &["enable", UNIT_NAME],
        // restart rather than start: pick up a config that was just rewritten.
        &["restart", UNIT_NAME],
    ] {
        anyhow::ensure!(
            systemctl(args)?,
            "`systemctl --user {}` failed; see `journalctl --user -u {UNIT_NAME}`",
            args.join(" ")
        );
    }

    // Do not claim success before the proxy actually answers.
    let status_url = format!(
        "http://{}/_matrix/client/versions",
        config::connect_addr(listen)
    );
    for _ in 0..50 {
        if http.get(&status_url).send().await.is_ok() {
            println!("The proxy is running (logs: journalctl --user -u {UNIT_NAME} -f).");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!(
        "the service was started but the proxy does not answer on {listen}; \
         see `journalctl --user -u {UNIT_NAME}`"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServeArgs;
    use crate::testutil::FakeHomeserver;

    #[test]
    fn server_name_comes_from_the_user_id() {
        assert_eq!(server_name("@ben:example.org").unwrap(), "example.org");
        assert_eq!(
            server_name("@a:matrix.example.org:8448").unwrap(),
            "matrix.example.org:8448"
        );
        for bad in ["ben", "ben@example.org", "@ben", ""] {
            let error = server_name(bad).unwrap_err().to_string();
            assert!(error.contains("not a Matrix user ID"), "{bad}: {error}");
        }
    }

    #[test]
    fn written_config_loads_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/dir/config.toml");
        let homeserver: Url = "https://matrix.example.org".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        write_config(&path, &render_config(listen, &homeserver)).unwrap();

        // What setup writes is what serve reads.
        let args = ServeArgs {
            config: Some(path.clone()),
            ..Default::default()
        };
        let config = crate::config::Config::load(&args).unwrap();
        assert_eq!(config.listen, listen);
        assert_eq!(config.homeserver, homeserver);
        assert_eq!(config.store_passphrase, None);
        assert_eq!(config.admin_token, None);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn unit_runs_this_binary_with_this_config() {
        let unit = render_unit(Path::new("/home/me/.cargo/bin/ement-e2ee"), None);
        assert!(unit.contains("\nExecStart=/home/me/.cargo/bin/ement-e2ee serve\n"));
        assert!(unit.contains("[Install]\nWantedBy=default.target"));
        assert!(unit.contains("Restart=on-failure"));

        let unit = render_unit(
            Path::new("/opt/my tools/ement-e2ee"),
            Some(Path::new("/etc/ement e2ee.toml")),
        );
        assert!(unit.contains(
            "ExecStart=\"/opt/my tools/ement-e2ee\" serve --config \"/etc/ement e2ee.toml\"\n"
        ));
    }

    #[test]
    fn snippet_points_ement_at_the_proxy() {
        let snippet = elisp_snippet(Some("@ben:example.org"), "127.0.0.1:8009".parse().unwrap());
        assert!(snippet.contains(":user-id \"@ben:example.org\""));
        assert!(snippet.contains(":uri-prefix \"http://127.0.0.1:8009\""));
        // A wildcard bind is still reached through loopback.
        let snippet = elisp_snippet(None, "0.0.0.0:9000".parse().unwrap());
        assert!(snippet.contains(":uri-prefix \"http://127.0.0.1:9000\""));
        assert!(snippet.contains("@you:example.org"));
    }

    #[tokio::test]
    async fn discovery_follows_well_known() {
        let http = reqwest::Client::new();
        // The server named in the user ID delegates to another host.
        let homeserver = FakeHomeserver::start().await;
        let delegating = FakeHomeserver::start().await;
        delegating.lock().well_known = Some(serde_json::json!({
            "m.homeserver": { "base_url": format!("{}", homeserver.url) },
        }));
        let found = discover(&http, &delegating.url).await.unwrap();
        assert_eq!(found, homeserver.url);
        check_homeserver(&http, &found).await.unwrap();
    }

    #[tokio::test]
    async fn discovery_falls_back_to_the_server_itself() {
        let http = reqwest::Client::new();
        // No .well-known at all: the server name is the homeserver.
        let homeserver = FakeHomeserver::start().await;
        assert_eq!(
            discover(&http, &homeserver.url).await.unwrap(),
            homeserver.url
        );

        // A .well-known without a homeserver entry says nothing either.
        homeserver.lock().well_known = Some(serde_json::json!({ "m.identity_server": {} }));
        assert_eq!(
            discover(&http, &homeserver.url).await.unwrap(),
            homeserver.url
        );

        // One that names something unusable is an error, not a silent guess.
        homeserver.lock().well_known = Some(serde_json::json!({
            "m.homeserver": { "base_url": "https://example.org/some/path" },
        }));
        let error = discover(&http, &homeserver.url).await.unwrap_err();
        assert!(format!("{error:#}").contains("unusable homeserver URL"));
    }

    #[tokio::test]
    async fn a_non_matrix_server_is_rejected_before_writing_anything() {
        let http = reqwest::Client::new();
        // Something answers, but it is not a homeserver.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|| async { "hello" });
            axum::serve(listener, app).await.unwrap();
        });
        let error = check_homeserver(&http, &url).await.unwrap_err().to_string();
        assert!(
            error.contains("does not look like a Matrix homeserver"),
            "{error}"
        );

        // Nothing answers at all: a port that was just released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dead: Url = format!("http://127.0.0.1:{port}").parse().unwrap();
        let error = check_homeserver(&http, &dead)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not reach"), "{error}");
    }

    #[tokio::test]
    async fn setup_without_service_writes_a_working_config() {
        let homeserver = FakeHomeserver::start().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let args = |force| SetupArgs {
            user_id: Some("@ben:example.org".to_owned()),
            homeserver: Some(homeserver.url.to_string()),
            listen: "127.0.0.1:9002".parse().unwrap(),
            config: Some(path.clone()),
            force,
            no_service: true,
            yes: false,
        };
        run(args(false)).await.unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("listen = \"127.0.0.1:9002\""));
        assert!(written.contains(&format!(
            "homeserver = \"{}\"",
            homeserver.url.as_str().trim_end_matches('/')
        )));

        // Running it again must not clobber what the user has since edited.
        std::fs::write(&path, format!("{written}\nadmin_token = \"mine\"\n")).unwrap();
        run(args(false)).await.unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("admin_token = \"mine\"")
        );
        // Unless asked to.
        run(args(true)).await.unwrap();
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("admin_token = \"mine\"")
        );
    }
}
