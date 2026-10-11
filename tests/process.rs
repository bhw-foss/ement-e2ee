//! Process-level tests: the real binary, its command line, exit codes and
//! signals. (Everything that needs a homeserver is tested in-crate, in
//! `src/e2e_tests.rs`.)

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ement-e2ee");

/// A port nothing listens on (released just now).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running `ement-e2ee serve` with its own config and store.
struct Proxy {
    child: Child,
    config: PathBuf,
    port: u16,
    dir: tempfile::TempDir,
}

impl Proxy {
    /// Start with `homeserver` (a URL) and any further config lines.
    fn start(homeserver: &str, extra_config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "listen = \"127.0.0.1:{port}\"\nhomeserver = \"{homeserver}\"\nstore_dir = \"{}\"\n{extra_config}\n",
                dir.path().join("store").display()
            ),
        )
        .unwrap();
        let child = Command::new(BIN)
            .args(["serve", "--config"])
            .arg(&config)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "the proxy did not start listening"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            config,
            port,
            dir,
        }
    }

    /// Start with a homeserver URL where nothing answers.
    fn start_offline(extra_config: &str) -> Self {
        Self::start(&format!("http://127.0.0.1:{}", free_port()), extra_config)
    }

    /// Run `ement-e2ee ctl --config <this proxy's config> ARGS...`.
    fn ctl(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(["ctl", "--config"])
            .arg(&self.config)
            .args(args)
            .output()
            .unwrap()
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Wait for the process to exit; returns (exit status, stdout).
    fn wait(mut self, limit: Duration) -> (std::process::ExitStatus, String) {
        let deadline = Instant::now() + limit;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the proxy did not exit within {limit:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = String::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        (status, stdout)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn sigterm_stops_the_proxy_cleanly() {
    // What `systemctl stop` sends.
    let proxy = Proxy::start_offline("");
    proxy.signal("-TERM");
    let (status, log) = proxy.wait(Duration::from_secs(10));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("terminated; shutting down"), "{log}");
}

#[test]
fn sigint_stops_the_proxy_cleanly() {
    let proxy = Proxy::start_offline("");
    proxy.signal("-INT");
    let (status, log) = proxy.wait(Duration::from_secs(10));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("interrupted; shutting down"), "{log}");
}

#[test]
fn shutdown_does_not_wait_for_hung_requests() {
    // A homeserver that accepts connections and never answers, like a
    // long-polling /sync with nothing to report.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let homeserver = format!("http://{}", silent.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for connection in silent.incoming() {
            held.push(connection);
        }
    });
    let proxy = Proxy::start(&homeserver, "");

    // A client request the proxy is still waiting on upstream for.
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).unwrap();
    client
        .write_all(b"GET /_matrix/client/versions HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let asked = Instant::now();
    proxy.signal("-TERM");
    let (status, log) = proxy.wait(Duration::from_secs(15));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("closing remaining connections"), "{log}");
    // It gave the request a moment, but not systemd's whole stop timeout.
    assert!(
        asked.elapsed() >= Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    assert!(
        asked.elapsed() < Duration::from_secs(10),
        "{:?}",
        asked.elapsed()
    );
}

#[test]
fn ctl_finds_the_proxy_and_its_token_through_the_config() {
    let proxy = Proxy::start_offline("admin_token = \"s3cret\"");

    // No --proxy, no token on the command line: both come from the config.
    let output = proxy.ctl(&["status"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let status: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["sessions"], serde_json::json!([]));

    // A config without the token is turned away, and told why.
    let other_config = proxy.dir.path().join("no-token.toml");
    std::fs::write(
        &other_config,
        format!(
            "listen = \"127.0.0.1:{}\"\nhomeserver = \"http://127.0.0.1:1\"\n",
            proxy.port
        ),
    )
    .unwrap();
    let output = Command::new(BIN)
        .args(["ctl", "--config"])
        .arg(&other_config)
        .arg("status")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("401"), "{error}");
    assert!(error.contains("admin_token"), "{error}");
}

#[test]
fn ctl_says_when_no_proxy_is_running() {
    let output = Command::new(BIN)
        .args([
            "ctl",
            "--proxy",
            &format!("http://127.0.0.1:{}", free_port()),
            "status",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("could not reach the proxy"), "{error}");
    assert!(error.contains("ement-e2ee serve"), "{error}");
}

#[test]
fn debug_commands_against_a_running_proxy() {
    let proxy = Proxy::start_offline("");

    // The homeserver is unreachable: `check` says so, with the remedy, and
    // exits non-zero so scripts notice.
    let output = proxy.ctl(&["debug", "check"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(
        report.starts_with(&format!("ement-e2ee {} — up ", env!("CARGO_PKG_VERSION"))),
        "{report}"
    );
    assert!(report.contains("  ✗ homeserver "), "{report}");
    assert!(
        report.contains("→ check the network and the `homeserver` setting"),
        "{report}"
    );
    assert!(report.contains("  ! sessions "), "{report}");
    assert!(report.contains("1 failure"), "{report}");
    assert!(stderr(&output).contains("1 check(s) failed"));

    // --json gives the same findings to a program.
    let output = proxy.ctl(&["debug", "check", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["summary"]["fail"], 1);
    assert_eq!(json["proxy"][0]["id"], "homeserver");

    // The log level changes without a restart, and the in-memory tail has
    // both the start-up line and the change.
    let output = proxy.ctl(&["debug", "log-level", "ement_e2ee=debug"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("now logs at: ement_e2ee=debug"));
    let output = proxy.ctl(&["debug", "log-level", "ement_e2ee=loud"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("invalid log filter"),
        "{}",
        stderr(&output)
    );
    let output = proxy.ctl(&["debug", "logs"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let logs = stdout(&output);
    assert!(
        logs.contains("INFO  ement_e2ee: starting ement-e2ee"),
        "{logs}"
    );
    assert!(
        logs.contains("log filter changed filter=ement_e2ee=debug"),
        "{logs}"
    );
    let output = proxy.ctl(&["debug", "logs", "--level", "error"]);
    assert!(
        stdout(&output).starts_with("No log lines"),
        "{}",
        stdout(&output)
    );

    // Session-specific commands explain what is missing.
    let output = proxy.ctl(&["debug", "session"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no active sessions"),
        "{}",
        stderr(&output)
    );

    // The report is one JSON file.
    let path = proxy.dir.path().join("report.json");
    let output = proxy.ctl(&["debug", "report", "--output", path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(report["check"]["summary"]["fail"], 1);
    assert!(report["logs"]["lines"].as_array().unwrap().len() >= 2);
}

#[test]
fn debug_log_level_takes_effect_on_stdout() {
    let proxy = Proxy::start_offline("log_level = \"warn\"");
    // Nothing at INFO reaches stdout at first ...
    assert!(proxy.ctl(&["status"]).status.success());
    assert!(
        proxy
            .ctl(&["debug", "log-level", "ement_e2ee=trace"])
            .status
            .success()
    );
    // ... but after the change, per-request tracing does.
    assert!(proxy.ctl(&["status"]).status.success());
    proxy.signal("-TERM");
    let (_, log) = proxy.wait(Duration::from_secs(10));
    assert!(!log.contains("starting ement-e2ee"), "{log}");
    assert!(log.contains("log filter changed"), "{log}");
    assert!(log.contains("TRACE"), "{log}");
}

#[test]
fn a_failing_passphrase_command_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "homeserver = \"https://matrix.example.org\"\nstore_passphrase_command = \"exit 7\"\n",
    )
    .unwrap();
    let output = Command::new(BIN)
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("store_passphrase_command failed"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn setup_writes_the_config_and_prints_the_snippet() {
    // Just enough of a homeserver for setup's sanity check.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let homeserver = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for connection in listener.incoming() {
            let mut connection = connection.unwrap();
            let mut request = [0u8; 2048];
            let _ = connection.read(&mut request);
            let body = r#"{"versions":["v1.11"]}"#;
            let _ = write!(
                connection,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ement-e2ee/config.toml");
    let output = Command::new(BIN)
        .args(["setup", "--user-id", "@ben:example.org", "--no-service"])
        .args([
            "--homeserver",
            &homeserver,
            "--listen",
            "127.0.0.1:9123",
            "--config",
        ])
        .arg(&config)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains(":user-id \"@ben:example.org\""), "{text}");
    assert!(
        text.contains(":uri-prefix \"http://127.0.0.1:9123\""),
        "{text}"
    );
    assert!(
        text.contains(&format!("serve --config {}", config.display())),
        "{text}"
    );
    assert!(text.contains("ement-e2ee ctl bootstrap"), "{text}");

    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains("listen = \"127.0.0.1:9123\""), "{written}");
    assert!(
        written.contains(&format!("homeserver = \"{homeserver}\"")),
        "{written}"
    );

    // Without a user ID or homeserver it has to ask, and says so if it cannot.
    let output = Command::new(BIN)
        .args(["setup", "--no-service", "--config"])
        .arg(dir.path().join("other.toml"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no answer"), "{}", stderr(&output));
}
