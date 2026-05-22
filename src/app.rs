//! CLI boundary for hifi.
//!
//! This module keeps command parsing and command dispatch separate from scanner
//! and runtime internals. Formatting, HTTP client setup, and completion scripts
//! live in focused submodules so the command flow stays easy to scan.

mod client;
mod completions;
mod render;

use self::client::runtime_client;
use self::completions::{
    completion_script, install_completions, parse_completions, parse_install,
    print_host_completions, Shell,
};
pub use self::render::escape_terminal;
use self::render::{render_daemon_reply, render_processed, render_warnings, RenderOptions};
use crate::grep;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::daemon;
use crate::runtime::http::Client;
use crate::runtime::net;
use crate::runtime::processor::{CacheContext, Processor};
use std::io;
use std::time::Duration;
use thiserror::Error;

const HELP: &str = "\
hifi — map an HTTP API surface

USAGE:
    hifi <url> [<path-filter>] [--routes] [--all] [--no-cache] [--no-daemon] [--flat|--json]
    hifi grep <url> <pattern> [-C N] [--max-hits N] [--max-bytes-per-hit N] [-a|--all]
    hifi serve
    hifi install [bash|zsh|fish]
    hifi completions <bash|zsh|fish>

EXAMPLES:
    hifi example.com
    hifi example.com /modules        # drill into one resource
    hifi https://api.example.com/v2
    hifi grep example.com TODO -C 2

FLAGS:
    -h, --help        show this help
    -r, --routes      expand the route summary into a full path list
    -a, --all         include internal/framework routes (e.g. _next, _index)
        --no-cache    bypass cached results
        --no-daemon   skip the background daemon
        --flat        print tab-separated output
        --json        print machine-readable JSON

GREP FLAGS:
    -C, --context N              include N lines around each hit
        --max-hits N             cap printed hits (default: 50)
        --max-bytes-per-hit N    cap each printed snippet (default: 200)
    -a, --all                    print all hits

SHELL COMPLETION:
    Tab-complete subcommands, flags, and cached hosts. One-shot install:
        hifi install            # detect your shell automatically
        hifi install zsh        # or pick a specific shell
    To print the raw script instead, use `hifi completions <shell>`.
";

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Daemon(#[from] daemon::DaemonError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Net(#[from] net::NetError),
    #[error(transparent)]
    Http(#[from] crate::runtime::http::Error),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::processor::RuntimeError),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

impl From<&'static str> for AppError {
    fn from(value: &'static str) -> Self {
        Self::Message(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Auto,
    Flat,
    Json,
}

impl OutputMode {
    pub fn for_stdout(self) -> Self {
        match self {
            Self::Auto => Self::Flat,
            mode => mode,
        }
    }
}

#[derive(Debug)]
enum Command {
    Help,
    Serve,
    Grep(Vec<String>),
    Scan(ScanArgs),
    Completions(Shell),
    Install(Option<Shell>),
    CompleteHosts(String),
    CompletePaths { url: String, prefix: String },
}

// Keep CLI state explicit. The scanner should not need to know whether a scan
// came from argv, a daemon request, or a future library caller.
#[derive(Debug)]
struct ScanArgs {
    url: String,
    no_cache: bool,
    no_daemon: bool,
    mode: OutputMode,
    render: RenderOptions,
}

pub async fn run(raw: Vec<String>) -> Result<i32, AppError> {
    let command = parse_command(&raw)?;
    match command {
        Command::Help => {
            print!("{HELP}");
            Ok(0)
        }
        Command::Completions(shell) => {
            print!("{}", completion_script(shell));
            Ok(0)
        }
        Command::Install(shell) => install_completions(shell),
        Command::CompleteHosts(prefix) => {
            print_host_completions(&prefix);
            Ok(0)
        }
        Command::CompletePaths { url, prefix } => {
            self::completions::print_path_completions(&url, &prefix);
            Ok(0)
        }
        Command::Grep(args) => {
            let (config, client) = runtime_client()?;
            grep::run(&args, client, config).await
        }
        Command::Serve => {
            let (config, client) = runtime_client()?;
            daemon::serve(client, config).await?;
            Ok(0)
        }
        Command::Scan(args) => {
            let (config, client) = runtime_client()?;
            run_scan(args, client, config).await
        }
    }
}

pub fn run_completion(raw: &[String]) -> Option<Result<i32, AppError>> {
    if !matches!(
        raw.first().map(String::as_str),
        Some("__complete" | "__complete-paths")
    ) {
        return None;
    }

    let result = match parse_command(raw) {
        Ok(Command::CompleteHosts(prefix)) => {
            print_host_completions(&prefix);
            Ok(0)
        }
        Ok(Command::CompletePaths { url, prefix }) => {
            self::completions::print_path_completions(&url, &prefix);
            Ok(0)
        }
        Ok(_) => return None,
        Err(err) => Err(err),
    };
    Some(result)
}

fn parse_command(raw: &[String]) -> Result<Command, AppError> {
    if raw.is_empty() || matches!(raw[0].as_str(), "-h" | "--help" | "help") {
        return Ok(Command::Help);
    }
    match raw[0].as_str() {
        "grep" => Ok(Command::Grep(raw[1..].to_vec())),
        "serve" => {
            if raw.len() > 1 {
                return Err(format!("unexpected argument '{}' (try --help)", raw[1]).into());
            }
            Ok(Command::Serve)
        }
        "completions" => parse_completions(&raw[1..]).map(Command::Completions),
        "install" => Ok(Command::Install(parse_install(&raw[1..])?)),
        "__complete" => Ok(Command::CompleteHosts(
            raw.get(1).cloned().unwrap_or_default(),
        )),
        "__complete-paths" => Ok(Command::CompletePaths {
            url: raw.get(1).cloned().unwrap_or_default(),
            prefix: raw.get(2).cloned().unwrap_or_default(),
        }),
        _ => parse_scan_args(raw).map(Command::Scan),
    }
}

fn parse_scan_args(raw: &[String]) -> Result<ScanArgs, AppError> {
    let mut url = None;
    let mut filter: Option<String> = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    let mut mode = OutputMode::Auto;
    let mut render = RenderOptions::default();
    for arg in raw {
        match arg.as_str() {
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            "--flat" => mode = set_mode(mode, OutputMode::Flat)?,
            "--json" => mode = set_mode(mode, OutputMode::Json)?,
            "--routes" | "-r" => render.expand_routes = true,
            "--all" | "-a" => render.show_internal = true,
            s if s.starts_with("--") || s.starts_with('-') => {
                return Err(format!("unknown flag '{s}' (try --help)").into());
            }
            _ if url.is_none() => url = Some(arg.clone()),
            _ if filter.is_none() => filter = Some(normalize_filter(arg)),
            _ => return Err(format!("unexpected argument '{arg}' (try --help)").into()),
        }
    }
    let url = url.ok_or("missing URL (try --help)")?;
    let url = normalize_url(&url)?;
    if filter.is_some() {
        render.expand_routes = true;
    }
    render.filter = filter;

    Ok(ScanArgs {
        url,
        no_cache,
        no_daemon,
        mode,
        render,
    })
}

// Accept `/modules`, `modules`, or `/modules/` and normalize to `/modules`.
fn normalize_filter(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

async fn run_scan(args: ScanArgs, client: Client, config: RuntimeConfig) -> Result<i32, AppError> {
    if !args.no_daemon {
        if let Some(reply) = daemon_output(&args.url, args.no_cache, args.mode, &args.render).await
        {
            print!("{}", reply.stdout);
            eprint!("{}", reply.stderr);
            return Ok(reply.exit_code);
        }
    }

    let out = Processor::new(
        &client,
        config.chunk_concurrency,
        CacheContext::for_config(config),
    )
    .process_for_display(&args.url, args.no_cache, std::time::Instant::now())
    .await?;
    render_processed(&out, args.mode, &args.render)?;
    render_warnings(&out);
    Ok(0)
}

fn set_mode(current: OutputMode, next: OutputMode) -> Result<OutputMode, AppError> {
    if current != OutputMode::Auto && current != next {
        return Err("choose only one of --flat or --json".into());
    }
    Ok(next)
}

pub fn normalize_url(url: &str) -> Result<String, AppError> {
    if url.contains("://") {
        let parsed = url::Url::parse(url)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!("unsupported URL scheme '{}'", parsed.scheme()).into());
        }
        Ok(parsed.to_string())
    } else {
        Ok(url::Url::parse(&format!("https://{url}"))?.to_string())
    }
}

async fn daemon_output(
    url: &str,
    no_cache: bool,
    mode: OutputMode,
    render: &RenderOptions,
) -> Option<daemon::DaemonReply> {
    match daemon::request(url, no_cache).await {
        daemon::DaemonRequest::Reply(mut out) => {
            render_daemon_reply(&mut out, mode, render);
            return Some(out);
        }
        daemon::DaemonRequest::StaleDaemon | daemon::DaemonRequest::Unavailable => {}
    }
    if daemon::start() {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(25));
            match daemon::request(url, no_cache).await {
                daemon::DaemonRequest::Reply(mut out) => {
                    render_daemon_reply(&mut out, mode, render);
                    return Some(out);
                }
                daemon::DaemonRequest::StaleDaemon | daemon::DaemonRequest::Unavailable => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scan_command_normalizes_url_and_keeps_runtime_flags() {
        let raw = args(["example.com", "--no-cache", "--no-daemon", "--json"]);

        let Command::Scan(scan) = parse_command(&raw).unwrap() else {
            panic!("expected scan command");
        };

        assert_eq!(scan.url, "https://example.com/");
        assert!(scan.no_cache);
        assert!(scan.no_daemon);
        assert_eq!(scan.mode, OutputMode::Json);
    }

    #[test]
    fn parse_subcommands_before_scan_flags() {
        let grep = parse_command(&args(["grep", "example.com", "TODO"])).unwrap();
        assert!(matches!(grep, Command::Grep(values) if values == args(["example.com", "TODO"])));

        let serve = parse_command(&args(["serve"])).unwrap();
        assert!(matches!(serve, Command::Serve));
    }

    fn args<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
