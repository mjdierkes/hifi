//! CLI boundary for hifi.
//!
//! The product surface is intentionally narrow: scan a URL for internal APIs or
//! grep the raw reachable app bytes.

mod client;
mod render;

use self::client::runtime_client;
use self::render::{render_processed, render_warnings};
use crate::grep;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::processor;
use crate::runtime::http::Client;
use crate::runtime::net;
use std::{fmt, io};

const HELP: &str = "\
hifi - extract internal APIs from web app bytes

USAGE:
    hifi <url> [--no-cache] [--json]
    hifi grep <url> <pattern> [-C N] [--max-hits N] [--max-bytes-per-hit N] [-a|--all]

EXAMPLES:
    hifi example.com
    hifi https://api.example.com/v2 --json
    hifi grep example.com TODO -C 2

FLAGS:
    -h, --help        show this help
        --no-cache    bypass cached scan results
        --json        print machine-readable API output

GREP FLAGS:
    -C, --context N              include N lines around each hit
        --max-hits N             cap printed hits (default: 50)
        --max-bytes-per-hit N    cap each printed snippet (default: 200)
    -a, --all                    print all hits
";

#[derive(Debug)]
pub enum AppError {
    Message(String),
    Io(io::Error),
    Net(net::NetError),
    Http(crate::runtime::http::Error),
    Runtime(crate::runtime::processor::RuntimeError),
    Url(crate::url::ParseError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Io(err) => err.fmt(f),
            Self::Net(err) => err.fmt(f),
            Self::Http(err) => err.fmt(f),
            Self::Runtime(err) => err.fmt(f),
            Self::Url(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Io(err) => Some(err),
            Self::Net(err) => Some(err),
            Self::Http(err) => Some(err),
            Self::Runtime(err) => Some(err),
            Self::Url(err) => Some(err),
        }
    }
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

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<net::NetError> for AppError {
    fn from(err: net::NetError) -> Self {
        Self::Net(err)
    }
}

impl From<crate::runtime::http::Error> for AppError {
    fn from(err: crate::runtime::http::Error) -> Self {
        Self::Http(err)
    }
}

impl From<crate::runtime::processor::RuntimeError> for AppError {
    fn from(err: crate::runtime::processor::RuntimeError) -> Self {
        Self::Runtime(err)
    }
}

impl From<crate::url::ParseError> for AppError {
    fn from(err: crate::url::ParseError) -> Self {
        Self::Url(err)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Text,
    Json,
}

#[derive(Debug)]
enum Command {
    Help,
    Grep(Vec<String>),
    Scan(ScanArgs),
}

#[derive(Debug)]
struct ScanArgs {
    url: String,
    no_cache: bool,
    mode: OutputMode,
}

pub async fn run(raw: Vec<String>) -> Result<i32, AppError> {
    match parse_command(&raw)? {
        Command::Help => {
            print!("{HELP}");
            Ok(0)
        }
        Command::Grep(args) => {
            let (config, client) = runtime_client()?;
            grep::run(&args, client, config).await
        }
        Command::Scan(args) => {
            let (config, client) = runtime_client()?;
            run_scan(args, client, config).await
        }
    }
}

fn parse_command(raw: &[String]) -> Result<Command, AppError> {
    if raw.is_empty() || matches!(raw[0].as_str(), "-h" | "--help" | "help") {
        return Ok(Command::Help);
    }
    match raw[0].as_str() {
        "grep" => Ok(Command::Grep(raw[1..].to_vec())),
        _ => parse_scan_args(raw).map(Command::Scan),
    }
}

fn parse_scan_args(raw: &[String]) -> Result<ScanArgs, AppError> {
    let mut url = None;
    let mut no_cache = false;
    let mut mode = OutputMode::Text;
    for arg in raw {
        match arg.as_str() {
            "--no-cache" => no_cache = true,
            "--json" => mode = OutputMode::Json,
            s if s.starts_with("--") || s.starts_with('-') => {
                return Err(format!("unknown flag '{s}' (try --help)").into());
            }
            _ if url.is_none() => url = Some(arg.clone()),
            _ => return Err(format!("unexpected argument '{arg}' (try --help)").into()),
        }
    }
    Ok(ScanArgs {
        url: normalize_url(&url.ok_or("missing URL (try --help)")?)?,
        no_cache,
        mode,
    })
}

async fn run_scan(args: ScanArgs, client: Client, config: RuntimeConfig) -> Result<i32, AppError> {
    let out = processor::scan_site(
        &client,
        &args.url,
        config.chunk_concurrency,
        config.allow_private,
        args.no_cache,
        std::time::Instant::now(),
    )
    .await?;
    render_processed(&out, args.mode)?;
    render_warnings(&out);
    Ok(0)
}

use crate::util::normalize_url;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scan_command_normalizes_url_and_keeps_runtime_flags() {
        let raw = args(["example.com", "--no-cache", "--json"]);

        let Command::Scan(scan) = parse_command(&raw).unwrap() else {
            panic!("expected scan command");
        };

        assert_eq!(scan.url, "https://example.com/");
        assert!(scan.no_cache);
        assert_eq!(scan.mode, OutputMode::Json);
    }

    #[test]
    fn parse_grep_before_scan() {
        let grep = parse_command(&args(["grep", "example.com", "TODO"])).unwrap();
        assert!(matches!(grep, Command::Grep(values) if values == args(["example.com", "TODO"])));
    }

    fn args<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
