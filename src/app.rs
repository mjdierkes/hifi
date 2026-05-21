//! CLI boundary for hifi.
//!
//! This module keeps command parsing, daemon selection, and output rendering
//! separate from the scanner/runtime code. That gives the rest of the crate a
//! typed request to execute instead of leaking argv shape through the system.

use crate::grep;
use crate::runtime::cache;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::daemon;
use crate::runtime::net;
use crate::runtime::processor::{CacheContext, Output, Processor, CACHE_FRESH_SECS};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use std::io::{self, Write};
use std::time::Duration;
use thiserror::Error;

// Many CDNs (notably Cloudflare) block obvious bot UAs with 403 before we ever
// see the page. hifi crawls publicly-served content the way a browser does, so
// presenting as one removes a class of "site unreachable" failures.
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const HELP: &str = "\
hifi — map an HTTP API surface

USAGE:
    hifi <url> [--no-cache] [--no-daemon] [--flat|--json]
    hifi grep <url> <pattern> [-C N] [--max-hits N] [--max-bytes-per-hit N] [-a|--all]
    hifi serve
    hifi completions <bash|zsh|fish>

EXAMPLES:
    hifi example.com
    hifi https://api.example.com/v2
    hifi grep example.com TODO -C 2

FLAGS:
    -h, --help        show this help
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
    Tab-complete cached hosts. Install with:
        bash:  eval \"$(hifi completions bash)\"
        zsh:   eval \"$(hifi completions zsh)\"
        fish:  hifi completions fish | source
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
    Reqwest(#[from] reqwest::Error),
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
    CompleteHosts(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

// Keep CLI state explicit. The scanner should not need to know whether a scan
// came from argv, a daemon request, or a future library caller.
#[derive(Debug)]
struct ScanArgs {
    url: String,
    no_cache: bool,
    no_daemon: bool,
    mode: OutputMode,
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
        Command::CompleteHosts(prefix) => {
            print_host_completions(&prefix);
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
        "__complete" => Ok(Command::CompleteHosts(
            raw.get(1).cloned().unwrap_or_default(),
        )),
        _ => parse_scan_args(raw).map(Command::Scan),
    }
}

fn parse_scan_args(raw: &[String]) -> Result<ScanArgs, AppError> {
    let mut url = None;
    let (mut no_cache, mut no_daemon) = (false, false);
    let mut mode = OutputMode::Auto;
    for arg in raw {
        match arg.as_str() {
            "--no-cache" => no_cache = true,
            "--no-daemon" => no_daemon = true,
            "--flat" => mode = set_mode(mode, OutputMode::Flat)?,
            "--json" => mode = set_mode(mode, OutputMode::Json)?,
            s if s.starts_with("--") || s.starts_with('-') => {
                return Err(format!("unknown flag '{s}' (try --help)").into());
            }
            _ if url.is_none() => url = Some(arg.clone()),
            _ => return Err(format!("unexpected argument '{arg}' (try --help)").into()),
        }
    }
    let url = url.ok_or("missing URL (try --help)")?;
    let url = normalize_url(&url)?;

    Ok(ScanArgs {
        url,
        no_cache,
        no_daemon,
        mode,
    })
}

fn runtime_client() -> Result<(RuntimeConfig, Client), AppError> {
    let config = RuntimeConfig::from_env();
    let client = make_client(config)?;
    Ok((config, client))
}

async fn run_scan(args: ScanArgs, client: Client, config: RuntimeConfig) -> Result<i32, AppError> {
    if !args.no_daemon {
        if let Some(reply) = daemon_output(&args.url, args.no_cache, args.mode).await {
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
    render_processed(&out, args.mode)?;
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

pub fn render_json_mode(json: &str, mode: OutputMode) -> String {
    match mode.for_stdout() {
        OutputMode::Json => {
            let mut out = String::with_capacity(json.len() + 1);
            out.push_str(json);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
        OutputMode::Flat | OutputMode::Auto => render_flat(json),
    }
}

fn render_processed(out: &Output, mode: OutputMode) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    match mode.for_stdout() {
        OutputMode::Json => {
            serde_json::to_writer(&mut stdout, &out)?;
            stdout.write_all(b"\n")?;
        }
        OutputMode::Flat | OutputMode::Auto => render_flat_output(out, &mut stdout)?,
    }
    Ok(())
}

pub fn warning_text(out: &Output) -> String {
    out.warnings
        .iter()
        .map(|w| format!("hifi: warning: {w}\n"))
        .collect()
}

pub fn warning_text_from_json(json: &str) -> String {
    serde_json::from_str::<Output>(json)
        .map(|out| warning_text(&out))
        .unwrap_or_default()
}

fn render_warnings(out: &Output) {
    eprint!("{}", warning_text(out));
}

fn render_flat_output<W: Write>(v: &Output, out: &mut W) -> io::Result<()> {
    let mut keys: Vec<&String> = v.apis.keys().collect();
    keys.sort_unstable();
    for k in keys {
        let shape = &v.apis[k];
        writeln!(
            out,
            "{}\t{}\t{}",
            shape.methods_csv(),
            escape_terminal(k),
            shape.flags_csv()
        )?;
    }
    let mut keys: Vec<&String> = v.candidates.keys().collect();
    keys.sort_unstable();
    for k in keys {
        writeln!(out, "?\t{}\t", escape_terminal(k))?;
    }
    let mut keys: Vec<&String> = v.routes.keys().collect();
    keys.sort_unstable();
    for k in keys {
        writeln!(out, "route\t{}\t", escape_terminal(k))?;
    }
    Ok(())
}

fn render_flat(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Output>(json) else {
        return format!("{json}\n");
    };
    let mut out = Vec::new();
    if render_flat_output(&v, &mut out).is_err() {
        return format!("{json}\n");
    }
    String::from_utf8(out).unwrap_or_else(|_| format!("{json}\n"))
}

async fn daemon_output(url: &str, no_cache: bool, mode: OutputMode) -> Option<daemon::DaemonReply> {
    match daemon::request(url, no_cache).await {
        daemon::DaemonRequest::Reply(mut out) => {
            render_daemon_reply(&mut out, mode);
            return Some(out);
        }
        daemon::DaemonRequest::StaleDaemon | daemon::DaemonRequest::Unavailable => {}
    }
    if daemon::start() {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(25));
            match daemon::request(url, no_cache).await {
                daemon::DaemonRequest::Reply(mut out) => {
                    render_daemon_reply(&mut out, mode);
                    return Some(out);
                }
                daemon::DaemonRequest::StaleDaemon | daemon::DaemonRequest::Unavailable => {}
            }
        }
    }
    None
}

fn render_daemon_reply(reply: &mut daemon::DaemonReply, mode: OutputMode) {
    if reply.exit_code == 0 {
        reply
            .stderr
            .push_str(&warning_text_from_json(&reply.stdout));
        reply.stdout = render_json_mode(&reply.stdout, mode);
    }
}

fn make_client(config: RuntimeConfig) -> reqwest::Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(config.chunk_concurrency)
        .pool_idle_timeout(Duration::from_secs(CACHE_FRESH_SECS))
        .tcp_keepalive(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if net::validate_url(attempt.url(), config.allow_private).is_ok() {
                attempt.follow()
            } else {
                attempt.error("blocked redirect to private or unsupported URL")
            }
        }))
        .user_agent(DEFAULT_USER_AGENT)
        .default_headers(browser_default_headers())
        .build()
}

// Cloudflare bot-management 403s any request that looks programmatic — UA alone
// isn't enough. Real browsers always send Accept, Accept-Language, and the
// Sec-Fetch-* hints; sending the same set lets us through without TLS
// fingerprinting tricks. Sec-Fetch-Dest is left as "document" for all requests
// because the alternative (per-asset variation) buys us nothing past the root.
fn browser_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,\
             image/avif,image/webp,*/*;q=0.8",
        ),
    );
    headers.insert(
        reqwest::header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    headers.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
    headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
    headers.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
    headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
    headers.insert(
        "Upgrade-Insecure-Requests",
        HeaderValue::from_static("1"),
    );
    headers
}

pub fn escape_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() || ch == '\u{7f}' {
            use std::fmt::Write as _;
            let _ = write!(out, "\\x{:02x}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_completions(rest: &[String]) -> Result<Shell, AppError> {
    let shell = rest
        .first()
        .ok_or("completions requires a shell (bash, zsh, or fish)")?;
    if rest.len() > 1 {
        return Err(format!("unexpected argument '{}' (try --help)", rest[1]).into());
    }
    match shell.as_str() {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        other => Err(format!("unsupported shell '{other}' (use bash, zsh, or fish)").into()),
    }
}

fn print_host_completions(prefix: &str) {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    for host in cache::cached_hosts() {
        if host.starts_with(prefix) {
            let _ = writeln!(stdout, "{host}");
        }
    }
}

fn completion_script(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => BASH_COMPLETION,
        Shell::Zsh => ZSH_COMPLETION,
        Shell::Fish => FISH_COMPLETION,
    }
}

const BASH_COMPLETION: &str = r#"_hifi() {
    local cur prev words cword
    _init_completion || return
    local subcommands="grep serve completions help"
    local flags="--no-cache --no-daemon --flat --json -h --help"

    if [[ ${cword} -eq 1 ]]; then
        local hosts
        hosts=$(hifi __complete "${cur}" 2>/dev/null)
        COMPREPLY=( $(compgen -W "${hosts} ${subcommands}" -- "${cur}") )
        return
    fi

    case "${words[1]}" in
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return
            ;;
        grep)
            if [[ ${cword} -eq 2 ]]; then
                local hosts
                hosts=$(hifi __complete "${cur}" 2>/dev/null)
                COMPREPLY=( $(compgen -W "${hosts}" -- "${cur}") )
                return
            fi
            ;;
    esac

    COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
}
complete -F _hifi hifi
"#;

const ZSH_COMPLETION: &str = r#"#compdef hifi
_hifi() {
    local -a hosts subs
    subs=(grep serve completions help)
    if (( CURRENT == 2 )); then
        hosts=("${(@f)$(hifi __complete "${words[CURRENT]}" 2>/dev/null)}")
        _describe -t hosts 'cached host' hosts
        _describe -t commands 'command' subs
        _arguments '*:flag:(--no-cache --no-daemon --flat --json -h --help)'
        return
    fi
    case "${words[2]}" in
        completions)
            _values 'shell' bash zsh fish
            return
            ;;
        grep)
            if (( CURRENT == 3 )); then
                hosts=("${(@f)$(hifi __complete "${words[CURRENT]}" 2>/dev/null)}")
                _describe -t hosts 'cached host' hosts
                return
            fi
            ;;
    esac
    _arguments '*:flag:(--no-cache --no-daemon --flat --json -h --help)'
}
compdef _hifi hifi
"#;

const FISH_COMPLETION: &str = r#"function __hifi_hosts
    hifi __complete (commandline -ct) 2>/dev/null
end

complete -c hifi -f
complete -c hifi -n '__fish_use_subcommand' -a '(__hifi_hosts)' -d 'cached host'
complete -c hifi -n '__fish_use_subcommand' -a 'grep' -d 'grep a URL'
complete -c hifi -n '__fish_use_subcommand' -a 'serve' -d 'run the daemon'
complete -c hifi -n '__fish_use_subcommand' -a 'completions' -d 'print shell completions'
complete -c hifi -n '__fish_use_subcommand' -a 'help' -d 'show help'
complete -c hifi -n '__fish_seen_subcommand_from grep' -a '(__hifi_hosts)' -d 'cached host'
complete -c hifi -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
complete -c hifi -l no-cache -d 'bypass cached results'
complete -c hifi -l no-daemon -d 'skip the background daemon'
complete -c hifi -l flat -d 'tab-separated output'
complete -c hifi -l json -d 'JSON output'
complete -c hifi -s h -l help -d 'show help'
"#;

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
