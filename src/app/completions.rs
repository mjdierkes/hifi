use super::AppError;
use crate::runtime::cache;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            _ => None,
        }
    }
}

pub fn parse_completions(rest: &[String]) -> Result<Shell, AppError> {
    let shell = rest
        .first()
        .ok_or("completions requires a shell (bash, zsh, or fish)")?;
    if rest.len() > 1 {
        return Err(format!("unexpected argument '{}' (try --help)", rest[1]).into());
    }
    Shell::parse(shell)
        .ok_or_else(|| format!("unsupported shell '{shell}' (use bash, zsh, or fish)").into())
}

pub fn parse_install(rest: &[String]) -> Result<Option<Shell>, AppError> {
    if rest.is_empty() {
        return Ok(None);
    }
    if rest.len() > 1 {
        return Err(format!("unexpected argument '{}' (try --help)", rest[1]).into());
    }
    Shell::parse(&rest[0])
        .map(Some)
        .ok_or_else(|| format!("unsupported shell '{}' (use bash, zsh, or fish)", rest[0]).into())
}

pub fn print_host_completions(prefix: &str) {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    for host in cache::cached_hosts() {
        if host.starts_with(prefix) {
            let _ = writeln!(stdout, "{host}");
        }
    }
}

// Suggest paths for the second positional arg by reading the cached scan
// output for `url`. We surface both top-level resource prefixes (e.g.
// `/machines`) and every concrete route, so the user can `<Tab>` through to
// any nested path.
pub fn print_path_completions(url: &str, prefix: &str) {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    let Some((parsed, candidates, should_persist)) = cached_completion_candidates(url) else {
        return;
    };
    for path in &candidates {
        if path.starts_with(prefix) {
            let _ = writeln!(stdout, "{path}");
        }
    }
    if should_persist {
        cache::write_completion_candidates(&parsed, &candidates);
    }
}

fn cached_completion_candidates(url: &str) -> Option<(crate::url::Url, Vec<String>, bool)> {
    let parsed = normalized_url(url)?;
    if let Some(candidates) = cache::read_completion_candidates(&parsed) {
        return Some((parsed, candidates, false));
    }
    let paths = cached_paths(&parsed)?;
    Some((parsed, path_completion_candidates(&paths), true))
}

// Read every cached scan we have for the host (the cache path is keyed by
// build hash, so a rebuild orphans the previous file — for completion we just
// want any recent surface, so union them all).
fn cached_paths(parsed: &crate::url::Url) -> Option<Vec<String>> {
    let primary = cache::path_for(parsed).with_extension("bin");
    let host_dir = primary.parent()?;

    let mut paths = Vec::new();
    let entries = fs::read_dir(host_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Some(output) = crate::runtime::processor::decode_output_binary(&bytes) else {
            continue;
        };
        for evidence in output.evidence {
            if matches!(
                evidence.kind,
                crate::scan::EvidenceKind::Route | crate::scan::EvidenceKind::Api
            ) {
                paths.push(evidence.url);
            }
        }
    }
    if paths.is_empty() {
        return None;
    }
    Some(paths)
}

fn normalized_url(url: &str) -> Option<crate::url::Url> {
    let normalized = super::normalize_url(url).ok()?;
    crate::url::Url::parse(&normalized).ok()
}

fn path_completion_candidates(paths: &[String]) -> Vec<String> {
    let mut set = std::collections::BTreeSet::<String>::new();
    for raw in paths {
        let path = normalize_completion_path(raw);
        if path.is_empty() {
            continue;
        }
        set.insert(path.clone());
        // Also offer every parent prefix so `/account/me/<Tab>` works even
        // when `/account` isn't itself a recorded route.
        let mut current = path.as_str();
        while let Some(idx) = current.rfind('/') {
            let parent = &current[..idx];
            if parent.is_empty() {
                break;
            }
            set.insert(parent.to_string());
            current = parent;
        }
    }
    set.into_iter().collect()
}

fn normalize_completion_path(raw: &str) -> String {
    let raw = raw.split(['?', '#']).next().unwrap_or(raw);
    let path = crate::url::Url::parse(raw)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| raw.to_string());
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let trimmed = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    trimmed.replace("{dynamic}", ":id")
}

pub fn completion_script(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => BASH_COMPLETION,
        Shell::Zsh => ZSH_COMPLETION,
        Shell::Fish => FISH_COMPLETION,
    }
}

pub fn install_completions(shell: Option<Shell>) -> Result<i32, AppError> {
    let shell = match shell.or_else(detect_shell) {
        Some(s) => s,
        None => {
            return Err(
                "could not detect shell; pass one explicitly: hifi install <bash|zsh|fish>".into(),
            )
        }
    };
    let home = home_dir().ok_or("could not locate $HOME")?;
    match shell {
        Shell::Fish => install_fish(&home),
        Shell::Zsh => install_zsh(&home),
        Shell::Bash => install_bash(&home),
    }
}

fn detect_shell() -> Option<Shell> {
    let shell = std::env::var("SHELL").ok()?;
    let name = Path::new(&shell).file_name()?.to_str()?;
    match name {
        n if n.ends_with("zsh") => Some(Shell::Zsh),
        n if n.ends_with("bash") => Some(Shell::Bash),
        n if n.ends_with("fish") => Some(Shell::Fish),
        _ => None,
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// Fish autoloads any file in ~/.config/fish/completions/, so we only need to
// drop the script there.
fn install_fish(home: &Path) -> Result<i32, AppError> {
    let dir = home.join(".config/fish/completions");
    fs::create_dir_all(&dir)?;
    let path = dir.join("hifi.fish");
    fs::write(&path, FISH_COMPLETION)?;
    println!("installed fish completions: {}", path.display());
    println!(
        "open a new shell (or run `source {}`) to use them.",
        path.display()
    );
    Ok(0)
}

// Zsh needs the completion file on $fpath and `compinit` to have been called.
// We write to ~/.zsh/completions/_hifi and ensure ~/.zshrc adds that directory
// to $fpath and initialises compinit. The marker prevents duplicate appends if
// `install` is run again.
fn install_zsh(home: &Path) -> Result<i32, AppError> {
    let dir = home.join(".zsh/completions");
    fs::create_dir_all(&dir)?;
    let path = dir.join("_hifi");
    fs::write(&path, ZSH_COMPLETION)?;

    let zshrc = home.join(".zshrc");
    let marker = "# >>> hifi completions >>>";
    let block = format!(
        "{marker}\nfpath=(\"$HOME/.zsh/completions\" $fpath)\nautoload -Uz compinit && compinit\n# <<< hifi completions <<<\n"
    );
    let appended = append_block_if_missing(&zshrc, marker, &block)?;
    println!("installed zsh completions: {}", path.display());
    if appended {
        println!(
            "updated {} to load completions on startup.",
            zshrc.display()
        );
    }
    println!("open a new shell to use them.");
    Ok(0)
}

fn install_bash(home: &Path) -> Result<i32, AppError> {
    let dir = home.join(".local/share/bash-completion/completions");
    fs::create_dir_all(&dir)?;
    let path = dir.join("hifi");
    fs::write(&path, BASH_COMPLETION)?;

    // Source the file directly from ~/.bashrc so users without the
    // bash-completion package still get completions.
    let bashrc = home.join(".bashrc");
    let marker = "# >>> hifi completions >>>";
    let block = format!(
        "{marker}\n[ -r \"$HOME/.local/share/bash-completion/completions/hifi\" ] && \\\n    source \"$HOME/.local/share/bash-completion/completions/hifi\"\n# <<< hifi completions <<<\n"
    );
    let appended = append_block_if_missing(&bashrc, marker, &block)?;
    println!("installed bash completions: {}", path.display());
    if appended {
        println!(
            "updated {} to load completions on startup.",
            bashrc.display()
        );
    }
    println!("open a new shell to use them.");
    Ok(0)
}

fn append_block_if_missing(rc: &Path, marker: &str, block: &str) -> io::Result<bool> {
    let existing = fs::read_to_string(rc).unwrap_or_default();
    if existing.contains(marker) {
        return Ok(false);
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push('\n');
    content.push_str(block);
    fs::write(rc, content)?;
    Ok(true)
}

const BASH_COMPLETION: &str = r#"__hifi_cache_dir() {
    if [[ -n "${HIFI_CACHE_DIR-}" ]]; then
        printf '%s' "${HIFI_CACHE_DIR}"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        printf '%s' "${HOME}/Library/Caches/hifi"
    else
        printf '%s' "${XDG_CACHE_HOME:-${HOME}/.cache}/hifi"
    fi
}

__hifi_hosts() {
    local dir host seen
    declare -A seen
    local cache_dir
    cache_dir=$(__hifi_cache_dir)
    for kind in processed assets; do
        [[ -d "${cache_dir}/${kind}" ]] || continue
        for dir in "${cache_dir}/${kind}"/*/; do
            [[ -d "${dir}" ]] || continue
            host="${dir%/}"
            host="${host##*/}"
            [[ -z "${host}" || "${host}" == "unknown" ]] && continue
            if [[ -z "${seen[$host]-}" ]]; then
                seen[$host]=1
                printf '%s\n' "${host}"
            fi
        done
    done
}

_hifi() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local cword=${COMP_CWORD}
    local subcommands="grep serve completions install help"
    local flags="--routes -r --all -a --no-cache --no-daemon --flat --json -h --help"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
        return
    fi

    if [[ ${cword} -eq 1 ]]; then
        local hosts
        hosts=$(__hifi_hosts)
        COMPREPLY=( $(compgen -W "${subcommands} ${hosts}" -- "${cur}") )
        return
    fi

    case "${COMP_WORDS[1]}" in
        completions|install)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return
            ;;
        grep)
            if [[ ${cword} -eq 2 ]]; then
                local hosts
                hosts=$(__hifi_hosts)
                COMPREPLY=( $(compgen -W "${hosts}" -- "${cur}") )
                return
            fi
            ;;
    esac

    if [[ ${cword} -eq 2 && "${cur}" != -* ]]; then
        local paths
        paths=$(hifi __complete-paths "${COMP_WORDS[1]}" "${cur}" 2>/dev/null)
        if [[ -n "${paths}" ]]; then
            COMPREPLY=( $(compgen -W "${paths}" -- "${cur}") )
            return
        fi
    fi

    COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
}
complete -F _hifi hifi
"#;

const ZSH_COMPLETION: &str = r#"#compdef hifi
__hifi_cache_dir() {
    if [[ -n "${HIFI_CACHE_DIR-}" ]]; then
        print -r -- "${HIFI_CACHE_DIR}"
    elif [[ "$OSTYPE" == darwin* ]]; then
        print -r -- "${HOME}/Library/Caches/hifi"
    else
        print -r -- "${XDG_CACHE_HOME:-${HOME}/.cache}/hifi"
    fi
}

__hifi_hosts() {
    local cache_dir
    cache_dir=$(__hifi_cache_dir)
    local -a entries
    entries=(${cache_dir}/processed/*(/N:t) ${cache_dir}/assets/*(/N:t))
    print -rl -- ${(u)entries:#unknown}
}

_hifi() {
    local -a hosts paths subs
    subs=(grep serve completions install help)
    if [[ "${words[CURRENT]}" == -* ]]; then
        _arguments '*:flag:(--routes -r --all -a --no-cache --no-daemon --flat --json -h --help)'
        return
    fi
    if (( CURRENT == 2 )); then
        hosts=("${(@f)$(__hifi_hosts)}")
        _describe -t commands 'command' subs
        _describe -t hosts 'cached host' hosts
        return
    fi
    case "${words[2]}" in
        completions|install)
            _values 'shell' bash zsh fish
            return
            ;;
        grep)
            if (( CURRENT == 3 )); then
                hosts=("${(@f)$(__hifi_hosts)}")
                _describe -t hosts 'cached host' hosts
                return
            fi
            ;;
    esac
    if (( CURRENT == 3 )) && [[ "${words[CURRENT]}" != -* ]]; then
        paths=("${(@f)$(hifi __complete-paths "${words[2]}" "${words[CURRENT]}" 2>/dev/null)}")
        if (( ${#paths[@]} > 0 )) && [[ -n "${paths[1]}" ]]; then
            _describe -t paths 'cached route' paths
            return
        fi
    fi
    _arguments '*:flag:(--routes -r --all -a --no-cache --no-daemon --flat --json -h --help)'
}
zstyle ':completion:*:*:hifi:*' menu select
compdef _hifi hifi
"#;

const FISH_COMPLETION: &str = r#"function __hifi_cache_dir
    if set -q HIFI_CACHE_DIR
        echo $HIFI_CACHE_DIR
    else if test (uname -s) = Darwin
        echo $HOME/Library/Caches/hifi
    else if set -q XDG_CACHE_HOME
        echo $XDG_CACHE_HOME/hifi
    else
        echo $HOME/.cache/hifi
    end
end

function __hifi_hosts
    set -l cache_dir (__hifi_cache_dir)
    set -l hosts
    for kind in processed assets
        if test -d $cache_dir/$kind
            for dir in $cache_dir/$kind/*/
                set -l name (basename $dir)
                if test -n "$name" -a "$name" != unknown
                    set -a hosts $name
                end
            end
        end
    end
    printf '%s\n' $hosts | sort -u
end

function __hifi_host_position
    set -l token (commandline -ct)
    if string match -q -- '-*' $token
        return 1
    end
    for cmd in grep serve completions install help
        if string match -q -- "$token*" $cmd
            return 1
        end
    end
    __fish_use_subcommand
end

function __hifi_paths
    set -l token (commandline -ct)
    if string match -q -- '-*' $token
        return 1
    end
    set -l tokens (commandline -opc)
    if test (count $tokens) -ge 2
        hifi __complete-paths $tokens[2] (commandline -ct) 2>/dev/null
    end
end

complete -c hifi -f
complete -c hifi -n '__hifi_host_position' -a '(__hifi_hosts)' -d 'cached host'
complete -c hifi -n '__fish_use_subcommand' -a 'grep' -d 'grep a URL'
complete -c hifi -n '__fish_use_subcommand' -a 'serve' -d 'run the daemon'
complete -c hifi -n '__fish_use_subcommand' -a 'completions' -d 'print shell completions'
complete -c hifi -n '__fish_use_subcommand' -a 'install' -d 'install tab completions'
complete -c hifi -n '__fish_use_subcommand' -a 'help' -d 'show help'
complete -c hifi -n '__fish_seen_subcommand_from grep' -a '(__hifi_hosts)' -d 'cached host'
complete -c hifi -n '__fish_seen_subcommand_from completions install' -a 'bash zsh fish'
complete -c hifi -n 'not __fish_use_subcommand; and not __fish_seen_subcommand_from grep serve completions install help' -a '(__hifi_paths)' -d 'cached route'
complete -c hifi -s r -l routes -d 'expand the route summary into a full path list'
complete -c hifi -s a -l all -d 'include internal/framework routes'
complete -c hifi -l no-cache -d 'bypass cached results'
complete -c hifi -l no-daemon -d 'skip the background daemon'
complete -c hifi -l flat -d 'tab-separated output'
complete -c hifi -l json -d 'JSON output'
complete -c hifi -s h -l help -d 'show help'
"#;
