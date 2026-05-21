use super::AppError;
use crate::runtime::cache;
use std::io::{self, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

pub fn parse_completions(rest: &[String]) -> Result<Shell, AppError> {
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

pub fn print_host_completions(prefix: &str) {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    for host in cache::cached_hosts() {
        if host.starts_with(prefix) {
            let _ = writeln!(stdout, "{host}");
        }
    }
}

pub fn completion_script(shell: Shell) -> &'static str {
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
