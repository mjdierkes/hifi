use super::{AppError, OutputMode};
use crate::runtime::daemon;
use crate::runtime::processor::Output;
use std::io::{self, Write};

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

pub fn render_processed(out: &Output, mode: OutputMode) -> Result<(), AppError> {
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

pub fn render_daemon_reply(reply: &mut daemon::DaemonReply, mode: OutputMode) {
    if reply.exit_code == 0 {
        reply
            .stderr
            .push_str(&warning_text_from_json(&reply.stdout));
        reply.stdout = render_json_mode(&reply.stdout, mode);
    }
}

pub fn warning_text(out: &Output) -> String {
    out.warnings
        .iter()
        .map(|w| format!("hifi: warning: {w}\n"))
        .collect()
}

pub fn render_warnings(out: &Output) {
    eprint!("{}", warning_text(out));
}

fn warning_text_from_json(json: &str) -> String {
    serde_json::from_str::<Output>(json)
        .map(|out| warning_text(&out))
        .unwrap_or_default()
}

fn render_flat_output<W: Write>(v: &Output, out: &mut W) -> io::Result<()> {
    let mut rows: Vec<_> = v.evidence.iter().collect();
    rows.sort_by_key(|e| (e.kind, e.url.as_str(), e.extractor));
    for evidence in rows {
        match evidence.kind {
            crate::scan::EvidenceKind::Api => {
                let Some(shape) = &evidence.shape else {
                    continue;
                };
                writeln!(
                    out,
                    "{}\t{}\t{}\t{:?}",
                    shape.methods_csv(),
                    escape_terminal(&evidence.url),
                    shape.flags_csv(),
                    evidence.confidence
                )?;
            }
            crate::scan::EvidenceKind::Candidate => {
                writeln!(
                    out,
                    "?\t{}\t\t{:?}",
                    escape_terminal(&evidence.url),
                    evidence.confidence
                )?;
            }
            crate::scan::EvidenceKind::Route => {
                writeln!(
                    out,
                    "route\t{}\t\t{:?}",
                    escape_terminal(&evidence.url),
                    evidence.confidence
                )?;
            }
        }
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

pub fn escape_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() || ch == '\u{7f}' || is_visual_spoofing_char(ch) {
            use std::fmt::Write as _;
            let _ = write!(out, "\\u{{{:x}}}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_visual_spoofing_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
    )
}
