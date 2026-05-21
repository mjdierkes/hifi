use super::{AppError, OutputMode};
use crate::runtime::daemon;
use crate::runtime::processor::Output;
use crate::scan::{Confidence, Evidence, EvidenceKind, Shape};
use std::collections::BTreeMap;
use std::io::{self, Write};

pub fn render_json_mode(json: &str, mode: OutputMode) -> String {
    match mode {
        OutputMode::Json => {
            let mut out = String::with_capacity(json.len() + 1);
            out.push_str(json);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
        OutputMode::Flat => render_flat(json),
        OutputMode::Auto => render_grouped(json),
    }
}

pub fn render_processed(out: &Output, mode: OutputMode) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    match mode {
        OutputMode::Json => {
            serde_json::to_writer(&mut stdout, &out)?;
            stdout.write_all(b"\n")?;
        }
        OutputMode::Flat => render_flat_output(out, &mut stdout)?,
        OutputMode::Auto => render_grouped_output(out, &mut stdout)?,
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

fn render_grouped_output<W: Write>(v: &Output, out: &mut W) -> io::Result<()> {
    let api_groups = grouped_apis(v);
    if !api_groups.is_empty() {
        writeln!(out, "APIs")?;
        for (prefix, rows) in api_groups {
            writeln!(out, "{}", escape_terminal(&prefix))?;
            let method_width = rows
                .iter()
                .map(|row| row.shape.methods_csv().len())
                .max()
                .unwrap_or(0);
            for row in rows {
                let methods = row.shape.methods_csv();
                let flags = row.shape.flags_csv();
                if flags.is_empty() {
                    writeln!(
                        out,
                        "  {methods:<method_width$}  {}",
                        escape_terminal(&path_suffix(&prefix, &row.url)),
                    )?;
                } else {
                    writeln!(
                        out,
                        "  {methods:<method_width$}  {}  {}",
                        escape_terminal(&path_suffix(&prefix, &row.url)),
                        flags,
                    )?;
                }
            }
        }
    }

    render_path_groups(
        out,
        "API candidates",
        v.evidence
            .iter()
            .filter(|evidence| evidence.kind == EvidenceKind::Candidate),
        2,
    )?;
    render_path_groups(
        out,
        "Routes",
        v.evidence
            .iter()
            .filter(|evidence| evidence.kind == EvidenceKind::Route),
        1,
    )?;

    Ok(())
}

fn render_path_groups<'a, W: Write>(
    out: &mut W,
    title: &str,
    rows: impl Iterator<Item = &'a Evidence>,
    prefix_depth: usize,
) -> io::Result<()> {
    let mut rows: Vec<_> = rows.collect();
    rows.sort_by_key(|evidence| (evidence.url.as_str(), evidence.extractor));
    rows.dedup_by_key(|evidence| (evidence.url.as_str(), evidence.extractor));
    if rows.is_empty() {
        return Ok(());
    }

    writeln!(out, "{title}")?;
    let mut groups = BTreeMap::<String, Vec<&Evidence>>::new();
    for evidence in rows {
        groups
            .entry(path_prefix(&evidence.url, prefix_depth))
            .or_default()
            .push(evidence);
    }
    for (prefix, rows) in groups {
        writeln!(out, "{}", escape_terminal(&prefix))?;
        for evidence in rows {
            writeln!(
                out,
                "  {}",
                escape_terminal(&path_suffix(&prefix, &evidence.url))
            )?;
        }
    }
    Ok(())
}

struct ApiRow {
    url: String,
    shape: Shape,
    confidence: Confidence,
}

fn grouped_apis(v: &Output) -> BTreeMap<String, Vec<ApiRow>> {
    let mut rows = BTreeMap::<String, ApiRow>::new();
    for evidence in &v.evidence {
        if evidence.kind != EvidenceKind::Api {
            continue;
        }
        let Some(shape) = &evidence.shape else {
            continue;
        };
        rows.entry(evidence.url.clone())
            .and_modify(|row| {
                row.shape.merge(shape);
                row.confidence = row.confidence.min(evidence.confidence);
            })
            .or_insert_with(|| ApiRow {
                url: evidence.url.clone(),
                shape: shape.clone(),
                confidence: evidence.confidence,
            });
    }

    let mut groups = BTreeMap::<String, Vec<ApiRow>>::new();
    for row in rows.into_values() {
        groups.entry(api_prefix(&row.url)).or_default().push(row);
    }
    groups
}

fn api_prefix(url: &str) -> String {
    path_prefix(url, 2)
}

fn path_prefix(url: &str, depth: usize) -> String {
    let path = url::Url::parse(url)
        .map(|url| url.path().to_string())
        .unwrap_or_else(|_| url.split(['?', '#']).next().unwrap_or(url).to_string());
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let segments = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .take(depth)
        .collect::<Vec<_>>();

    if segments.is_empty() {
        return "/".to_string();
    }

    format!("/{}", segments.join("/"))
}

fn path_suffix(prefix: &str, url: &str) -> String {
    let path = url::Url::parse(url)
        .map(|url| {
            let mut path = url.path().to_string();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            path
        })
        .unwrap_or_else(|_| url.to_string());
    let path_no_query = path.split(['?', '#']).next().unwrap_or(&path);
    let suffix = path_no_query.strip_prefix(prefix).unwrap_or(path_no_query);
    if suffix.is_empty() {
        "(root)".to_string()
    } else {
        let mut out = suffix.to_string();
        if let Some(rest) = path.strip_prefix(path_no_query) {
            out.push_str(rest);
        }
        out
    }
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

fn render_grouped(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Output>(json) else {
        return format!("{json}\n");
    };
    let mut out = Vec::new();
    if render_grouped_output(&v, &mut out).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::processor::CacheStatus;
    use crate::scan::{Evidence, Extractor};

    #[test]
    fn auto_output_groups_human_sections_and_merges_api_shapes() {
        let out = Output {
            evidence: vec![
                Evidence {
                    url: "/dashboard".to_string(),
                    kind: EvidenceKind::Route,
                    extractor: Extractor::Manifest,
                    confidence: Confidence::Parsed,
                    shape: None,
                },
                Evidence {
                    url: "/api/users".to_string(),
                    kind: EvidenceKind::Api,
                    extractor: Extractor::ApiCall,
                    confidence: Confidence::Observed,
                    shape: Some(test_shape(1, false, false)),
                },
                Evidence {
                    url: "/api/users".to_string(),
                    kind: EvidenceKind::Api,
                    extractor: Extractor::ServerAction,
                    confidence: Confidence::Inferred,
                    shape: Some(test_shape(2, true, true)),
                },
                Evidence {
                    url: "/api/users/{dynamic}".to_string(),
                    kind: EvidenceKind::Api,
                    extractor: Extractor::ApiCall,
                    confidence: Confidence::Observed,
                    shape: Some(test_shape(1, false, false)),
                },
                Evidence {
                    url: "/api/admin/settings".to_string(),
                    kind: EvidenceKind::Api,
                    extractor: Extractor::ApiCall,
                    confidence: Confidence::Observed,
                    shape: Some(test_shape(4, true, false)),
                },
                Evidence {
                    url: "/api/team/{dynamic}".to_string(),
                    kind: EvidenceKind::Candidate,
                    extractor: Extractor::Literal,
                    confidence: Confidence::Candidate,
                    shape: None,
                },
                Evidence {
                    url: "/dashboard/stats".to_string(),
                    kind: EvidenceKind::Route,
                    extractor: Extractor::Manifest,
                    confidence: Confidence::Parsed,
                    shape: None,
                },
            ],
            revision: None,
            cache: CacheStatus::Miss,
            cache_age_secs: None,
            elapsed_us: None,
            warnings: Vec::new(),
        };

        let mut rendered = Vec::new();
        render_grouped_output(&out, &mut rendered).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();

        assert_eq!(
            rendered,
            "APIs\n/api/admin\n  PUT  /settings  body\n/api/users\n  GET,POST  (root)  body,next-action\n  GET       /{dynamic}\nAPI candidates\n/api/team\n  /{dynamic}\nRoutes\n/dashboard\n  (root)\n  /stats\n"
        );
    }

    fn test_shape(methods: u8, has_body: bool, next_server_action: bool) -> Shape {
        serde_json::from_str(&format!(
            r#"{{"methods":{methods},"has_body":{has_body},"has_headers":false,"content_types":0,"auth":false,"query_params":[],"next_server_action":{next_server_action}}}"#
        ))
        .unwrap()
    }
}
