use super::{AppError, OutputMode};
use crate::runtime::processor::Output;
use crate::scan::{EvidenceKind, Shape};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Write};

pub fn render_processed(out: &Output, mode: OutputMode) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    match mode {
        OutputMode::Text => render_api_text(out, &mut stdout)?,
        OutputMode::Json => render_api_json(out, &mut stdout)?,
    }
    Ok(())
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

fn render_api_text<W: Write>(out: &Output, writer: &mut W) -> io::Result<()> {
    for row in collect_apis(out) {
        if row.flags.is_empty() {
            writeln!(writer, "{}\t{}", row.methods, escape_terminal(&row.path))?;
        } else {
            writeln!(
                writer,
                "{}\t{}\t{}",
                row.methods,
                escape_terminal(&row.path),
                row.flags
            )?;
        }
    }
    Ok(())
}

fn render_api_json<W: Write>(out: &Output, writer: &mut W) -> io::Result<()> {
    let apis = collect_apis(out);
    let mut body = String::new();
    body.push_str("{\"apis\":[");
    for (i, row) in apis.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str("{\"path\":");
        push_json_string(&mut body, &row.path);
        body.push_str(",\"methods\":");
        push_json_array(&mut body, row.methods.split(',').filter(|s| !s.is_empty()));
        let flags = row.flags.split(',').filter(|s| !s.is_empty());
        body.push_str(",\"flags\":");
        push_json_array(&mut body, flags);
        body.push('}');
    }
    body.push_str("],\"warnings\":");
    push_json_array(&mut body, out.warnings.iter().map(String::as_str));
    body.push_str("}\n");
    writer.write_all(body.as_bytes())
}

struct ApiRow {
    path: String,
    methods: String,
    flags: String,
}

fn collect_apis(out: &Output) -> Vec<ApiRow> {
    let mut merged = BTreeMap::<String, Shape>::new();
    for evidence in &out.evidence {
        if evidence.kind != EvidenceKind::Api {
            continue;
        }
        let Some(shape) = &evidence.shape else {
            continue;
        };
        merged
            .entry(prettify(&normalize_path(&evidence.url)))
            .and_modify(|existing| existing.merge(shape))
            .or_insert_with(|| shape.clone());
    }
    let mut rows: Vec<ApiRow> = merged
        .into_iter()
        .map(|(path, shape)| ApiRow {
            path,
            methods: shape.methods_csv(),
            flags: shape.flags_csv(),
        })
        .collect();
    rows.sort_by(|a, b| a.path.cmp(&b.path).then(a.methods.cmp(&b.methods)));
    rows
}

fn normalize_path(url: &str) -> String {
    let raw = crate::url::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.split(['?', '#']).next().unwrap_or(url).to_string());
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn prettify(path: &str) -> String {
    path.replace("{dynamic}", ":id")
}

fn push_json_array<'a>(out: &mut String, values: impl Iterator<Item = &'a str>) {
    out.push('[');
    for (i, value) in values.enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_string(out, value);
    }
    out.push(']');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if ch <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub fn escape_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() || ch == '\u{7f}' || is_visual_spoofing_char(ch) {
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
    use crate::runtime::processor::{CacheStatus, Output};
    use crate::scan::{Confidence, Evidence, Extractor};

    #[test]
    fn text_output_is_api_only() {
        let out = fixture();
        let mut rendered = Vec::new();

        render_api_text(&out, &mut rendered).unwrap();

        let rendered = String::from_utf8(rendered).unwrap();
        assert_eq!(
            rendered,
            "GET\t/api/users\tquery\nPOST\t/v1/login\tbody,headers,json\n"
        );
    }

    #[test]
    fn json_output_is_api_only() {
        let out = fixture();
        let mut rendered = Vec::new();

        render_api_json(&out, &mut rendered).unwrap();

        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("\"apis\":["));
        assert!(rendered.contains("\"path\":\"/api/users\""));
        assert!(!rendered.contains("/dashboard"));
        assert!(!rendered.contains("/api/maybe"));
    }

    fn fixture() -> Output {
        Output {
            evidence: vec![
                api("/api/users?team=1", Shape::inferred(Some("GET"), false)),
                api("/v1/login", {
                    let mut shape = Shape::inferred(Some("POST"), true);
                    shape.merge(&shape_with_json());
                    shape
                }),
                Evidence {
                    url: "/dashboard".to_string(),
                    kind: EvidenceKind::Route,
                    extractor: Extractor::Literal,
                    confidence: Confidence::Candidate,
                    shape: None,
                },
                Evidence {
                    url: "/api/maybe".to_string(),
                    kind: EvidenceKind::Candidate,
                    extractor: Extractor::Literal,
                    confidence: Confidence::Candidate,
                    shape: None,
                },
            ],
            revision: None,
            framework: Default::default(),
            cache: CacheStatus::Miss,
            cache_age_secs: None,
            elapsed_us: None,
            warnings: Vec::new(),
        }
    }

    fn api(url: &str, mut shape: Shape) -> Evidence {
        shape.apply_query_params(url);
        Evidence {
            url: url.to_string(),
            kind: EvidenceKind::Api,
            extractor: Extractor::ApiCall,
            confidence: Confidence::Observed,
            shape: Some(shape),
        }
    }

    fn shape_with_json() -> Shape {
        let mut shape = Shape::default();
        let parsed = crate::scan::scan_endpoints(
            br#"fetch("/x",{method:"POST",headers:{"content-type":"application/json"},body:"{}"})"#,
        );
        if let Some(found) = parsed.evidence.first().and_then(|e| e.shape.clone()) {
            shape.merge(&found);
        }
        shape
    }
}
