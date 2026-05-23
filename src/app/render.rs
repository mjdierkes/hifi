use super::{AppError, OutputMode};
use crate::runtime::processor::Output;
use crate::util::escape_terminal;
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

fn warning_text(out: &Output) -> String {
    out.warnings
        .iter()
        .map(|w| format!("hifi: warning: {w}\n"))
        .collect()
}

pub fn render_warnings(out: &Output) {
    eprint!("{}", warning_text(out));
}

fn stats_line(out: &Output) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(us) = out.elapsed_us {
        parts.push(format_duration_us(us));
    }
    let cache = match out.cache {
        crate::runtime::processor::CacheStatus::Fresh => "fresh",
        crate::runtime::processor::CacheStatus::RevisionHit => "revision-hit",
        crate::runtime::processor::CacheStatus::Stored => "stored",
        crate::runtime::processor::CacheStatus::Miss => "miss",
    };
    if let Some(age) = out.cache_age_secs {
        parts.push(format!("cache={cache}({age}s)"));
    } else {
        parts.push(format!("cache={cache}"));
    }
    parts.push(format!("apis={}", out.apis.len()));
    parts.join("  ")
}

fn format_duration_us(us: u128) -> String {
    if us < 1_000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

fn render_api_text<W: Write>(out: &Output, writer: &mut W) -> io::Result<()> {
    writeln!(writer, "# {}", stats_line(out))?;

    let groups = group_apis(&out.apis);
    for (gi, group) in groups.iter().enumerate() {
        if gi > 0 {
            writeln!(writer)?;
        }
        let label_width = group
            .rows
            .iter()
            .map(|r| r.label.chars().count())
            .max()
            .unwrap_or(0);
        let method_width = group
            .rows
            .iter()
            .map(|r| r.methods.chars().count())
            .max()
            .unwrap_or(0);
        for row in &group.rows {
            write!(writer, "{}", row.label)?;
            if !row.methods.is_empty() || !row.flags.is_empty() {
                let pad = label_width.saturating_sub(row.label.chars().count());
                write!(writer, "{}  {}", " ".repeat(pad), row.methods)?;
            }
            if !row.flags.is_empty() {
                let mpad = method_width.saturating_sub(row.methods.chars().count());
                write!(writer, "{}  · {}", " ".repeat(mpad), row.flags)?;
            }
            writeln!(writer)?;
        }
    }
    Ok(())
}

struct Group {
    rows: Vec<Row>,
}

struct Row {
    label: String,
    methods: String,
    flags: String,
}

fn group_apis(apis: &[crate::runtime::processor::Api]) -> Vec<Group> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<&crate::runtime::processor::Api>> = BTreeMap::new();
    for api in apis {
        let prefix = first_segment(&api.path);
        groups.entry(prefix).or_default().push(api);
    }
    groups
        .into_iter()
        .map(|(prefix, mut items)| {
            items.sort_by(|a, b| a.path.cmp(&b.path));
            let mut rows = Vec::with_capacity(items.len());
            let root_idx = items.iter().position(|api| api.path == prefix);
            let header_methods = root_idx
                .map(|i| short_methods(&items[i].shape.methods_csv()))
                .unwrap_or_default();
            let header_flags = root_idx
                .map(|i| pretty_flags(&items[i].shape.flags_csv()))
                .unwrap_or_default();
            rows.push(Row {
                label: escape_terminal(&prefix),
                methods: header_methods,
                flags: header_flags,
            });
            for (i, api) in items.iter().enumerate() {
                if Some(i) == root_idx {
                    continue;
                }
                let suffix = api.path.strip_prefix(&prefix).unwrap_or(&api.path);
                rows.push(Row {
                    label: format!("  {}", escape_terminal(suffix)),
                    methods: short_methods(&api.shape.methods_csv()),
                    flags: pretty_flags(&api.shape.flags_csv()),
                });
            }
            Group { rows }
        })
        .collect()
}

fn first_segment(path: &str) -> String {
    let rest = path.strip_prefix('/').unwrap_or(path);
    match rest.find('/') {
        Some(idx) => format!("/{}", &rest[..idx]),
        None => format!("/{rest}"),
    }
}

fn short_methods(csv: &str) -> String {
    csv.split(',')
        .filter(|s| !s.is_empty())
        .map(abbreviate_method)
        .collect::<Vec<_>>()
        .join(" ")
}

fn abbreviate_method(method: &str) -> &str {
    match method {
        "DELETE" => "DEL",
        "PATCH" => "PAT",
        "OPTIONS" => "OPT",
        other => other,
    }
}

fn pretty_flags(csv: &str) -> String {
    csv.split(',')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_api_json<W: Write>(out: &Output, writer: &mut W) -> io::Result<()> {
    let mut body = String::new();
    body.push_str("{\"apis\":[");
    for (i, api) in out.apis.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str("{\"path\":");
        push_json_string(&mut body, &api.path);
        body.push_str(",\"methods\":");
        let methods = api.shape.methods_csv();
        push_json_array(&mut body, methods.split(',').filter(|s| !s.is_empty()));
        body.push_str(",\"flags\":");
        let flags = api.shape.flags_csv();
        push_json_array(&mut body, flags.split(',').filter(|s| !s.is_empty()));
        body.push('}');
    }
    body.push_str("],\"warnings\":");
    push_json_array(&mut body, out.warnings.iter().map(String::as_str));
    body.push_str("}\n");
    writer.write_all(body.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::processor::{Api, CacheStatus, Output};
    use crate::scan::Shape;

    #[test]
    fn text_output_is_api_only() {
        let out = fixture();
        let mut rendered = Vec::new();

        render_api_text(&out, &mut rendered).unwrap();

        let rendered = String::from_utf8(rendered).unwrap();
        assert_eq!(
            rendered,
            "# cache=miss  apis=2\n/api\n  /users  GET  · query\n\n/v1\n  /login  POST  · body headers json\n"
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
            apis: vec![
                api("/api/users?team=1", Shape::inferred(Some("GET"), false)),
                api("/v1/login", {
                    let mut shape = Shape::inferred(Some("POST"), true);
                    shape.merge(&shape_with_json());
                    shape
                }),
            ],
            revision: None,
            cache: CacheStatus::Miss,
            cache_age_secs: None,
            elapsed_us: None,
            warnings: Vec::new(),
        }
    }

    fn api(url: &str, mut shape: Shape) -> Api {
        shape.apply_query_params(url);
        Api {
            path: url.split('?').next().unwrap_or(url).to_string(),
            shape,
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
