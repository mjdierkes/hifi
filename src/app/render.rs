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

fn render_api_text<W: Write>(out: &Output, writer: &mut W) -> io::Result<()> {
    for api in &out.apis {
        let methods = api.shape.methods_csv();
        let flags = api.shape.flags_csv();
        if flags.is_empty() {
            writeln!(writer, "{}\t{}", methods, escape_terminal(&api.path))?;
        } else {
            writeln!(
                writer,
                "{}\t{}\t{}",
                methods,
                escape_terminal(&api.path),
                flags
            )?;
        }
    }
    Ok(())
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
