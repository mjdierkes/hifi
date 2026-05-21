use super::{AppError, OutputMode};
use crate::runtime::daemon;
use crate::runtime::processor::{CacheStatus, Output};
use crate::scan::{EvidenceKind, Shape};
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
            EvidenceKind::Api => {
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
            EvidenceKind::Candidate => {
                writeln!(
                    out,
                    "?\t{}\t\t{:?}",
                    escape_terminal(&evidence.url),
                    evidence.confidence
                )?;
            }
            EvidenceKind::Route => {
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
    let apis = collect_apis(v);
    let candidates = collect_paths(v, EvidenceKind::Candidate);
    let (routes, internal_count) = split_internal(collect_paths(v, EvidenceKind::Route));

    write_header(out, v, apis.len(), routes.len(), candidates.len())?;

    if !apis.is_empty() {
        writeln!(out)?;
        writeln!(out, "APIs")?;
        let method_width = apis.iter().map(|r| r.methods.len()).max().unwrap_or(0);
        for row in &apis {
            let path = escape_terminal(&row.path);
            if row.flags.is_empty() {
                writeln!(out, "  {:<width$}  {}", row.methods, path, width = method_width)?;
            } else {
                writeln!(
                    out,
                    "  {:<width$}  {}  {}",
                    row.methods,
                    path,
                    row.flags,
                    width = method_width
                )?;
            }
        }
    }

    if !candidates.is_empty() {
        writeln!(out)?;
        writeln!(out, "API candidates")?;
        for path in &candidates {
            writeln!(out, "  ?  {}", escape_terminal(path))?;
        }
    }

    if !routes.is_empty() {
        writeln!(out)?;
        writeln!(out, "Routes")?;
        render_resource_summary(out, &routes)?;
    }

    if internal_count > 0 {
        writeln!(out)?;
        writeln!(
            out,
            "+{internal_count} internal route{} (--all)",
            if internal_count == 1 { "" } else { "s" }
        )?;
    }

    Ok(())
}

fn write_header<W: Write>(
    out: &mut W,
    v: &Output,
    api_count: usize,
    route_count: usize,
    candidate_count: usize,
) -> io::Result<()> {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!(
        "{route_count} route{}",
        if route_count == 1 { "" } else { "s" }
    ));
    parts.push(format!(
        "{api_count} API{}",
        if api_count == 1 { "" } else { "s" }
    ));
    if candidate_count > 0 {
        parts.push(format!(
            "{candidate_count} candidate{}",
            if candidate_count == 1 { "" } else { "s" }
        ));
    }
    if let Some(label) = v.framework.label() {
        parts.push(label);
    }
    parts.push(cache_label(v.cache).to_string());
    if let Some(us) = v.elapsed_us {
        parts.push(format_elapsed(us));
    }
    writeln!(out, "{}", parts.join(" · "))
}

fn cache_label(status: CacheStatus) -> &'static str {
    match status {
        CacheStatus::Fresh => "cache fresh",
        CacheStatus::Stale => "cache stale",
        CacheStatus::RevisionHit => "cache hit",
        CacheStatus::Miss => "fresh scan",
        CacheStatus::Stored => "stored",
    }
}

fn format_elapsed(us: u128) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{}ms", us / 1_000)
    } else {
        format!("{us}us")
    }
}

struct ApiRow {
    path: String,
    methods: String,
    flags: String,
}

fn collect_apis(v: &Output) -> Vec<ApiRow> {
    let mut merged = BTreeMap::<String, Shape>::new();
    for evidence in &v.evidence {
        if evidence.kind != EvidenceKind::Api {
            continue;
        }
        let Some(shape) = &evidence.shape else {
            continue;
        };
        let path = prettify(&normalize_path(&evidence.url));
        merged
            .entry(path)
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
    rows.sort_by(|a, b| a.methods.cmp(&b.methods).then(a.path.cmp(&b.path)));
    rows
}

fn collect_paths(v: &Output, kind: EvidenceKind) -> Vec<String> {
    let mut paths: Vec<String> = v
        .evidence
        .iter()
        .filter(|e| e.kind == kind)
        .map(|e| prettify(&normalize_path(&e.url)))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

fn normalize_path(url: &str) -> String {
    let raw = url::Url::parse(url)
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

fn split_internal(paths: Vec<String>) -> (Vec<String>, usize) {
    let mut visible = Vec::with_capacity(paths.len());
    let mut hidden = 0usize;
    for path in paths {
        let internal = path
            .split('/')
            .any(|seg| !seg.is_empty() && seg.starts_with('_'));
        if internal {
            hidden += 1;
        } else {
            visible.push(path);
        }
    }
    (visible, hidden)
}

fn prettify(path: &str) -> String {
    path.replace("{dynamic}", ":id")
}

#[derive(Default)]
struct Trie {
    is_endpoint: bool,
    children: BTreeMap<String, Trie>,
}

impl Trie {
    fn insert(&mut self, segments: &[String]) {
        match segments.split_first() {
            None => self.is_endpoint = true,
            Some((head, rest)) => self
                .children
                .entry(head.clone())
                .or_default()
                .insert(rest),
        }
    }
}

fn brace_collapse(paths: &[String]) -> Vec<String> {
    let mut root = Trie::default();
    for path in paths {
        let segs: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        root.insert(&segs);
    }

    let mut lines = Vec::new();
    if root.is_endpoint {
        lines.push("/".to_string());
    }
    for (name, child) in &root.children {
        lines.push(format!("/{}{}", name, render_tail(child)));
    }
    lines
}

fn render_tail(node: &Trie) -> String {
    if node.children.is_empty() {
        return String::new();
    }
    let kids: Vec<(&String, &Trie)> = node.children.iter().collect();

    // Single child, not an endpoint: chain segments with /
    if !node.is_endpoint && kids.len() == 1 {
        let (name, child) = kids[0];
        return format!("/{}{}", name, render_tail(child));
    }

    // Multiple children, not an endpoint: factor the / outside the braces
    if !node.is_endpoint {
        let parts: Vec<String> = kids
            .iter()
            .map(|(n, c)| format!("{}{}", n, render_tail(c)))
            .collect();
        return format!("/{{{}}}", parts.join(", "));
    }

    // Endpoint + children: include an empty branch for the endpoint itself
    let mut parts: Vec<String> = vec![String::new()];
    for (name, child) in &kids {
        parts.push(format!("/{}{}", name, render_tail(child)));
    }
    format!("{{{}}}", parts.join(","))
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
    use crate::scan::{Confidence, Evidence, Extractor};

    #[test]
    fn brace_collapses_routes_and_hides_internal() {
        let out = Output {
            evidence: vec![
                route("/"),
                route("/account"),
                route("/account/billing"),
                route("/account/billing/setup"),
                route("/account/password"),
                route("/machines"),
                route("/machines/{dynamic}"),
                route("/machines/{dynamic}/cancel"),
                route("/machines/{dynamic}/reboot"),
                route("/_head"),
                route("/_not-found"),
            ],
            revision: None,
            framework: Default::default(),
            cache: CacheStatus::Miss,
            cache_age_secs: None,
            elapsed_us: Some(1_234_000),
            warnings: Vec::new(),
        };

        let mut rendered = Vec::new();
        render_grouped_output(&out, &mut rendered).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();

        let expected = "\
9 routes · 0 APIs · fresh scan · 1.23s

Routes
  /
  /account{,/billing{,/setup},/password}
  /machines{,/:id{,/cancel,/reboot}}

+2 internal routes (--all)
";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn apis_render_with_methods_and_flags() {
        let out = Output {
            evidence: vec![
                api("/api/auth/signout", 2, true, false),
                api("/api/auth/csrf", 1, false, false),
                api("/api/checkout/start", 2, true, false),
                Evidence {
                    url: "/api/docs".to_string(),
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
        };

        let mut rendered = Vec::new();
        render_grouped_output(&out, &mut rendered).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();

        assert!(rendered.starts_with("0 routes · 3 APIs · 1 candidate · fresh scan\n"));
        assert!(rendered.contains("  GET   /api/auth/csrf\n"));
        assert!(rendered.contains("  POST  /api/auth/signout  body\n"));
        assert!(rendered.contains("  ?  /api/docs\n"));
    }

    fn route(path: &str) -> Evidence {
        Evidence {
            url: path.to_string(),
            kind: EvidenceKind::Route,
            extractor: Extractor::Manifest,
            confidence: Confidence::Parsed,
            shape: None,
        }
    }

    fn api(path: &str, methods: u8, has_body: bool, next_action: bool) -> Evidence {
        Evidence {
            url: path.to_string(),
            kind: EvidenceKind::Api,
            extractor: Extractor::ApiCall,
            confidence: Confidence::Observed,
            shape: Some(
                serde_json::from_str(&format!(
                    r#"{{"methods":{methods},"has_body":{has_body},"has_headers":false,"content_types":0,"auth":false,"query_params":[],"next_server_action":{next_action}}}"#
                ))
                .unwrap(),
            ),
        }
    }
}
