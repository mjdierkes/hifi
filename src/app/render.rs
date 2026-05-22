use super::{AppError, OutputMode};
use crate::runtime::daemon;
use crate::runtime::processor::{CacheStatus, Output};
use crate::scan::{EvidenceKind, Shape};
use std::collections::BTreeMap;
use std::io::{self, Write};

#[derive(Clone, Debug, Default)]
pub struct RenderOptions {
    pub expand_routes: bool,
    pub show_internal: bool,
    pub filter: Option<String>,
}

pub fn render_processed(
    out: &Output,
    mode: OutputMode,
    opts: &RenderOptions,
) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    match mode {
        OutputMode::Json => {
            stdout.write_all(out.to_json_string().as_bytes())?;
            stdout.write_all(b"\n")?;
        }
        OutputMode::Flat => render_flat_output(out, &mut stdout)?,
        OutputMode::Auto => render_grouped_output(out, &mut stdout, opts)?,
    }
    Ok(())
}

pub fn render_daemon_reply(
    reply: &mut daemon::DaemonReply,
    mode: OutputMode,
    opts: &RenderOptions,
) {
    if reply.exit_code != 0 {
        return;
    }
    let Some(mut output) = reply.output.take() else {
        if !reply.stdout.ends_with('\n') {
            reply.stdout.push('\n');
        }
        return;
    };
    if output.cache == CacheStatus::Stored {
        output.cache = CacheStatus::Fresh;
    }
    reply.stderr.push_str(&warning_text(&output));
    let mut rendered = Vec::new();
    let ok = match mode {
        OutputMode::Json => {
            reply.stdout = output.to_json_string();
            if !reply.stdout.ends_with('\n') {
                reply.stdout.push('\n');
            }
            true
        }
        OutputMode::Flat => render_flat_output(&output, &mut rendered).is_ok(),
        OutputMode::Auto => render_grouped_output(&output, &mut rendered, opts).is_ok(),
    };
    if ok && mode != OutputMode::Json {
        reply.stdout = String::from_utf8(rendered).unwrap_or_else(|_| {
            let mut json = output.to_json_string();
            json.push('\n');
            json
        });
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

fn render_grouped_output<W: Write>(
    v: &Output,
    out: &mut W,
    opts: &RenderOptions,
) -> io::Result<()> {
    let mut apis = collect_apis(v);
    let mut candidates = collect_paths(v, EvidenceKind::Candidate);
    let all_routes = collect_paths(v, EvidenceKind::Route);
    let (mut routes, internal_count) = if opts.show_internal {
        (all_routes, 0)
    } else {
        split_internal(all_routes)
    };

    if let Some(filter) = opts.filter.as_deref() {
        apis.retain(|r| path_matches(&r.path, filter));
        candidates.retain(|p| path_matches(p, filter));
        routes.retain(|p| path_matches(p, filter));
    }

    write_header(out, v, apis.len(), routes.len(), candidates.len(), opts)?;

    if !apis.is_empty() {
        writeln!(out)?;
        writeln!(out, "APIs")?;
        let method_width = apis.iter().map(|r| r.methods.len()).max().unwrap_or(0);
        for row in &apis {
            let path = escape_terminal(&row.path);
            if row.flags.is_empty() {
                writeln!(
                    out,
                    "  {:<width$}  {}",
                    row.methods,
                    path,
                    width = method_width
                )?;
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
        if opts.expand_routes {
            for path in &routes {
                writeln!(out, "  {}", escape_terminal(path))?;
            }
        } else {
            render_resource_summary(out, &routes)?;
        }
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
    opts: &RenderOptions,
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
    if let Some(filter) = opts.filter.as_deref() {
        parts.push(format!("filter {filter}"));
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

// A path matches a filter if it equals the filter or is nested below it
// (so `/modules` matches `/modules` and `/modules/billing` but not `/modules-x`).
fn path_matches(path: &str, filter: &str) -> bool {
    if path == filter {
        return true;
    }
    if let Some(rest) = path.strip_prefix(filter) {
        return rest.starts_with('/');
    }
    false
}

fn cache_label(status: CacheStatus) -> &'static str {
    match status {
        CacheStatus::Fresh => "cache fresh",
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

// Show each first-segment as a "resource" row with its child count + tail names.
// Paths whose first segment has no nested children become "top-level" entries.
const RESOURCE_LINE_WIDTH: usize = 78;

#[derive(Default)]
struct ResourceGroup {
    count: usize,
    actions: std::collections::BTreeSet<String>,
}

fn render_resource_summary<W: Write>(out: &mut W, paths: &[String]) -> io::Result<()> {
    let mut resource_first_segs: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for path in paths {
        let segs = path_segments(path);
        if segs.len() >= 2 {
            resource_first_segs.insert(segs[0].clone());
        }
    }

    let mut groups: BTreeMap<String, ResourceGroup> = BTreeMap::new();
    let mut top_level: Vec<String> = Vec::new();

    for path in paths {
        let segs = path_segments(path);
        if segs.is_empty() {
            top_level.push("/".to_string());
            continue;
        }
        if resource_first_segs.contains(&segs[0]) {
            let group = groups.entry(segs[0].clone()).or_default();
            group.count += 1;
            // Use the first non-param segment after the resource as the action
            // name. Detail-only children use ":id" (e.g. /images/:id).
            let action = segs[1..]
                .iter()
                .find(|s| !is_param(s))
                .cloned()
                .or_else(|| {
                    segs.get(1)
                        .filter(|s| is_param(s))
                        .map(|_| ":id".to_string())
                });
            if let Some(a) = action {
                group.actions.insert(a);
            }
        } else {
            top_level.push(format!("/{}", segs.join("/")));
        }
    }

    let name_width = groups
        .keys()
        .map(|k| k.len())
        .max()
        .unwrap_or(0)
        .max("top-level".len());
    let count_width = groups
        .values()
        .map(|g| g.count)
        .chain(std::iter::once(top_level.len()))
        .map(|n| n.to_string().len())
        .max()
        .unwrap_or(1);

    let action_budget = RESOURCE_LINE_WIDTH.saturating_sub(2 + name_width + 2 + count_width + 2);

    for (name, group) in &groups {
        let actions = truncate_actions(&group.actions, action_budget);
        writeln!(
            out,
            "  {name:<name_width$}  {count:>count_width$}  {actions}",
            name = escape_terminal(name),
            count = group.count,
            actions = escape_terminal(&actions),
        )?;
    }

    if !top_level.is_empty() {
        top_level.sort();
        top_level.dedup();
        let count = top_level.len();
        let joined = truncate_list(&top_level, action_budget);
        writeln!(
            out,
            "  {name:<name_width$}  {count:>count_width$}  {joined}",
            name = "top-level",
            count = count,
            joined = escape_terminal(&joined),
        )?;
    }

    Ok(())
}

fn path_segments(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_param(seg: &str) -> bool {
    seg.starts_with(':') || seg == "{dynamic}"
}

fn truncate_actions(actions: &std::collections::BTreeSet<String>, budget: usize) -> String {
    let names: Vec<&str> = actions.iter().map(String::as_str).collect();
    truncate_csv(&names, budget)
}

fn truncate_list(items: &[String], budget: usize) -> String {
    let names: Vec<&str> = items.iter().map(String::as_str).collect();
    truncate_csv(&names, budget)
}

fn truncate_csv(items: &[&str], budget: usize) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (i, item) in items.iter().enumerate() {
        let candidate_len = out.len() + if i == 0 { 0 } else { 2 } + item.len();
        let remaining = items.len() - i;
        let suffix = if remaining > 1 { 2 } else { 0 };
        if candidate_len + suffix > budget && i > 0 {
            out.push_str(", …");
            return out;
        }
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(item);
    }
    out
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
    fn resource_summary_groups_routes_and_hides_internal() {
        let out = Output {
            evidence: vec![
                route("/"),
                route("/docs"),
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
        render_grouped_output(&out, &mut rendered, &RenderOptions::default()).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();

        let expected = "\
10 routes · 0 APIs · fresh scan · 1.23s

Routes
  account    4  billing, password
  machines   4  :id, cancel, reboot
  top-level  2  /, /docs

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
        render_grouped_output(&out, &mut rendered, &RenderOptions::default()).unwrap();
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
            shape: Some(Shape::from_binary_parts(
                methods,
                has_body,
                false,
                0,
                false,
                next_action,
                Vec::new(),
            )),
        }
    }
}
