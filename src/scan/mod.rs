use self::literals::{
    BAD_EXTS, CALL_LITERALS, ROUTE_BAD_EXTS, ROUTE_CALL_LITERALS, ROUTE_START_LITERALS,
    ROUTE_VALUE_LITERALS, SHAPE_LITERALS, SKIPPED_CHUNK_FRAGMENTS,
};
use aho_corasick::{AhoCorasick, MatchKind};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::LazyLock};
use url::Url;

static CALL_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CALL_LITERALS).expect("valid call literals"));
static SHAPE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SHAPE_LITERALS).expect("valid shape literals"));
static CANDIDATE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CANDIDATE_LITERALS).expect("valid candidate literals"));
static DOCUMENT_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let mut patterns = Vec::with_capacity(
        CALL_LITERALS.len()
            + SHAPE_LITERALS.len()
            + CANDIDATE_LITERALS.len()
            + ROUTE_CALL_LITERALS.len()
            + ROUTE_VALUE_LITERALS.len()
            + ROUTE_START_LITERALS.len()
            + 2,
    );
    patterns.extend_from_slice(CALL_LITERALS);
    patterns.extend_from_slice(SHAPE_LITERALS);
    patterns.extend_from_slice(CANDIDATE_LITERALS);
    patterns.extend_from_slice(ROUTE_CALL_LITERALS);
    patterns.extend_from_slice(ROUTE_VALUE_LITERALS);
    patterns.extend_from_slice(ROUTE_START_LITERALS);
    patterns.push("/_next/");
    patterns.push("static/chunks/");
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns)
        .expect("valid document literals")
});

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, ()>;
pub type RouteMap = FxHashMap<String, ()>;

pub mod html;
pub mod literals;

const METHOD_GET: u8 = 1 << 0;
const METHOD_POST: u8 = 1 << 1;
const METHOD_PUT: u8 = 1 << 2;
const METHOD_DELETE: u8 = 1 << 3;
const METHOD_PATCH: u8 = 1 << 4;
const METHOD_HEAD: u8 = 1 << 5;
const METHOD_OPTIONS: u8 = 1 << 6;
const CONTENT_JSON: u8 = 1 << 0;
const CONTENT_FORM: u8 = 1 << 1;
const CONTENT_URLENCODED: u8 = 1 << 2;
const CONTENT_TEXT: u8 = 1 << 3;
const METHODS: [(u8, &str); 7] = [
    (METHOD_GET, "GET"),
    (METHOD_POST, "POST"),
    (METHOD_PUT, "PUT"),
    (METHOD_DELETE, "DELETE"),
    (METHOD_PATCH, "PATCH"),
    (METHOD_HEAD, "HEAD"),
    (METHOD_OPTIONS, "OPTIONS"),
];
const CONTENT_TYPES: [(u8, &str); 4] = [
    (CONTENT_JSON, "application/json"),
    (CONTENT_FORM, "multipart/form-data"),
    (CONTENT_URLENCODED, "application/x-www-form-urlencoded"),
    (CONTENT_TEXT, "text/plain"),
];
const CANDIDATE_LITERALS: &[&str] = &["/api", "/graphql", "/trpc", "/_next/data"];
const SHAPE_WINDOW: usize = 400;
const STREAM_RETAIN: usize = 8192;

#[derive(Default)]
pub struct ScanResult {
    pub apis: ApiMap,
    pub candidates: CandidateMap,
    pub routes: RouteMap,
    pub refs: Vec<Url>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Shape {
    methods: u8,
    has_body: bool,
    has_headers: bool,
    content_types: u8,
    auth: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    query_params: Vec<String>,
}

impl Shape {
    pub fn methods_csv(&self) -> String {
        METHODS
            .iter()
            .filter_map(|(bit, name)| (self.methods & bit != 0).then_some(*name))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn flags_csv(&self) -> String {
        let mut flags: Vec<&str> = Vec::with_capacity(4);
        if self.has_body {
            flags.push("body");
        }
        if self.has_headers {
            flags.push("headers");
        }
        for (bit, name) in CONTENT_TYPES {
            if self.content_types & bit != 0 {
                flags.push(match name {
                    "application/json" => "json",
                    "multipart/form-data" => "form",
                    "application/x-www-form-urlencoded" => "urlencoded",
                    "text/plain" => "text",
                    _ => name,
                });
            }
        }
        if self.auth {
            flags.push("auth");
        }
        if !self.query_params.is_empty() {
            flags.push("query");
        }
        flags.join(",")
    }

    fn merge_ref(&mut self, other: &Shape) {
        self.methods |= other.methods;
        self.has_body |= other.has_body;
        self.has_headers |= other.has_headers;
        self.content_types |= other.content_types;
        self.auth |= other.auth;
        merge_string_vec(&mut self.query_params, &other.query_params);
    }
}

struct PendingApi {
    url: String,
    shape: Shape,
    expires_at: usize,
}

struct DocumentScanState {
    base: Url,
    out: ScanResult,
    seen_refs: FxHashSet<Url>,
    recent_shapes: VecDeque<(usize, ShapeKind)>,
    pending: Vec<PendingApi>,
}

impl DocumentScanState {
    fn new(base: Url) -> Self {
        Self {
            base,
            out: ScanResult::default(),
            seen_refs: FxHashSet::default(),
            recent_shapes: VecDeque::new(),
            pending: Vec::new(),
        }
    }

    fn scan_prefix(&mut self, bytes: &[u8], base_offset: usize, process_end: usize) {
        for m in DOCUMENT_AC.find_iter(bytes) {
            if m.start() >= process_end {
                break;
            }
            let pos = base_offset + m.start();
            flush_pending(&mut self.pending, &mut self.out.apis, pos);
            prune_recent_shapes(&mut self.recent_shapes, pos);
            self.handle_match(bytes, base_offset, m);
        }

        let end = base_offset + process_end;
        flush_pending(&mut self.pending, &mut self.out.apis, end);
        prune_recent_shapes(&mut self.recent_shapes, end);
    }

    fn handle_match(&mut self, bytes: &[u8], base_offset: usize, m: aho_corasick::Match) {
        let pattern = m.pattern().as_usize();
        if pattern < CALL_LITERALS.len() {
            let after = m.end();
            let Some(url) = extract_url_arg(bytes, after) else {
                return;
            };
            if !is_url_like(url) {
                return;
            }

            let mut shape = Shape::default();
            shape.methods |= method_hint(CALL_LITERALS[pattern]);
            let statement_start = base_offset + statement_start(bytes, m.start());
            for (shape_pos, kind) in &self.recent_shapes {
                if *shape_pos >= statement_start {
                    apply_shape_kind(&mut shape, *kind);
                }
            }
            self.pending.push(PendingApi {
                url: url.to_owned(),
                shape,
                expires_at: base_offset + shape_expires_at(bytes, after),
            });
            return;
        }

        let shape_start = CALL_LITERALS.len();
        let shape_end = shape_start + SHAPE_LITERALS.len();
        if pattern < shape_end {
            let pos = base_offset + m.start();
            let kind = shape_kind(pattern - shape_start);
            self.recent_shapes.push_back((pos, kind));
            for pending in &mut self.pending {
                if pos <= pending.expires_at {
                    apply_shape_kind(&mut pending.shape, kind);
                }
            }
            return;
        }

        let candidate_start = shape_end;
        let candidate_end = candidate_start + CANDIDATE_LITERALS.len();
        if pattern < candidate_end {
            if let Some(url) = extract_candidate_at(bytes, m.start()) {
                self.out.candidates.entry(url).or_default();
            }
            return;
        }

        let route_call_start = candidate_end;
        let route_call_end = route_call_start + ROUTE_CALL_LITERALS.len();
        if pattern < route_call_end {
            let after = m.end();
            if let Some(url) = extract_url_arg(bytes, after).filter(|url| is_client_route(url)) {
                self.out.routes.entry(url.to_owned()).or_default();
            }
            return;
        }

        let route_value_start = route_call_end;
        let route_value_end = route_value_start + ROUTE_VALUE_LITERALS.len();
        if pattern < route_value_end {
            if !is_identifier_boundary_before(bytes, m.start()) {
                return;
            }
            if let Some(url) =
                extract_value_after_anchor(bytes, m.end()).filter(|url| is_client_route(url))
            {
                self.out.routes.entry(url.to_owned()).or_default();
            }
            return;
        }

        let route_start_start = route_value_end;
        let route_start_end = route_start_start + ROUTE_START_LITERALS.len();
        if pattern < route_start_end {
            let slash = m.end().saturating_sub(1);
            if let Some(url) = extract_candidate_at(bytes, slash) {
                self.out.candidates.entry(url).or_default();
                return;
            }
            if bytes[slash..].starts_with(b"/_next/") {
                let start = walk_chunk_url_start(bytes, slash);
                let end = slash + chunk_url_len(&bytes[slash..], false);
                push_chunk_ref(
                    &bytes[start..end],
                    &self.base,
                    false,
                    &mut self.seen_refs,
                    &mut self.out.refs,
                );
                return;
            }
            if let Some(url) = extract_route_at(bytes, slash) {
                self.out.routes.entry(url).or_default();
            }
            return;
        }

        if pattern == route_start_end {
            let start = walk_chunk_url_start(bytes, m.start());
            let end = m.start() + chunk_url_len(&bytes[m.start()..], false);
            push_chunk_ref(
                &bytes[start..end],
                &self.base,
                false,
                &mut self.seen_refs,
                &mut self.out.refs,
            );
        } else {
            if m.start() >= 7 && &bytes[m.start() - 7..m.start()] == b"/_next/" {
                return;
            }
            let end = m.start() + chunk_url_len(&bytes[m.start()..], true);
            push_chunk_ref(
                &bytes[m.start()..end],
                &self.base,
                true,
                &mut self.seen_refs,
                &mut self.out.refs,
            );
        }
    }

    fn finish(mut self) -> ScanResult {
        flush_pending(&mut self.pending, &mut self.out.apis, usize::MAX);
        self.out
    }
}

pub struct StreamingDocumentScanner {
    state: DocumentScanState,
    buf: Vec<u8>,
    base_offset: usize,
}

impl StreamingDocumentScanner {
    pub fn new(base: Url) -> Self {
        Self {
            state: DocumentScanState::new(base),
            buf: Vec::with_capacity(STREAM_RETAIN * 2),
            base_offset: 0,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() <= STREAM_RETAIN {
            return;
        }

        let process_end = self.buf.len() - STREAM_RETAIN;
        self.state
            .scan_prefix(&self.buf, self.base_offset, process_end);
        self.buf.drain(..process_end);
        self.base_offset += process_end;
    }

    pub fn finish(mut self) -> ScanResult {
        let process_end = self.buf.len();
        self.state
            .scan_prefix(&self.buf, self.base_offset, process_end);
        self.state.finish()
    }
}

pub fn scan_document(bytes: &[u8], base: &Url) -> ScanResult {
    let mut state = DocumentScanState::new(base.clone());
    state.scan_prefix(bytes, 0, bytes.len());
    state.finish()
}

fn flush_pending(pending: &mut Vec<PendingApi>, apis: &mut ApiMap, pos: usize) {
    let mut i = 0;
    while i < pending.len() {
        if pending[i].expires_at >= pos {
            i += 1;
            continue;
        }
        let mut pending_api = pending.swap_remove(i);
        if pending_api.shape.methods == 0 {
            pending_api.shape.methods = METHOD_GET;
        }
        apply_query_params(&mut pending_api.shape, &pending_api.url);
        apis.entry(pending_api.url)
            .or_default()
            .merge_ref(&pending_api.shape);
    }
}

fn prune_recent_shapes(recent_shapes: &mut VecDeque<(usize, ShapeKind)>, pos: usize) {
    while recent_shapes
        .front()
        .is_some_and(|(shape_pos, _)| shape_pos.saturating_add(SHAPE_WINDOW) < pos)
    {
        recent_shapes.pop_front();
    }
}

pub fn scan(bytes: &[u8], apis: &mut ApiMap) {
    let mut calls = CALL_AC.find_iter(bytes).peekable();
    if calls.peek().is_none() {
        return;
    }

    for m in calls {
        let after = m.end();
        let Some(url) = extract_url_arg(bytes, after) else {
            continue;
        };
        if !is_url_like(url) {
            continue;
        }

        let ws = statement_start(bytes, m.start()).max(m.start().saturating_sub(SHAPE_WINDOW));
        let we = shape_expires_at(bytes, after).min(bytes.len());

        let entry = apis.entry(url.to_owned()).or_default();

        entry.methods |= method_hint(CALL_LITERALS[m.pattern().as_usize()]);

        apply_shape_window(entry, &bytes[ws..we]);
        if entry.methods == 0 {
            entry.methods = METHOD_GET;
        }
        apply_query_params(entry, url);
    }
}

#[derive(Clone, Copy)]
enum ShapeKind {
    Method(u8),
    Body,
    Headers,
    Content(u8),
    Auth,
    Ignore,
}

fn shape_kind(pattern: usize) -> ShapeKind {
    shape_kind_literal(SHAPE_LITERALS[pattern])
}

fn shape_kind_literal(literal: &str) -> ShapeKind {
    let upper = literal.to_ascii_uppercase();
    if upper.starts_with("BODY") {
        ShapeKind::Body
    } else if upper.starts_with("HEADERS") {
        ShapeKind::Headers
    } else if upper.contains("APPLICATION/JSON") {
        ShapeKind::Content(CONTENT_JSON)
    } else if upper.contains("MULTIPART/FORM-DATA") || upper.contains("FORMDATA") {
        ShapeKind::Content(CONTENT_FORM)
    } else if upper.contains("X-WWW-FORM-URLENCODED") || upper.contains("URLSEARCHPARAMS") {
        ShapeKind::Content(CONTENT_URLENCODED)
    } else if upper.contains("TEXT/PLAIN") {
        ShapeKind::Content(CONTENT_TEXT)
    } else if upper.contains("CONTENT-TYPE") {
        ShapeKind::Headers
    } else if upper.contains("AUTHORIZATION") || upper.contains("BEARER") {
        ShapeKind::Auth
    } else if upper.starts_with("METHOD") && upper.contains("POST") {
        ShapeKind::Method(METHOD_POST)
    } else if upper.starts_with("METHOD") && upper.contains("PUT") {
        ShapeKind::Method(METHOD_PUT)
    } else if upper.starts_with("METHOD") && upper.contains("DELETE") {
        ShapeKind::Method(METHOD_DELETE)
    } else if upper.starts_with("METHOD") && upper.contains("PATCH") {
        ShapeKind::Method(METHOD_PATCH)
    } else if upper.starts_with("METHOD") && upper.contains("GET") {
        ShapeKind::Method(METHOD_GET)
    } else if upper.starts_with("METHOD") && upper.contains("HEAD") {
        ShapeKind::Method(METHOD_HEAD)
    } else if upper.starts_with("METHOD") && upper.contains("OPTIONS") {
        ShapeKind::Method(METHOD_OPTIONS)
    } else {
        ShapeKind::Ignore
    }
}

fn apply_shape_window(entry: &mut Shape, bytes: &[u8]) {
    for m in SHAPE_AC.find_iter(bytes) {
        apply_shape_kind(entry, shape_kind(m.pattern().as_usize()));
    }
}

fn apply_shape_kind(entry: &mut Shape, kind: ShapeKind) {
    match kind {
        ShapeKind::Method(method) => entry.methods |= method,
        ShapeKind::Body => entry.has_body = true,
        ShapeKind::Headers => entry.has_headers = true,
        ShapeKind::Content(content) => entry.content_types |= content,
        ShapeKind::Auth => entry.auth = true,
        ShapeKind::Ignore => {}
    }
}

pub fn scan_candidates(bytes: &[u8], candidates: &mut CandidateMap) {
    if CANDIDATE_AC.find(bytes).is_none() {
        return;
    }

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' | b'`' => {
                let quote = bytes[i];
                let start = i + 1;
                let (end, next) = quoted_end(bytes, i);
                if quote == b'`' {
                    scan_template_candidate_text(&bytes[start..end], candidates);
                } else {
                    scan_candidate_text(&bytes[start..end], candidates);
                }
                i = next;
            }
            _ => i += 1,
        }
    }
    scan_unquoted_candidate_text(bytes, candidates);
}

pub fn merge_candidates_into(dst: &mut CandidateMap, src: CandidateMap) {
    for (url, candidate) in src {
        dst.entry(url).or_insert(candidate);
    }
}

pub fn merge_routes_into(dst: &mut RouteMap, src: RouteMap) {
    for (url, route) in src {
        dst.entry(url).or_insert(route);
    }
}

pub fn merge_candidate_refs_into<'a>(
    dst: &mut CandidateMap,
    src: impl IntoIterator<Item = (&'a String, &'a ())>,
) {
    for (url, _) in src {
        dst.entry(url.clone()).or_default();
    }
}

pub fn merge_route_refs_into<'a>(
    dst: &mut RouteMap,
    src: impl IntoIterator<Item = (&'a String, &'a ())>,
) {
    for (url, _) in src {
        dst.entry(url.clone()).or_default();
    }
}

pub fn merge_into(dst: &mut ApiMap, src: ApiMap) {
    for (url, shape) in src {
        dst.entry(url).or_default().merge_ref(&shape);
    }
}

pub fn merge_refs_into<'a>(
    dst: &mut ApiMap,
    src: impl IntoIterator<Item = (&'a String, &'a Shape)>,
) {
    for (url, shape) in src {
        dst.entry(url.clone()).or_default().merge_ref(shape);
    }
}

fn extract_url_arg(bytes: &[u8], start: usize) -> Option<&str> {
    if start > 0 && matches!(bytes[start - 1], b'"' | b'\'' | b'`') {
        return extract_quoted_tail(bytes, start, bytes[start - 1]);
    }

    let mut i = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }

    let quote = bytes[i];
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }

    let mut s = i + 1;

    // Template literal starting with `${expr}` — skip the expression so we
    // can capture the literal suffix after it (e.g. `${base}/foo` → "/foo").
    if quote == b'`' && s + 1 < bytes.len() && bytes[s] == b'$' && bytes[s + 1] == b'{' {
        let mut j = s + 2;
        let mut depth = 1;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        s = j;
    }

    let mut e = s;
    while e < bytes.len() && bytes[e] != quote {
        if bytes[e] == b'\\' && e + 1 < bytes.len() {
            e += 2;
            continue;
        }
        if quote == b'`' && bytes[e] == b'$' && e + 1 < bytes.len() && bytes[e + 1] == b'{' {
            break;
        }
        e += 1;
    }

    std::str::from_utf8(&bytes[s..e]).ok()
}

fn extract_quoted_tail(bytes: &[u8], start: usize, quote: u8) -> Option<&str> {
    let mut e = start;
    while e < bytes.len() && bytes[e] != quote {
        if bytes[e] == b'\\' && e + 1 < bytes.len() {
            e += 2;
            continue;
        }
        if quote == b'`' && bytes[e] == b'$' && e + 1 < bytes.len() && bytes[e + 1] == b'{' {
            break;
        }
        e += 1;
    }
    std::str::from_utf8(&bytes[start..e]).ok()
}

fn extract_value_after_anchor(bytes: &[u8], mut i: usize) -> Option<&str> {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i < bytes.len() && matches!(bytes[i], b'"' | b'\'' | b'`') {
        let quote = bytes[i];
        i += 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == quote {
            i += 1;
        }
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= bytes.len() || !matches!(bytes[i], b':' | b'=') {
        return None;
    }
    i += 1;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= bytes.len() || !matches!(bytes[i], b'"' | b'\'' | b'`') {
        return None;
    }
    extract_url_arg(bytes, i)
}

fn skip_template_expr(bytes: &[u8], mut i: usize) -> usize {
    let mut depth = 1;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b'\\' if i + 1 < bytes.len() => i += 1,
            _ => {}
        }
        i += 1;
    }
    i
}

fn scan_candidate_text(bytes: &[u8], candidates: &mut CandidateMap) {
    for m in CANDIDATE_AC.find_iter(bytes) {
        if let Some(url) = extract_candidate_at(bytes, m.start()) {
            candidates.entry(url).or_default();
        }
    }
}

fn scan_unquoted_candidate_text(bytes: &[u8], candidates: &mut CandidateMap) {
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'"' | b'\'' | b'`') {
            scan_candidate_text(&bytes[start..i], candidates);
            i = skip_quoted(bytes, i);
            start = i;
        } else {
            i += 1;
        }
    }
    scan_candidate_text(&bytes[start..], candidates);
}

fn skip_quoted(bytes: &[u8], start: usize) -> usize {
    quoted_end(bytes, start).1
}

fn quoted_end(bytes: &[u8], start: usize) -> (usize, usize) {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if quote == b'`' && bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            i = skip_template_expr(bytes, i + 2);
            continue;
        }
        if bytes[i] == quote {
            return (i, i + 1);
        }
        i += 1;
    }
    (bytes.len(), bytes.len())
}

fn scan_template_candidate_text(bytes: &[u8], candidates: &mut CandidateMap) {
    if memchr::memmem::find(bytes, b"${").is_none() {
        scan_candidate_text(bytes, candidates);
        return;
    }

    let mut normalized = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            normalized.extend_from_slice(b"{dynamic}");
            i = skip_template_expr(bytes, i + 2);
        } else {
            normalized.push(bytes[i]);
            i += 1;
        }
    }
    scan_candidate_text(&normalized, candidates);
}

fn extract_candidate_at(bytes: &[u8], pos: usize) -> Option<String> {
    let start = walk_candidate_start(bytes, pos);
    let url = candidate_string(bytes, start)?;
    is_api_candidate(&url).then_some(url)
}

fn extract_route_at(bytes: &[u8], pos: usize) -> Option<String> {
    let url = candidate_string(bytes, pos)?;
    is_client_route(&url).then_some(url)
}

fn candidate_string(bytes: &[u8], start: usize) -> Option<String> {
    let mut normalized = None;
    let end = candidate_end(bytes, start, &mut normalized);
    if let Some(normalized) = normalized {
        return String::from_utf8(normalized)
            .ok()
            .map(|url| url.trim_matches('\\').to_string());
    }

    let raw = std::str::from_utf8(&bytes[start..end]).ok()?;
    Some(raw.trim_matches('\\').to_string())
}

fn candidate_end(bytes: &[u8], mut i: usize, normalized: &mut Option<Vec<u8>>) -> usize {
    let start = i;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{dynamic}") {
            if let Some(out) = normalized {
                out.extend_from_slice(b"{dynamic}");
            }
            i += b"{dynamic}".len();
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let out = normalized.get_or_insert_with(|| bytes[start..i].to_vec());
            out.extend_from_slice(b"{dynamic}");
            i = skip_template_expr(bytes, i + 2);
            continue;
        }
        if is_candidate_delim(bytes[i]) {
            break;
        }
        if let Some(out) = normalized {
            out.push(bytes[i]);
        }
        i += 1;
    }
    i
}

fn walk_candidate_start(bytes: &[u8], pos: usize) -> usize {
    let mut s = pos;
    while s > 0 && !is_candidate_delim(bytes[s - 1]) {
        s -= 1;
    }
    s
}

fn is_candidate_delim(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\''
                | b'`'
                | b'<'
                | b'>'
                | b')'
                | b'('
                | b','
                | b';'
                | b'{'
                | b'}'
                | b'['
                | b']'
        )
}

fn is_api_candidate(s: &str) -> bool {
    is_url_like(s)
        && (s.starts_with("/api")
            || s.starts_with("/graphql")
            || s.starts_with("/trpc")
            || s.starts_with("/_next/data")
            || ((s.starts_with("http://") || s.starts_with("https://"))
                && (s.contains("/api/")
                    || s.ends_with("/api")
                    || s.contains("/graphql")
                    || s.contains("/trpc")
                    || s.contains("/_next/data/"))))
}

fn is_client_route(s: &str) -> bool {
    is_route_like(s)
        && !s.starts_with("/api")
        && !s.starts_with("/graphql")
        && !s.starts_with("/trpc")
        && !s.starts_with("/_next")
}

fn is_route_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && s.starts_with('/')
        && !s.starts_with("//")
        && bytes.iter().any(u8::is_ascii_alphanumeric)
        && !is_bad_route_url(bytes)
}

fn is_bad_route_url(s: &[u8]) -> bool {
    let path = s.split(|b| *b == b'?' || *b == b'#').next().unwrap_or(s);
    ROUTE_BAD_EXTS
        .iter()
        .any(|ext| ends_with_ci(path, ext.as_bytes()))
}

fn method_hint(anchor: &str) -> u8 {
    match anchor {
        "axios.get(" | "ky.get(" | ".get(" => METHOD_GET,
        "axios.post(" | "ky.post(" | ".post(" => METHOD_POST,
        "axios.put(" | ".put(" => METHOD_PUT,
        "axios.delete(" | ".delete(" => METHOD_DELETE,
        "axios.patch(" | ".patch(" => METHOD_PATCH,
        _ => 0,
    }
}

fn is_url_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=512).contains(&bytes.len())
        && (s.starts_with('/') || s.starts_with("http://") || s.starts_with("https://"))
        && s != "/"
        && !is_bad_asset_url(bytes)
        && bytes.iter().any(u8::is_ascii_alphanumeric)
}

fn is_bad_asset_url(s: &[u8]) -> bool {
    let path = s.split(|b| *b == b'?').next().unwrap_or(s);
    BAD_EXTS
        .iter()
        .any(|ext| ends_with_ci(path, ext.as_bytes()))
}

fn ends_with_ci(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn is_identifier_boundary_before(bytes: &[u8], pos: usize) -> bool {
    pos == 0
        || !matches!(
            bytes[pos - 1],
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$'
        )
}

fn statement_start(bytes: &[u8], pos: usize) -> usize {
    let start = pos.saturating_sub(SHAPE_WINDOW);
    bytes[start..pos]
        .iter()
        .rposition(|b| *b == b';')
        .map(|rel| start + rel + 1)
        .unwrap_or(start)
}

fn shape_expires_at(bytes: &[u8], after: usize) -> usize {
    let end = (after + SHAPE_WINDOW).min(bytes.len());
    bytes[after..end]
        .iter()
        .position(|b| *b == b';')
        .map(|rel| after + rel)
        .unwrap_or(end)
}

fn apply_query_params(shape: &mut Shape, url: &str) {
    let Some(query_start) = url.find('?') else {
        return;
    };
    let query = &url[query_start + 1..];
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        let key = pair.split('=').next().unwrap_or("").trim();
        if key.is_empty() || key.len() > 128 {
            continue;
        }
        push_unique_sorted(&mut shape.query_params, key);
    }
}

fn merge_string_vec(dst: &mut Vec<String>, src: &[String]) {
    for value in src {
        push_unique_sorted(dst, value);
    }
}

fn push_unique_sorted(dst: &mut Vec<String>, value: &str) {
    if dst.iter().any(|existing| existing == value) {
        return;
    }
    dst.push(value.to_owned());
    dst.sort_unstable();
}

fn walk_chunk_url_start(bytes: &[u8], needle_pos: usize) -> usize {
    let mut s = needle_pos;
    while s > 0 {
        let b = bytes[s - 1];
        if b.is_ascii_whitespace()
            || matches!(
                b,
                b'"' | b'\'' | b'`' | b'<' | b'>' | b'=' | b'(' | b',' | b';' | b'['
            )
        {
            break;
        }
        s -= 1;
    }
    s
}

fn chunk_url_len(bytes: &[u8], backtick: bool) -> usize {
    bytes
        .iter()
        .position(|b| {
            b.is_ascii_whitespace()
                || matches!(b, b'"' | b'\'' | b'<' | b'>' | b')' | b',' | b';')
                || (backtick && *b == b'`')
        })
        .unwrap_or(bytes.len())
}

fn push_chunk_ref(
    src: &[u8],
    base: &Url,
    nested: bool,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<Url>,
) {
    if is_skipped_chunk(src)
        || (nested && !src.ends_with(b".js"))
        || (!nested && memchr::memmem::find(src, b".js").is_none())
    {
        return;
    }
    let Ok(src) = std::str::from_utf8(src) else {
        return;
    };
    let url = if nested {
        base.join(&format!("/_next/{src}"))
    } else {
        base.join(src)
    };
    if let Ok(url) = url {
        push_unique_ref(url, seen, out);
    }
}

fn push_unique_ref(url: Url, seen: &mut FxHashSet<Url>, out: &mut Vec<Url>) {
    if seen.insert(url.clone()) {
        out.push(url);
    }
}

fn is_skipped_chunk(src: &[u8]) -> bool {
    SKIPPED_CHUNK_FRAGMENTS
        .iter()
        .any(|f| memchr::memmem::find(src, f.as_bytes()).is_some())
}
