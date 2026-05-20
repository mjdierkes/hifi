use self::literals::{BAD_EXTS, CALL_LITERALS, SHAPE_LITERALS};
use aho_corasick::AhoCorasick;
use rustc_hash::FxHashMap;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use std::sync::LazyLock;

static CALL_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(CALL_LITERALS).expect("valid call literals"));
static SHAPE_AC: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SHAPE_LITERALS).expect("valid shape literals"));

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, Candidate>;

pub mod html;
pub mod literals;

const METHOD_GET: u8 = 1 << 0;
const METHOD_POST: u8 = 1 << 1;
const METHOD_PUT: u8 = 1 << 2;
const METHOD_DELETE: u8 = 1 << 3;
const METHOD_PATCH: u8 = 1 << 4;
const CONTENT_JSON: u8 = 1 << 0;
const METHODS: [(u8, &str); 5] = [
    (METHOD_GET, "GET"),
    (METHOD_POST, "POST"),
    (METHOD_PUT, "PUT"),
    (METHOD_DELETE, "DELETE"),
    (METHOD_PATCH, "PATCH"),
];
const CONTENT_TYPES: [(u8, &str); 1] = [(CONTENT_JSON, "application/json")];

#[derive(Default, Clone)]
pub struct Shape {
    methods: u8,
    has_body: bool,
    has_headers: bool,
    content_types: u8,
    auth: bool,
}

#[derive(Clone)]
pub struct Candidate {
    source: String,
    confidence: String,
}

impl Default for Candidate {
    fn default() -> Self {
        Self {
            source: "literal".into(),
            confidence: "candidate".into(),
        }
    }
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
                flags.push(if name == "application/json" {
                    "json"
                } else {
                    name
                });
            }
        }
        if self.auth {
            flags.push("auth");
        }
        flags.join(",")
    }

    pub fn tree_label(&self) -> String {
        let methods = self.methods_csv();
        let flags = self.flags_csv();
        if flags.is_empty() {
            format!("[{methods}]")
        } else {
            format!("[{methods}] [{flags}]")
        }
    }
}

fn serialize_flags<S: serde::Serializer>(
    bits: &u8,
    flags: &[(u8, &str)],
    s: S,
) -> Result<S::Ok, S::Error> {
    flags
        .iter()
        .filter_map(|(bit, name)| (bits & bit != 0).then_some(*name))
        .collect::<Vec<_>>()
        .serialize(s)
}

impl Serialize for Shape {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut len = 1;
        len += self.has_body as usize;
        len += self.has_headers as usize;
        len += (self.content_types != 0) as usize;
        len += self.auth as usize;

        let mut st = serializer.serialize_struct("Shape", len)?;
        st.serialize_field("methods", &Flags(self.methods, &METHODS))?;
        if self.has_body {
            st.serialize_field("has_body", &self.has_body)?;
        }
        if self.has_headers {
            st.serialize_field("has_headers", &self.has_headers)?;
        }
        if self.content_types != 0 {
            st.serialize_field("content_types", &Flags(self.content_types, &CONTENT_TYPES))?;
        }
        if self.auth {
            st.serialize_field("auth", &self.auth)?;
        }
        st.end()
    }
}

struct Flags<'a>(u8, &'a [(u8, &'a str)]);

impl Serialize for Flags<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_flags(&self.0, self.1, serializer)
    }
}

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        enum Field {
            Methods,
            HasBody,
            HasHeaders,
            ContentTypes,
            Auth,
            Ignore,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("shape field")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        Ok(match value {
                            "methods" => Field::Methods,
                            "has_body" => Field::HasBody,
                            "has_headers" => Field::HasHeaders,
                            "content_types" => Field::ContentTypes,
                            "auth" => Field::Auth,
                            _ => Field::Ignore,
                        })
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ShapeVisitor;

        impl<'de> Visitor<'de> for ShapeVisitor {
            type Value = Shape;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("API shape object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut shape = Shape::default();
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Methods => {
                            shape.methods = deserialize_flags_value(map.next_value()?, &METHODS)
                        }
                        Field::HasBody => shape.has_body = map.next_value()?,
                        Field::HasHeaders => shape.has_headers = map.next_value()?,
                        Field::ContentTypes => {
                            shape.content_types =
                                deserialize_flags_value(map.next_value()?, &CONTENT_TYPES);
                        }
                        Field::Auth => shape.auth = map.next_value()?,
                        Field::Ignore => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(shape)
            }
        }

        deserializer.deserialize_struct(
            "Shape",
            &[
                "methods",
                "has_body",
                "has_headers",
                "content_types",
                "auth",
            ],
            ShapeVisitor,
        )
    }
}

fn deserialize_flags_value(values: Vec<String>, flags: &[(u8, &str)]) -> u8 {
    let mut bits = 0;
    for value in values {
        if let Some((bit, _)) = flags.iter().find(|(_, name)| *name == value) {
            bits |= *bit;
        }
    }
    bits
}

impl Serialize for Candidate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("Candidate", 2)?;
        st.serialize_field("source", &self.source)?;
        st.serialize_field("confidence", &self.confidence)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for Candidate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        enum Field {
            Source,
            Confidence,
            Ignore,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("candidate field")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        Ok(match value {
                            "source" => Field::Source,
                            "confidence" => Field::Confidence,
                            _ => Field::Ignore,
                        })
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct CandidateVisitor;

        impl<'de> Visitor<'de> for CandidateVisitor {
            type Value = Candidate;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("candidate object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut candidate = Candidate::default();
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Source => candidate.source = map.next_value()?,
                        Field::Confidence => candidate.confidence = map.next_value()?,
                        Field::Ignore => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(candidate)
            }
        }

        deserializer.deserialize_struct("Candidate", &["source", "confidence"], CandidateVisitor)
    }
}

impl Shape {
    fn merge_ref(&mut self, other: &Shape) {
        self.methods |= other.methods;
        self.has_body |= other.has_body;
        self.has_headers |= other.has_headers;
        self.content_types |= other.content_types;
        self.auth |= other.auth;
    }
}

pub fn scan(bytes: &[u8], apis: &mut ApiMap) {
    const WIN: usize = 400;

    for m in CALL_AC.find_iter(bytes) {
        let after = m.end();
        let Some(url) = extract_url_arg(bytes, after) else {
            continue;
        };
        if !is_url_like(url) {
            continue;
        }

        let ws = m.start().saturating_sub(WIN);
        let we = (after + WIN).min(bytes.len());
        let window = &bytes[ws..we];

        let entry = apis.entry(url.to_owned()).or_default();

        entry.methods |= method_hint(CALL_LITERALS[m.pattern().as_usize()]);

        for sm in SHAPE_AC.find_iter(window) {
            match sm.pattern().as_usize() {
                0 | 1 => entry.methods |= METHOD_POST,
                2 | 3 => entry.methods |= METHOD_PUT,
                4 | 5 => entry.methods |= METHOD_DELETE,
                6 | 7 => entry.methods |= METHOD_PATCH,
                8 | 9 => entry.methods |= METHOD_GET,
                10 => entry.has_body = true,
                11 => entry.has_headers = true,
                13 => entry.content_types |= CONTENT_JSON,
                14 | 15 => entry.auth = true,
                _ => {}
            }
        }
        if entry.methods == 0 {
            entry.methods = METHOD_GET;
        }
    }
}

pub fn scan_candidates(bytes: &[u8], candidates: &mut CandidateMap) {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' | b'`' => {
                let quote = bytes[i];
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != quote {
                    if bytes[end] == b'\\' && end + 1 < bytes.len() {
                        end += 2;
                        continue;
                    }
                    if quote == b'`'
                        && bytes[end] == b'$'
                        && end + 1 < bytes.len()
                        && bytes[end + 1] == b'{'
                    {
                        end = skip_template_expr(bytes, end + 2);
                        continue;
                    }
                    end += 1;
                }
                if quote == b'`' {
                    scan_template_candidate_text(&bytes[start..end], candidates);
                } else {
                    scan_candidate_text(&bytes[start..end], candidates);
                }
                i = end.saturating_add(1);
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

pub fn merge_candidate_refs_into<'a>(
    dst: &mut CandidateMap,
    src: impl IntoIterator<Item = (&'a String, &'a Candidate)>,
) {
    for (url, candidate) in src {
        dst.entry(url.clone()).or_insert_with(|| candidate.clone());
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
    for needle in [
        b"/api".as_slice(),
        b"/graphql".as_slice(),
        b"/trpc".as_slice(),
        b"/_next/data".as_slice(),
    ] {
        let mut offset = 0;
        while let Some(rel) = memchr::memmem::find(&bytes[offset..], needle) {
            let pos = offset + rel;
            if let Some(url) = extract_candidate_at(bytes, pos) {
                candidates.entry(url).or_default();
            }
            offset = pos + needle.len();
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
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn scan_template_candidate_text(bytes: &[u8], candidates: &mut CandidateMap) {
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
    let end = candidate_end(bytes, pos);
    let raw = std::str::from_utf8(&bytes[start..end]).ok()?;
    let url = raw.trim_matches('\\');
    is_api_candidate(url).then(|| url.to_owned())
}

fn candidate_end(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{dynamic}") {
            i += b"{dynamic}".len();
            continue;
        }
        if is_candidate_delim(bytes[i]) {
            break;
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
