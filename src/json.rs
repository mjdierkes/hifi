//! Minimal streaming JSON scanner.
//!
//! Produced for vertical integration: replaces `serde_json::Value` walking in
//! framework manifest parsing. The caller pulls events; we never materialise
//! a tree. Strings are returned as `&str` borrowed straight from the input
//! when they contain no escapes (the common case for routes and URLs).
//! Escaped strings are decoded only when encountered, keeping the common
//! unescaped route/URL path allocation-free at the call site.
//!
//! This is not a conformance-grade JSON parser. It accepts what production
//! frameworks emit and rejects everything else by returning `None`.

use std::str;

#[derive(Debug)]
pub enum Event<'a> {
    BeginObject,
    EndObject,
    BeginArray,
    EndArray,
    /// The next event will be the value for this key.
    Key(JsonStr<'a>),
    String(JsonStr<'a>),
    Number,
    Bool,
    Null,
}

/// A JSON string, either borrowed directly from the input (no escapes) or
/// decoded into a caller-supplied scratch buffer.
#[derive(Debug)]
pub enum JsonStr<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl JsonStr<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            JsonStr::Borrowed(s) => s,
            JsonStr::Owned(s) => s,
        }
    }
}

#[derive(Clone, Copy)]
enum Container {
    Object,
    Array,
}

pub struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    stack: Vec<Container>,
    /// In an object: next non-end event must be a key.
    expect_key: bool,
    /// Saw a value; the next non-end token must be `,` or container close.
    expect_sep: bool,
}

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            stack: Vec::new(),
            expect_key: false,
            expect_sep: false,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    pub fn next(&mut self) -> Option<Event<'a>> {
        loop {
            self.skip_ws();
            let b = self.peek()?;

            if self.expect_sep {
                match b {
                    b',' => {
                        self.pos += 1;
                        self.expect_sep = false;
                        self.expect_key = matches!(self.stack.last(), Some(Container::Object));
                        continue;
                    }
                    b'}' | b']' => self.expect_sep = false,
                    _ => return None,
                }
            }

            return Some(match b {
                b'}' => {
                    if !matches!(self.stack.pop()?, Container::Object) {
                        return None;
                    }
                    self.pos += 1;
                    self.expect_sep = true;
                    self.expect_key = false;
                    Event::EndObject
                }
                b']' => {
                    if !matches!(self.stack.pop()?, Container::Array) {
                        return None;
                    }
                    self.pos += 1;
                    self.expect_sep = true;
                    self.expect_key = false;
                    Event::EndArray
                }
                b'{' => {
                    self.pos += 1;
                    self.stack.push(Container::Object);
                    self.expect_key = true;
                    Event::BeginObject
                }
                b'[' => {
                    self.pos += 1;
                    self.stack.push(Container::Array);
                    self.expect_key = false;
                    Event::BeginArray
                }
                b'"' if self.expect_key => {
                    let key = self.read_string()?;
                    self.skip_ws();
                    if self.peek() != Some(b':') {
                        return None;
                    }
                    self.pos += 1;
                    self.expect_key = false;
                    Event::Key(key)
                }
                b'"' => {
                    let s = self.read_string()?;
                    self.expect_sep = true;
                    Event::String(s)
                }
                b't' => {
                    if !self.bytes[self.pos..].starts_with(b"true") {
                        return None;
                    }
                    self.pos += 4;
                    self.expect_sep = true;
                    Event::Bool
                }
                b'f' => {
                    if !self.bytes[self.pos..].starts_with(b"false") {
                        return None;
                    }
                    self.pos += 5;
                    self.expect_sep = true;
                    Event::Bool
                }
                b'n' => {
                    if !self.bytes[self.pos..].starts_with(b"null") {
                        return None;
                    }
                    self.pos += 4;
                    self.expect_sep = true;
                    Event::Null
                }
                b'-' | b'0'..=b'9' => {
                    self.skip_number();
                    self.expect_sep = true;
                    Event::Number
                }
                _ => return None,
            });
        }
    }

    fn skip_number(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9' => self.pos += 1,
                _ => break,
            }
        }
    }

    /// Skip the next value (and any nested structure). Use after a Key to
    /// discard the value.
    pub fn skip_value(&mut self) -> Option<()> {
        let start_depth = self.stack.len();
        let evt = self.next()?;
        match evt {
            Event::BeginObject | Event::BeginArray => {
                while self.stack.len() > start_depth {
                    self.next()?;
                }
                Some(())
            }
            _ => Some(()),
        }
    }

    fn read_string(&mut self) -> Option<JsonStr<'a>> {
        debug_assert_eq!(self.bytes.get(self.pos), Some(&b'"'));
        self.pos += 1;
        let start = self.pos;
        // Fast path: scan until we see a `"` or `\`. If we hit `"` first, no
        // escapes — return a borrowed slice.
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'"' => {
                    let raw = &self.bytes[start..self.pos];
                    self.pos += 1;
                    return str::from_utf8(raw).ok().map(JsonStr::Borrowed);
                }
                b'\\' => break,
                _ => self.pos += 1,
            }
        }
        if self.pos >= self.bytes.len() {
            return None;
        }
        // Slow path: copy into an owned buffer and decode escapes.
        let mut out = Vec::with_capacity(self.bytes.len() - start);
        out.extend_from_slice(&self.bytes[start..self.pos]);
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'"' => {
                    self.pos += 1;
                    return String::from_utf8(out).ok().map(JsonStr::Owned);
                }
                b'\\' => {
                    let esc = *self.bytes.get(self.pos + 1)?;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'u' => {
                            let hex = self.bytes.get(self.pos + 2..self.pos + 6)?;
                            let code = u16::from_str_radix(str::from_utf8(hex).ok()?, 16).ok()?;
                            let code = code as u32;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if self.bytes.get(self.pos + 6) != Some(&b'\\')
                                    || self.bytes.get(self.pos + 7) != Some(&b'u')
                                {
                                    return None;
                                }
                                let low_hex = self.bytes.get(self.pos + 8..self.pos + 12)?;
                                let low = u16::from_str_radix(str::from_utf8(low_hex).ok()?, 16)
                                    .ok()? as u32;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return None;
                                }
                                let scalar = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00));
                                push_char(&mut out, scalar)?;
                                self.pos += 10;
                            } else if (0xDC00..=0xDFFF).contains(&code) {
                                return None;
                            } else {
                                push_char(&mut out, code)?;
                                self.pos += 4;
                            }
                        }
                        _ => return None,
                    }
                    self.pos += 2;
                }
                b => {
                    out.push(b);
                    self.pos += 1;
                }
            }
        }
        None
    }
}

fn push_char(out: &mut Vec<u8>, code: u32) -> Option<()> {
    let c = char::from_u32(code)?;
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    Some(())
}

/// Walk every string value in `bytes`, calling `visit(parent_key, value)` for
/// each. `parent_key` is the key the value lives under in its immediate
/// object, or `None` if the value is an array element. Object keys
/// themselves are not visited as strings.
pub fn walk_strings(bytes: &[u8], mut visit: impl FnMut(Option<&str>, &str)) {
    walk(bytes, |evt| {
        if let Visit::String(key, value) = evt {
            visit(key, value);
        }
    });
}

/// Walk events emitted by [`walk`].
pub enum Visit<'a> {
    /// An object key. Fires for every key in every object.
    Key(&'a str),
    /// A string value. The first field is the immediate parent key (the key
    /// the string lives under) or `None` for strings without a key context.
    /// Object array values inherit the parent key of the array itself.
    String(Option<&'a str>, &'a str),
}

/// Walk strings and object keys with a single visitor closure.
pub fn walk(bytes: &[u8], mut visit: impl FnMut(Visit<'_>)) {
    let mut p = Parser::new(bytes);
    // Stack tracks the parent_key context across object boundaries. Arrays do
    // NOT push: the parent key visible to an array's elements is the key the
    // array itself lives under (e.g. `{"routes": ["/a"]}` should report
    // parent_key=Some("routes") for "/a").
    let mut key_stack: Vec<Option<String>> = Vec::new();
    let mut current_key: Option<String> = None;
    while let Some(evt) = p.next() {
        match evt {
            Event::BeginObject => {
                key_stack.push(current_key.take());
            }
            Event::EndObject => {
                current_key = key_stack.pop().unwrap_or(None);
            }
            Event::BeginArray | Event::EndArray => {}
            Event::Key(k) => {
                let s = k.as_str();
                visit(Visit::Key(s));
                current_key = Some(s.to_owned());
            }
            Event::String(s) => {
                visit(Visit::String(current_key.as_deref(), s.as_str()));
            }
            _ => {}
        }
    }
}

/// Read top-level keys of the root object. Returns `None` if the document
/// isn't a JSON object.
pub fn top_level_keys(bytes: &[u8]) -> Option<Vec<String>> {
    let mut p = Parser::new(bytes);
    match p.next()? {
        Event::BeginObject => {}
        _ => return None,
    }
    let mut keys = Vec::new();
    loop {
        match p.next()? {
            Event::EndObject => return Some(keys),
            Event::Key(k) => {
                keys.push(k.as_str().to_owned());
                p.skip_value()?;
            }
            _ => return None,
        }
    }
}

/// Find the object value under `target_key` at the root and return its
/// top-level keys. Returns `None` if `target_key` is missing or not an object.
pub fn keys_under(bytes: &[u8], target_key: &str) -> Option<Vec<String>> {
    let mut p = Parser::new(bytes);
    match p.next()? {
        Event::BeginObject => {}
        _ => return None,
    }
    loop {
        match p.next()? {
            Event::EndObject => return None,
            Event::Key(k) => {
                if k.as_str() == target_key {
                    match p.next()? {
                        Event::BeginObject => {}
                        _ => return None,
                    }
                    let mut keys = Vec::new();
                    loop {
                        match p.next()? {
                            Event::EndObject => return Some(keys),
                            Event::Key(k) => {
                                keys.push(k.as_str().to_owned());
                                p.skip_value()?;
                            }
                            _ => return None,
                        }
                    }
                }
                p.skip_value()?;
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_keys_works() {
        let bytes = br#"{"a":1,"b":[1,2,3],"c":{"x":1}}"#;
        let keys = top_level_keys(bytes).unwrap();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn keys_under_named_object() {
        let bytes = br#"{"pages":{"/foo":[],"/bar":[]},"other":"x"}"#;
        let keys = keys_under(bytes, "pages").unwrap();
        assert_eq!(keys, vec!["/foo", "/bar"]);
    }

    #[test]
    fn walk_strings_visits_with_key_context() {
        let bytes = br#"{"href":"/dashboard","nested":{"action":"/api"}}"#;
        let mut hits: Vec<(Option<String>, String)> = Vec::new();
        walk_strings(bytes, |k, v| {
            hits.push((k.map(str::to_owned), v.to_owned()));
        });
        assert_eq!(
            hits,
            vec![
                (Some("href".to_owned()), "/dashboard".to_owned()),
                (Some("action".to_owned()), "/api".to_owned()),
            ]
        );
    }

    #[test]
    fn walk_strings_handles_array_elements() {
        let bytes = br#"{"deps":["/a","/b"]}"#;
        let mut hits: Vec<String> = Vec::new();
        walk_strings(bytes, |_k, v| hits.push(v.to_owned()));
        assert_eq!(hits, vec!["/a", "/b"]);
    }

    #[test]
    fn handles_escapes() {
        let bytes = br#"{"k":"a\/b\nA"}"#;
        let mut hits: Vec<String> = Vec::new();
        walk_strings(bytes, |_k, v| hits.push(v.to_owned()));
        assert_eq!(hits, vec!["a/b\nA"]);
    }

    #[test]
    fn handles_unicode_surrogate_pairs() {
        let bytes = br#"{"k":"route-\ud83d\ude00"}"#;
        let mut hits: Vec<String> = Vec::new();
        walk_strings(bytes, |_k, v| hits.push(v.to_owned()));
        assert_eq!(hits, vec!["route-\u{1f600}"]);
    }

    #[test]
    fn rejects_unpaired_surrogates() {
        let bytes = br#"{"k":"route-\ud83d"}"#;
        let mut hits: Vec<String> = Vec::new();
        walk_strings(bytes, |_k, v| hits.push(v.to_owned()));
        assert!(hits.is_empty());
    }
}
