//! Endpoint and client-route scanner.

use crate::source;
use anchors::scan_anchors;
use patterns::{PatternKind, DOCUMENT_LITERALS};

pub mod classify;
pub(crate) mod anchors;
mod clients;
mod extract;
pub mod findings;
mod patterns;
mod shape;

pub use findings::{
    ApiMap, CandidateMap, Confidence, Evidence, EvidenceKind, FindingsBuilder, Provenance, RouteMap,
    ScanResult, Channel,
};
pub use shape::Shape;

pub fn scan_endpoints(bytes: &[u8]) -> FindingsBuilder {
    let mut out = FindingsBuilder::default();
    scan_anchors(bytes, &DOCUMENT_LITERALS, |m| {
        let pattern = m.value;
        match pattern.kind {
            PatternKind::ApiCall => {
                on_api_call(bytes, m.start(), m.end(), pattern.literal, &mut out)
            }
            PatternKind::ApiCandidate => {
                let _ = on_api_candidate(bytes, m.start(), &mut out);
            }
            PatternKind::RouteCall => on_route_call(bytes, m.end(), &mut out),
            PatternKind::RouteValue => on_route_value(bytes, m.start(), m.end(), &mut out),
            PatternKind::RouteStart => on_route_start(bytes, m.end(), &mut out),
        }
    });
    clients::scan(bytes, &mut out);
    out
}

pub(crate) fn has_document_pattern(bytes: &[u8]) -> bool {
    DOCUMENT_LITERALS.is_match(bytes)
}

fn on_api_call(bytes: &[u8], start: usize, after: usize, anchor: &str, out: &mut FindingsBuilder) {
    let Some((url, mut shape)) = shape::scan_call(bytes, start, after, anchor) else {
        return;
    };
    shape.ensure_default_method();
    let _ = out.try_record_api(url, shape, Provenance::channel(Channel::ApiCall));
}

fn on_route_call(bytes: &[u8], after: usize, out: &mut FindingsBuilder) {
    if let Some(url) = extract::url_arg(bytes, after) {
        out.try_record_route(url, Provenance::channel(Channel::RouteCall));
    }
}

fn on_route_value(bytes: &[u8], start: usize, after: usize, out: &mut FindingsBuilder) {
    if !source::is_identifier_boundary_before(bytes, start) {
        return;
    }
    if let Some(url) = extract::value_after_anchor(bytes, after) {
        out.try_record_route(url, Provenance::literal());
    }
}

fn on_route_start(bytes: &[u8], after: usize, out: &mut FindingsBuilder) {
    let slash = after.saturating_sub(1);
    if !on_api_candidate(bytes, slash, out) {
        if let Some(url) = extract::token_at(bytes, slash) {
            out.try_record_route(url, Provenance::literal());
        }
    }
}

fn on_api_candidate(bytes: &[u8], pos: usize, out: &mut FindingsBuilder) -> bool {
    let Some(url) = extract::token_before(bytes, pos) else {
        return false;
    };
    out.try_record_candidate(url, Provenance::literal())
}
