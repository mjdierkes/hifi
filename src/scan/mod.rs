//! Endpoint and client-route scanner.
//!
//! This module turns source bytes into three buckets:
//! - confirmed API calls with method/body/header hints,
//! - API-like candidates that were seen as values rather than calls,
//! - client routes that are useful context but not API endpoints.
//!
//! The scanner is intentionally anchor based. `patterns` registers each search
//! literal with a semantic kind, while `extract`, `classify`, and `shape` keep
//! parsing details out of the orchestration flow below.

use crate::source;
use patterns::{PatternKind, DOCUMENT_LITERALS};

pub mod classify;
mod clients;
mod extract;
pub mod findings;
mod literals;
mod patterns;
mod shape;

pub use findings::{
    ApiMap, CandidateMap, Confidence, Evidence, EvidenceKind, FindingsBuilder, Provenance, RouteMap,
    ScanResult, Channel,
};
pub use shape::Shape;

pub fn scan_endpoints(bytes: &[u8]) -> FindingsBuilder {
    let mut out = FindingsBuilder::default();

    for m in DOCUMENT_LITERALS.find_iter(bytes) {
        let pattern = m.value;
        match pattern.kind {
            PatternKind::ApiCall => {
                record_api_call(bytes, m.start(), m.end(), pattern.literal, &mut out)
            }
            PatternKind::ApiCandidate => {
                push_candidate(bytes, m.start(), &mut out);
            }
            PatternKind::RouteCall => record_route_call(bytes, m.end(), &mut out),
            PatternKind::RouteValue => record_route_value(bytes, m.start(), m.end(), &mut out),
            PatternKind::RouteStart => record_route_start(bytes, m.end(), &mut out),
        }
    }
    clients::scan(bytes, &mut out);
    out
}

pub(crate) fn has_document_pattern(bytes: &[u8]) -> bool {
    DOCUMENT_LITERALS.is_match(bytes)
}

fn record_api_call(
    bytes: &[u8],
    start: usize,
    after: usize,
    anchor: &str,
    out: &mut FindingsBuilder,
) {
    let Some((url, mut shape)) = shape::scan_call(bytes, start, after, anchor) else {
        return;
    };
    if !classify::is_url_like(&url) {
        return;
    }

    shape.ensure_default_method();
    shape.apply_query_params(&url);
    let url = classify::normalize_api_url(&url);
    out.record_api(url, shape, Provenance::channel(Channel::ApiCall));
}

fn record_route_call(bytes: &[u8], after: usize, out: &mut FindingsBuilder) {
    if let Some(url) = extract::url_arg(bytes, after).filter(|url| classify::is_client_route(url)) {
        out.record_route(url, Provenance::channel(Channel::RouteCall));
    }
}

fn record_route_value(bytes: &[u8], start: usize, after: usize, out: &mut FindingsBuilder) {
    if !source::is_identifier_boundary_before(bytes, start) {
        return;
    }
    if let Some(url) =
        extract::value_after_anchor(bytes, after).filter(|url| classify::is_client_route(url))
    {
        out.record_route(url, Provenance::literal());
    }
}

fn record_route_start(bytes: &[u8], after: usize, out: &mut FindingsBuilder) {
    let slash = after.saturating_sub(1);
    if !push_candidate(bytes, slash, out) {
        if let Some(url) =
            extract::token_at(bytes, slash).filter(|url| classify::is_client_route(url))
        {
            out.record_route(url, Provenance::literal());
        }
    }
}

fn push_candidate(bytes: &[u8], pos: usize, out: &mut FindingsBuilder) -> bool {
    let Some(url) = extract::token_before(bytes, pos) else {
        return false;
    };
    if !classify::is_api_candidate(&url) {
        return false;
    }

    let url = classify::normalize_api_url(&url);
    out.record_candidate(url, Provenance::literal());
    true
}
