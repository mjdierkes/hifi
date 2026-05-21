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
use patterns::{PatternKind, DOCUMENT_AC, DOCUMENT_PATTERNS};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

pub mod classify;
mod extract;
mod literals;
pub mod next;
mod patterns;
mod shape;

pub use shape::Shape;

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, ()>;
pub type RouteMap = FxHashMap<String, ()>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Api,
    Route,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Extractor {
    Literal,
    Manifest,
    Flight,
    ApiCall,
    RouteCall,
    ServerAction,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Observed,
    Parsed,
    Inferred,
    Candidate,
}

impl Extractor {
    fn confidence(self) -> Confidence {
        match self {
            Self::ApiCall | Self::RouteCall => Confidence::Observed,
            Self::Manifest | Self::Flight => Confidence::Parsed,
            Self::ServerAction => Confidence::Inferred,
            Self::Literal => Confidence::Candidate,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub url: String,
    pub kind: EvidenceKind,
    pub extractor: Extractor,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Shape>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl ScanResult {
    pub fn merge(&mut self, other: ScanResult) {
        self.merge_findings(&other);
    }

    pub fn merge_findings(&mut self, other: &ScanResult) {
        self.evidence.extend(other.evidence.iter().cloned());
        self.compact();
    }

    pub fn finalize(&mut self) {
        self.canonicalize_routes();
        self.drop_demoted();
        self.compact();
    }

    pub fn record_api(&mut self, url: String, shape: Shape, extractor: Extractor) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Api,
            extractor,
            confidence: extractor.confidence(),
            shape: Some(shape),
        });
        self.compact();
    }

    pub fn record_route(&mut self, url: String, extractor: Extractor) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Route,
            extractor,
            confidence: extractor.confidence(),
            shape: None,
        });
        self.compact();
    }

    pub fn record_candidate(&mut self, url: String, extractor: Extractor) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Candidate,
            extractor,
            confidence: extractor.confidence(),
            shape: None,
        });
        self.compact();
    }

    pub fn api_map(&self) -> ApiMap {
        let mut out = ApiMap::default();
        for evidence in &self.evidence {
            if evidence.kind == EvidenceKind::Api {
                if let Some(shape) = &evidence.shape {
                    out.entry(evidence.url.clone()).or_default().merge(shape);
                }
            }
        }
        out
    }

    pub fn route_map(&self) -> RouteMap {
        self.evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::Route)
            .map(|e| (e.url.clone(), ()))
            .collect()
    }

    pub fn candidate_map(&self) -> CandidateMap {
        self.evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::Candidate)
            .map(|e| (e.url.clone(), ()))
            .collect()
    }

    fn canonicalize_routes(&mut self) {
        for evidence in &mut self.evidence {
            if evidence.kind == EvidenceKind::Route {
                evidence.url = canonicalize_route(&evidence.url);
            }
        }
    }

    fn drop_demoted(&mut self) {
        let apis = self.api_map();
        let candidates = self.candidate_map();
        self.evidence.retain(|e| match e.kind {
            EvidenceKind::Api => true,
            EvidenceKind::Candidate => !apis.contains_key(&e.url),
            EvidenceKind::Route => !apis.contains_key(&e.url) && !candidates.contains_key(&e.url),
        });
    }

    fn compact(&mut self) {
        let mut compacted: Vec<Evidence> = Vec::with_capacity(self.evidence.len());
        for evidence in self.evidence.drain(..) {
            if let Some(existing) = compacted.iter_mut().find(|existing| {
                existing.url == evidence.url
                    && existing.kind == evidence.kind
                    && existing.extractor == evidence.extractor
            }) {
                if let (Some(dst), Some(src)) = (&mut existing.shape, &evidence.shape) {
                    dst.merge(src);
                }
            } else {
                compacted.push(evidence);
            }
        }
        self.evidence = compacted;
    }
}

fn canonicalize_route(s: &str) -> String {
    // Strip fragment and query; for navigation routes the path is canonical.
    let path = s.split(['?', '#']).next().unwrap_or(s);
    // Strip trailing slash but preserve root.
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub fn scan_endpoints(bytes: &[u8]) -> ScanResult {
    let mut out = ScanResult::default();

    for m in DOCUMENT_AC.find_iter(bytes) {
        let pattern = DOCUMENT_PATTERNS[m.pattern().as_usize()];
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
    out
}

pub(crate) fn has_document_pattern(bytes: &[u8]) -> bool {
    DOCUMENT_AC.is_match(bytes)
}

fn record_api_call(bytes: &[u8], start: usize, after: usize, anchor: &str, out: &mut ScanResult) {
    let Some((url, mut shape)) = shape::scan_call(bytes, start, after, anchor) else {
        return;
    };
    if !classify::is_url_like(&url) {
        return;
    }

    shape.ensure_default_method();
    shape.apply_query_params(&url);
    let url = classify::normalize_api_url(&url);
    out.record_api(url, shape, Extractor::ApiCall);
}

fn record_route_call(bytes: &[u8], after: usize, out: &mut ScanResult) {
    if let Some(url) = extract::url_arg(bytes, after).filter(|url| classify::is_client_route(url)) {
        out.record_route(url, Extractor::RouteCall);
    }
}

fn record_route_value(bytes: &[u8], start: usize, after: usize, out: &mut ScanResult) {
    if !source::is_identifier_boundary_before(bytes, start) {
        return;
    }
    if let Some(url) =
        extract::value_after_anchor(bytes, after).filter(|url| classify::is_client_route(url))
    {
        out.record_route(url, Extractor::Literal);
    }
}

fn record_route_start(bytes: &[u8], after: usize, out: &mut ScanResult) {
    let slash = after.saturating_sub(1);
    if !push_candidate(bytes, slash, out) {
        if let Some(url) =
            extract::token_at(bytes, slash).filter(|url| classify::is_client_route(url))
        {
            out.record_route(url, Extractor::Literal);
        }
    }
}

fn push_candidate(bytes: &[u8], pos: usize, out: &mut ScanResult) -> bool {
    let Some(url) = extract::token_before(bytes, pos) else {
        return false;
    };
    if !classify::is_api_candidate(&url) {
        return false;
    }

    let url = classify::normalize_api_url(&url);
    out.record_candidate(url, Extractor::Literal);
    true
}
