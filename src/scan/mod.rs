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

mod classify;
mod extract;
mod literals;
pub mod next;
mod patterns;
mod shape;

pub use shape::Shape;

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, ()>;
pub type RouteMap = FxHashMap<String, ()>;
pub type ProvenanceMap = FxHashMap<String, FindingSource>;

/// How a finding entered the result set. Used downstream to bucket findings
/// into a high-confidence tier (parsed manifests, HTML attributes, typed RSC
/// flight, explicit API calls) versus a best-effort tier (raw byte grep).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    /// Default for legacy paths that grep raw bytes without structural context.
    #[default]
    Literal,
    /// `<script src>`, `<link href>` etc. in an HTML document.
    HtmlTag,
    /// Pulled from a structurally parsed manifest (`_buildManifest.js`,
    /// `app-build-manifest.json`, `middleware-manifest.json`,
    /// `_clientReferenceManifest.json`).
    ManifestParsed,
    /// Walked from a typed React Flight payload line.
    FlightTyped,
    /// Identified at a call site like `fetch(...)`, `axios.get(...)`.
    ApiCall,
    /// Inferred from a Next.js Server Action marker on an HTML or RSC payload.
    ServerAction,
}

impl FindingSource {
    /// Provenance levels that are accurate enough to ship in a 99%-precision
    /// output tier without manual triage.
    pub fn is_high_confidence(self) -> bool {
        matches!(
            self,
            Self::HtmlTag
                | Self::ManifestParsed
                | Self::FlightTyped
                | Self::ApiCall
                | Self::ServerAction
        )
    }

    /// When two emit sites disagree on a finding's provenance, take the higher
    /// confidence one. Numeric ordering here is just for the max() call below.
    fn rank(self) -> u8 {
        match self {
            Self::Literal => 0,
            Self::FlightTyped => 1,
            Self::HtmlTag => 2,
            Self::ApiCall => 3,
            Self::ServerAction => 4,
            Self::ManifestParsed => 5,
        }
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub apis: ApiMap,
    #[serde(default, skip_serializing_if = "RouteMap::is_empty")]
    pub routes: RouteMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
    #[serde(default, skip_serializing_if = "ProvenanceMap::is_empty")]
    pub provenance: ProvenanceMap,
}

impl ScanResult {
    pub fn merge(&mut self, other: ScanResult) {
        self.merge_findings(&other);
    }

    pub fn merge_findings(&mut self, other: &ScanResult) {
        for (url, shape) in &other.apis {
            self.apis.entry(url.clone()).or_default().merge(shape);
        }
        self.routes
            .extend(other.routes.keys().map(|url| (url.clone(), ())));
        self.candidates
            .extend(other.candidates.keys().map(|url| (url.clone(), ())));
        for (url, source) in &other.provenance {
            self.bump_provenance(url.clone(), *source);
        }
    }

    pub fn finalize(&mut self) {
        for url in self.apis.keys() {
            self.candidates.remove(url);
            self.routes.remove(url);
        }
        for url in self.candidates.keys() {
            self.routes.remove(url);
        }
        // Drop provenance for entries that were demoted out of the result.
        let live: rustc_hash::FxHashSet<String> = self
            .apis
            .keys()
            .chain(self.routes.keys())
            .chain(self.candidates.keys())
            .cloned()
            .collect();
        self.provenance.retain(|url, _| live.contains(url));
    }

    /// Record (or upgrade) the provenance for a finding. If we already saw
    /// the same finding via a higher-confidence source, keep the higher one.
    pub fn bump_provenance(&mut self, url: String, source: FindingSource) {
        let entry = self.provenance.entry(url).or_default();
        if source.rank() > entry.rank() {
            *entry = source;
        }
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
    out.apis.entry(url.clone()).or_default().merge(&shape);
    out.bump_provenance(url, FindingSource::ApiCall);
}

fn record_route_call(bytes: &[u8], after: usize, out: &mut ScanResult) {
    if let Some(url) = extract::url_arg(bytes, after).filter(|url| classify::is_client_route(url)) {
        out.routes.entry(url.clone()).or_default();
        out.bump_provenance(url, FindingSource::ApiCall);
    }
}

fn record_route_value(bytes: &[u8], start: usize, after: usize, out: &mut ScanResult) {
    if !source::is_identifier_boundary_before(bytes, start) {
        return;
    }
    if let Some(url) =
        extract::value_after_anchor(bytes, after).filter(|url| classify::is_client_route(url))
    {
        out.routes.entry(url.clone()).or_default();
        out.bump_provenance(url, FindingSource::Literal);
    }
}

fn record_route_start(bytes: &[u8], after: usize, out: &mut ScanResult) {
    let slash = after.saturating_sub(1);
    if !push_candidate(bytes, slash, out) {
        if let Some(url) =
            extract::token_at(bytes, slash).filter(|url| classify::is_client_route(url))
        {
            out.routes.entry(url.clone()).or_default();
            out.bump_provenance(url, FindingSource::Literal);
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
    out.candidates.entry(url.clone()).or_default();
    out.bump_provenance(url, FindingSource::Literal);
    true
}
