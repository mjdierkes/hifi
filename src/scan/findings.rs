use crate::framework::FrameworkId;
use crate::hash::FxHashMap;

use super::classify;
use super::shape::Shape;

pub type ApiMap = FxHashMap<String, Shape>;
pub type CandidateMap = FxHashMap<String, ()>;
pub type RouteMap = FxHashMap<String, ()>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EvidenceKind {
    Api,
    Route,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Channel {
    Literal,
    Manifest,
    Flight,
    ApiCall,
    RouteCall,
    ServerAction,
    ApiClient,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Provenance {
    pub channel: Channel,
    pub framework: Option<FrameworkId>,
}

impl Provenance {
    pub const fn literal() -> Self {
        Self {
            channel: Channel::Literal,
            framework: None,
        }
    }

    pub const fn channel(channel: Channel) -> Self {
        Self {
            channel,
            framework: None,
        }
    }

    pub const fn framework(channel: Channel, framework: FrameworkId) -> Self {
        Self {
            channel,
            framework: Some(framework),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    Observed,
    Parsed,
    Inferred,
    Candidate,
}

impl Channel {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Literal,
            1 => Self::Manifest,
            2 => Self::Flight,
            3 => Self::ApiCall,
            4 => Self::RouteCall,
            5 => Self::ServerAction,
            6 => Self::ApiClient,
            _ => return None,
        })
    }

    pub fn confidence(self) -> Confidence {
        match self {
            Self::ApiCall | Self::RouteCall | Self::ApiClient => Confidence::Observed,
            Self::Manifest | Self::Flight => Confidence::Parsed,
            Self::ServerAction => Confidence::Inferred,
            Self::Literal => Confidence::Candidate,
        }
    }
}

impl Provenance {
    pub fn confidence(self) -> Confidence {
        if self.framework.is_some() && matches!(self.channel, Channel::Literal | Channel::Manifest) {
            Confidence::Parsed
        } else {
            self.channel.confidence()
        }
    }
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub url: String,
    pub kind: EvidenceKind,
    pub provenance: Provenance,
    pub shape: Option<Shape>,
}

#[derive(Debug, Default, Clone)]
pub struct FindingsBuilder {
    pub evidence: Vec<Evidence>,
}

impl FindingsBuilder {
    pub fn extend(&mut self, other: FindingsBuilder) {
        self.evidence.extend(other.evidence);
    }

    pub fn extend_result(&mut self, other: &ScanResult) {
        self.evidence.extend(other.evidence.iter().cloned());
    }

    pub fn finish(mut self) -> ScanResult {
        self.canonicalize_routes();
        self.drop_demoted();
        self.compact();
        ScanResult {
            evidence: self.evidence,
        }
    }

    pub fn try_record_api(&mut self, url: String, shape: Shape, provenance: Provenance) -> bool {
        if !classify::is_url_like(&url) {
            return false;
        }
        let mut shape = shape;
        shape.apply_query_params(&url);
        self.record_api(classify::normalize_api_url(&url), shape, provenance);
        true
    }

    pub fn try_record_route(&mut self, url: String, provenance: Provenance) -> bool {
        if !classify::is_client_route(&url) {
            return false;
        }
        self.record_route(url, provenance);
        true
    }

    pub fn try_record_candidate(&mut self, url: impl Into<String>, provenance: Provenance) -> bool {
        let url = url.into();
        if !classify::is_api_candidate(&url) {
            return false;
        }
        self.record_candidate(classify::normalize_api_url(&url), provenance);
        true
    }

    pub fn record_api(&mut self, url: String, shape: Shape, provenance: Provenance) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Api,
            provenance,
            shape: Some(shape),
        });
    }

    pub fn record_route(&mut self, url: String, provenance: Provenance) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Route,
            provenance,
            shape: None,
        });
    }

    pub fn record_candidate(&mut self, url: String, provenance: Provenance) {
        self.evidence.push(Evidence {
            url,
            kind: EvidenceKind::Candidate,
            provenance,
            shape: None,
        });
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
        let mut seen = FxHashMap::<(String, EvidenceKind, Provenance), usize>::default();
        let mut compacted: Vec<Evidence> = Vec::with_capacity(self.evidence.len());
        for evidence in self.evidence.drain(..) {
            let key = (evidence.url.clone(), evidence.kind, evidence.provenance);
            if let Some(index) = seen.get(&key).copied() {
                let existing = &mut compacted[index];
                if let (Some(dst), Some(src)) = (&mut existing.shape, &evidence.shape) {
                    dst.merge(src);
                }
            } else {
                seen.insert(key, compacted.len());
                compacted.push(evidence);
            }
        }
        self.evidence = compacted;
    }

    pub fn api_map(&self) -> ApiMap {
        api_map_from(&self.evidence)
    }

    pub fn route_map(&self) -> RouteMap {
        route_map_from(&self.evidence)
    }

    pub fn candidate_map(&self) -> CandidateMap {
        candidate_map_from(&self.evidence)
    }
}

#[derive(Default, Clone)]
pub struct ScanResult {
    pub evidence: Vec<Evidence>,
}

impl ScanResult {
    pub fn api_map(&self) -> ApiMap {
        api_map_from(&self.evidence)
    }

    pub fn route_map(&self) -> RouteMap {
        route_map_from(&self.evidence)
    }

    pub fn candidate_map(&self) -> CandidateMap {
        candidate_map_from(&self.evidence)
    }
}

fn api_map_from(evidence: &[Evidence]) -> ApiMap {
    let mut out = ApiMap::default();
    for evidence in evidence {
        if evidence.kind == EvidenceKind::Api {
            if let Some(shape) = &evidence.shape {
                out.entry(evidence.url.clone()).or_default().merge(shape);
            }
        }
    }
    out
}

fn route_map_from(evidence: &[Evidence]) -> RouteMap {
    evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Route)
        .map(|e| (e.url.clone(), ()))
        .collect()
}

fn candidate_map_from(evidence: &[Evidence]) -> CandidateMap {
    evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Candidate)
        .map(|e| (e.url.clone(), ()))
        .collect()
}

fn canonicalize_route(s: &str) -> String {
    let path = s.split(['?', '#']).next().unwrap_or(s);
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}
