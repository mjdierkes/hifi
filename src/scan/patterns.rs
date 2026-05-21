use super::literals::{
    CALL_LITERALS, ROUTE_CALL_LITERALS, ROUTE_START_LITERALS, ROUTE_VALUE_LITERALS,
};
use aho_corasick::{AhoCorasick, MatchKind};
use std::sync::LazyLock;

const CANDIDATE_LITERALS: &[&str] = &["/api", "/graphql", "/trpc"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatternKind {
    ApiCall,
    ApiCandidate,
    RouteCall,
    RouteValue,
    RouteStart,
}

// Each literal declares the kind of evidence it represents. That keeps the
// Aho-Corasick index from becoming hidden control flow.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SearchPattern {
    pub(crate) literal: &'static str,
    pub(crate) kind: PatternKind,
}

const PATTERN_GROUPS: &[(&[&str], PatternKind)] = &[
    (CALL_LITERALS, PatternKind::ApiCall),
    (CANDIDATE_LITERALS, PatternKind::ApiCandidate),
    (ROUTE_CALL_LITERALS, PatternKind::RouteCall),
    (ROUTE_VALUE_LITERALS, PatternKind::RouteValue),
    (ROUTE_START_LITERALS, PatternKind::RouteStart),
];

pub(crate) static DOCUMENT_PATTERNS: LazyLock<Vec<SearchPattern>> = LazyLock::new(|| {
    PATTERN_GROUPS
        .iter()
        .flat_map(|(literals, kind)| {
            literals.iter().map(|literal| SearchPattern {
                literal,
                kind: *kind,
            })
        })
        .collect()
});

pub(crate) static DOCUMENT_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(DOCUMENT_PATTERNS.iter().map(|pattern| pattern.literal))
        .expect("valid scan literals")
});
