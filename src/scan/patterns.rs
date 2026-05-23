use crate::generated;
use crate::literal::LiteralSet;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatternKind {
    ApiCall,
    ApiCandidate,
    RouteCall,
    RouteValue,
    RouteStart,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SearchPattern {
    pub(crate) literal: &'static str,
    pub(crate) kind: PatternKind,
}

impl PatternKind {
    fn from_tag(tag: u8) -> Self {
        match tag {
            0 => Self::ApiCall,
            1 => Self::ApiCandidate,
            2 => Self::RouteCall,
            3 => Self::RouteValue,
            _ => Self::RouteStart,
        }
    }
}

pub(crate) static DOCUMENT_LITERALS: LazyLock<LiteralSet<SearchPattern>> = LazyLock::new(|| {
    LiteralSet::from_strs(generated::DOCUMENT_PATTERNS.iter().map(|&(literal, tag)| {
        (
            literal,
            SearchPattern {
                literal,
                kind: PatternKind::from_tag(tag),
            },
        )
    }))
});
