mod assets;

pub use assets::scan_assets;

use crate::framework::{self, DetectedSite, FrameworkId};
use crate::framework::next::NextConfig;
use crate::hash::FxHashSet;
use crate::scan::findings::{FindingsBuilder, Provenance};
use crate::url::Url;

use assets::{
    is_empty_script, scan_dynamic_assets, scan_framework_markers, scan_html_assets,
    scan_literal_assets,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentKind {
    Html,
    Script,
    Manifest,
    Payload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    Script,
    Manifest,
    Payload,
}

impl AssetKind {
    fn document_kind(self) -> DocumentKind {
        match self {
            Self::Script => DocumentKind::Script,
            Self::Manifest => DocumentKind::Manifest,
            Self::Payload => DocumentKind::Payload,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetSource {
    HtmlScript,
    HtmlPreload,
    Literal,
    DynamicImport,
    NewUrl,
    NextManifest,
    FrameworkManifest,
}

#[derive(Clone, Debug)]
pub struct AssetRef {
    pub url: Url,
    pub kind: AssetKind,
    pub source: AssetSource,
}

impl AssetRef {
    pub fn document_kind(&self) -> DocumentKind {
        self.kind.document_kind()
    }
}

#[derive(Clone, Default)]
pub struct DocumentScan {
    pub findings: FindingsBuilder,
    pub assets: Vec<AssetRef>,
    pub revision: Option<String>,
    pub site: DetectedSite,
}

pub fn scan_document(bytes: &[u8], base: &Url, kind: DocumentKind) -> DocumentScan {
    scan_document_with_config(bytes, base, kind, None)
}

pub fn scan_document_with_config(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    parent_config: Option<&NextConfig>,
) -> DocumentScan {
    scan_document_with_config_and_findings(bytes, base, kind, parent_config, None)
}

pub(crate) fn scan_document_with_config_and_findings(
    bytes: &[u8],
    base: &Url,
    kind: DocumentKind,
    parent_config: Option<&NextConfig>,
    cached_findings: Option<FindingsBuilder>,
) -> DocumentScan {
    if is_empty_script(bytes, kind) {
        return DocumentScan::default();
    }

    let mut next_config = framework::next::parse_page_config(bytes, kind);
    if next_config.is_none() {
        next_config = parent_config.cloned();
    }
    let site = DetectedSite::detect(bytes, base, next_config.as_ref());
    let revision =
        framework::next::revision(bytes, site.has(FrameworkId::Next), next_config.as_ref());
    let mut out = DocumentScan {
        findings: cached_findings.unwrap_or_else(|| crate::scan::scan_endpoints(bytes)),
        assets: Vec::new(),
        revision,
        site: site.clone(),
    };
    let mut seen = FxHashSet::default();

    scan_framework_markers(bytes, &mut out.findings);
    framework::scan_document(
        bytes,
        base,
        kind,
        parent_config,
        &mut out.findings,
        &mut out.assets,
        &mut seen,
    );
    if kind == DocumentKind::Html {
        scan_html_assets(bytes, base, &site, &mut seen, &mut out.assets);
    }
    scan_literal_assets(
        bytes,
        base,
        &site,
        &mut out.findings,
        &mut seen,
        &mut out.assets,
    );
    scan_dynamic_assets(bytes, base, &site, &mut seen, &mut out.assets);

    out
}

pub(crate) fn push_asset(
    base: &Url,
    raw: &str,
    contexts: &DetectedSite,
    source: AssetSource,
    seen: &mut FxHashSet<Url>,
    out: &mut Vec<AssetRef>,
) {
    let Some(kind) = framework::classify_asset(raw) else {
        return;
    };
    let Some(url) = framework::resolve_asset(base, raw, contexts) else {
        return;
    };
    if framework::should_skip(&url) {
        return;
    }
    if seen.insert(url.clone()) {
        out.push(AssetRef { url, kind, source });
    }
}

pub(crate) fn push_candidate(findings: &mut FindingsBuilder, raw: &str) {
    framework::next::push_framework_candidate(findings, raw);
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    if (framework::nuxt::is_payload(raw, path)
        || framework::sveltekit::is_payload(raw, path)
        || raw.contains("/_actions/")
        || path.contains("/_server-islands/")
        || raw.contains("?_data=")
        || raw.contains("&_data=")
        || path.contains("/_data/"))
        && crate::scan::classify::is_api_candidate(raw)
    {
        findings.record_candidate(
            crate::scan::classify::normalize_api_url(raw),
            Provenance::literal(),
        );
    }
}
