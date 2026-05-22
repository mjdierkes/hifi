//! Scan lifecycle orchestration.
//!
//! `Processor` is the runtime boundary between network/cache concerns and pure
//! scanning. The public flow is intentionally staged: plan the request, check
//! processed cache, load the root page, scan the root document, recursively scan
//! assets, then build display output.

use crate::discover::{self, DocumentKind};
use crate::framework::FrameworkConfig;
use crate::scan::next::NextConfig;
use crate::scan::{Confidence, Evidence, EvidenceKind, Extractor, Shape};

use super::{cache, config::RuntimeConfig, fetch, net};
use lru::LruCache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::Instant,
};
use thiserror::Error;
use url::Url;

const MEMORY_CACHE_MAX_ENTRIES: usize = 256;

type Result<T, E = RuntimeError> = std::result::Result<T, E>;
pub type Body = Arc<str>;
pub type MemoryCache = Arc<RwLock<LruCache<String, (Body, Instant)>>>;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Net(#[from] net::NetError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Output {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "FrameworkConfig::is_none")]
    pub framework: FrameworkConfig,
    #[serde(default, skip_serializing_if = "CacheStatus::is_stored")]
    pub cache: CacheStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u128>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Output {
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub(crate) fn mark(
        mut self,
        t0: Option<Instant>,
        status: CacheStatus,
        age_secs: Option<u64>,
    ) -> Self {
        self.cache = status;
        self.cache_age_secs = age_secs;
        self.elapsed_us = t0.map(|t| t.elapsed().as_micros());
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum CacheStatus {
    #[default]
    #[serde(rename = "stored")]
    Stored,
    #[serde(rename = "fresh")]
    Fresh,
    #[serde(rename = "stale")]
    Stale,
    #[serde(rename = "hit")]
    RevisionHit,
    #[serde(rename = "miss")]
    Miss,
}

impl CacheStatus {
    fn is_stored(&self) -> bool {
        *self == Self::Stored
    }
}

#[derive(Clone, Default)]
pub struct CacheContext {
    pub memory: Option<MemoryCache>,
    pub assets: Option<fetch::AssetMemoryCache>,
    pub allow_private: bool,
}

impl CacheContext {
    pub fn for_config(config: RuntimeConfig) -> Self {
        Self {
            allow_private: config.allow_private,
            ..Self::default()
        }
    }
}

pub fn memory_cache() -> MemoryCache {
    Arc::new(RwLock::new(LruCache::new(
        NonZeroUsize::new(MEMORY_CACHE_MAX_ENTRIES).expect("nonzero cache size"),
    )))
}

pub struct Processor<'a> {
    client: &'a Client,
    concurrency: usize,
    cache: CacheContext,
}

struct RequestPlan {
    original_base: Url,
    cache: cache::ScanCache,
}

struct LoadedPage {
    html: bytes::Bytes,
    final_base: Url,
}

// A scan may reuse a processed result either before network I/O (`fresh`/`stale`)
// or after reading the root page when the page revision matches (`hit`).
struct ScanOutcome {
    output: Output,
    used_revision_cache: bool,
}

impl<'a> Processor<'a> {
    pub fn new(client: &'a Client, concurrency: usize, cache: CacheContext) -> Self {
        Self {
            client,
            concurrency,
            cache,
        }
    }

    pub async fn process_for_display(
        &self,
        url: &str,
        no_cache: bool,
        t0: Instant,
    ) -> Result<Output> {
        let active_cache = self.cache_for_request(no_cache);
        let plan = RequestPlan::new(url, &active_cache)?;
        let outcome = self
            .scan_request(&plan, !no_cache, Some(t0), &active_cache)
            .await?;
        if !no_cache && !outcome.used_revision_cache {
            write_caches(
                &plan.cache,
                &outcome.output,
                url,
                active_cache.memory.clone(),
            )?;
        }
        Ok(outcome.output)
    }

    fn cache_for_request(&self, no_cache: bool) -> CacheContext {
        if no_cache {
            CacheContext {
                allow_private: self.cache.allow_private,
                ..CacheContext::default()
            }
        } else {
            self.cache.clone()
        }
    }

    // This is the canonical scan pipeline. Keep cache lookup, page loading,
    // asset recursion, and output construction as separate steps so each policy
    // can be reasoned about independently.
    async fn scan_request(
        &self,
        plan: &RequestPlan,
        use_cache: bool,
        t0: Option<Instant>,
        cache_ctx: &CacheContext,
    ) -> Result<ScanOutcome> {
        if use_cache {
            if let Some((body, age)) = plan.cache.read_fresh_binary() {
                if let Some(output) = decode_output_binary(&body) {
                    return Ok(ScanOutcome {
                        output: output.mark(t0, CacheStatus::Fresh, Some(age)),
                        used_revision_cache: true,
                    });
                }
            }
        }

        let page = self.load_page(plan, use_cache, cache_ctx).await?;
        let root_scan = scan_root_document(page.html, page.final_base).await?;
        let mut found = root_scan.findings;
        let mut initial_assets = root_scan.assets;
        let revision = root_scan.revision.clone();

        // Revision hits happen after the page is read. The root HTML may be
        // new enough to validate the asset graph, so we can reuse processed
        // output without rescanning every static asset.
        if let (true, Some(revision), Some(t0)) = (use_cache, revision.as_deref(), t0) {
            if let Some(bytes) = plan.cache.read_stale_binary() {
                if let Some(output) = decode_output_binary(&bytes) {
                    if output.revision.as_deref() == Some(revision) {
                        return Ok(ScanOutcome {
                            output: output.mark(Some(t0), CacheStatus::RevisionHit, None),
                            used_revision_cache: true,
                        });
                    }
                }
            }
        }

        let asset_stats = fetch::scan_assets(
            self.client.clone(),
            initial_assets.drain(..),
            fetch::AssetScanOptions {
                concurrency: self.concurrency,
                use_processed_cache: use_cache,
                cache_key: revision.clone(),
                allow_private: cache_ctx.allow_private,
                memory: cache_ctx.assets.clone(),
                framework_config: root_scan.framework_config.clone(),
            },
            &mut found,
        )
        .await;
        let found = found.finish();

        Ok(ScanOutcome {
            output: Output {
                evidence: found.evidence,
                revision,
                framework: root_scan.framework_config,
                cache: CacheStatus::Miss,
                cache_age_secs: None,
                elapsed_us: t0.map(|t| t.elapsed().as_micros()),
                warnings: warnings_from_assets(&asset_stats),
            },
            used_revision_cache: false,
        })
    }

    async fn load_page(
        &self,
        plan: &RequestPlan,
        use_cache: bool,
        cache_ctx: &CacheContext,
    ) -> Result<LoadedPage> {
        let response = net::get_limited(
            self.client,
            plan.original_base.clone(),
            cache_ctx.allow_private,
        )
        .await?;
        let final_base = response.url().clone();
        let html = net::read_limited(response).await?;
        let _ = use_cache;
        Ok(LoadedPage { html, final_base })
    }
}

impl RequestPlan {
    fn new(url: &str, cache: &CacheContext) -> Result<Self, url::ParseError> {
        let original_base = Url::parse(url)?;
        let scan_cache = cache::ScanCache::for_base(&original_base);
        let _ = cache;
        Ok(Self {
            original_base,
            cache: scan_cache,
        })
    }
}

async fn scan_root_document(html: bytes::Bytes, final_base: Url) -> Result<discover::DocumentScan> {
    tokio::task::spawn_blocking(move || {
        discover::scan_document(&html, &final_base, DocumentKind::Html)
    })
    .await
    .map_err(RuntimeError::from)
}

fn warnings_from_assets(asset_stats: &fetch::AssetScanStats) -> Vec<String> {
    let mut warnings = Vec::new();
    if asset_stats.failed > 0 {
        let total = asset_stats.failed;
        let auth = asset_stats.unauthorized;
        let message = if auth == total {
            format!(
                "{total} assets blocked by auth (401/403); scan limited to public bundle surface"
            )
        } else if auth > 0 {
            let other = total - auth;
            format!(
                "failed to read {total} assets ({auth} auth-gated, {other} other); results may be incomplete"
            )
        } else {
            format!("failed to read {total} assets; results may be incomplete")
        };
        warnings.push(message);
    }
    if asset_stats.capped {
        warnings.push(format!(
            "stopped after {} discovered assets; results may be incomplete",
            asset_stats.discovered
        ));
    }
    warnings
}

pub fn read_memory(memory: &MemoryCache, url: &str) -> Option<(Body, u64)> {
    memory
        .write()
        .ok()?
        .get(url)
        .cloned()
        .map(|(body, t)| (body, t.elapsed().as_secs()))
}

pub fn write_memory(memory: &MemoryCache, url: String, body: Body) {
    if let Ok(mut entries) = memory.write() {
        let now = Instant::now();
        entries.put(url, (body, now));
        prune_memory(&mut entries, now);
    }
}

pub fn mark_cached_body(
    body: &str,
    t0: Instant,
    status: CacheStatus,
    age_secs: u64,
) -> Result<Body> {
    let output = serde_json::from_str::<Output>(body)?.mark(Some(t0), status, Some(age_secs));
    Ok(Arc::from(output.to_json_string()?))
}

fn write_caches(
    cache_store: &cache::ScanCache,
    out: &Output,
    url: &str,
    memory: Option<MemoryCache>,
) -> Result<()> {
    let cached = out.clone().mark(None, CacheStatus::Stored, None);
    cache_store.write_binary(&encode_output_binary(&cached));
    if let Ok(base) = url::Url::parse(url) {
        let candidates = completion_candidates(&cached.evidence);
        if !candidates.is_empty() {
            cache::write_completion_candidates(&base, &candidates);
        }
    }
    if let Some(memory) = memory {
        let body = Arc::from(cached.to_json_string()?);
        write_memory(&memory, url.to_string(), body);
    }
    Ok(())
}

const OUTPUT_BINARY_MAGIC: &[u8; 8] = b"HIFIOU1\0";

fn encode_output_binary(out: &Output) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(out.evidence.len().saturating_mul(48) + 128);
    bytes.extend_from_slice(OUTPUT_BINARY_MAGIC);
    put_opt_string(&mut bytes, out.revision.as_deref());
    put_framework(&mut bytes, &out.framework);
    put_u32(&mut bytes, out.evidence.len());
    for item in &out.evidence {
        put_string(&mut bytes, &item.url);
        bytes.push(evidence_kind_to_u8(item.kind));
        bytes.push(extractor_to_u8(item.extractor));
        bytes.push(confidence_to_u8(item.confidence));
        match &item.shape {
            Some(shape) => {
                bytes.push(1);
                put_shape(&mut bytes, shape);
            }
            None => bytes.push(0),
        }
    }
    put_u32(&mut bytes, out.warnings.len());
    for warning in &out.warnings {
        put_string(&mut bytes, warning);
    }
    bytes
}

fn decode_output_binary(bytes: &[u8]) -> Option<Output> {
    let mut reader = BinaryReader::new(bytes);
    reader
        .take_exact(OUTPUT_BINARY_MAGIC.len())
        .filter(|magic| *magic == OUTPUT_BINARY_MAGIC)?;
    let revision = reader.opt_string()?;
    let framework = reader.framework()?;
    let evidence_len = reader.u32()? as usize;
    let mut evidence = Vec::with_capacity(evidence_len);
    for _ in 0..evidence_len {
        let url = reader.string()?;
        let kind = evidence_kind_from_u8(reader.u8()?)?;
        let extractor = extractor_from_u8(reader.u8()?)?;
        let confidence = confidence_from_u8(reader.u8()?)?;
        let shape = match reader.u8()? {
            0 => None,
            1 => Some(reader.shape()?),
            _ => return None,
        };
        evidence.push(Evidence {
            url,
            kind,
            extractor,
            confidence,
            shape,
        });
    }
    let warnings_len = reader.u32()? as usize;
    let mut warnings = Vec::with_capacity(warnings_len);
    for _ in 0..warnings_len {
        warnings.push(reader.string()?);
    }
    Some(Output {
        evidence,
        revision,
        framework,
        cache: CacheStatus::Stored,
        cache_age_secs: None,
        elapsed_us: None,
        warnings,
    })
}

fn put_shape(bytes: &mut Vec<u8>, shape: &Shape) {
    let (methods, has_body, has_headers, content_types, auth, next_server_action, query_params) =
        shape.binary_parts();
    bytes.push(methods);
    bytes.push(has_body as u8);
    bytes.push(has_headers as u8);
    bytes.push(content_types);
    bytes.push(auth as u8);
    bytes.push(next_server_action as u8);
    put_u32(bytes, query_params.len());
    for param in query_params {
        put_string(bytes, param);
    }
}

fn put_framework(bytes: &mut Vec<u8>, framework: &FrameworkConfig) {
    match framework {
        FrameworkConfig::None => bytes.push(0),
        FrameworkConfig::Next(config) => {
            bytes.push(1);
            put_opt_string(bytes, config.build_id.as_deref());
            put_opt_string(bytes, config.asset_prefix.as_deref());
            put_opt_string(bytes, config.base_path.as_deref());
            put_string_vec(bytes, &config.locales);
            put_opt_string(bytes, config.default_locale.as_deref());
            put_opt_string(bytes, config.locale.as_deref());
            put_opt_string(bytes, config.page.as_deref());
        }
        FrameworkConfig::Nuxt => bytes.push(2),
        FrameworkConfig::SvelteKit => bytes.push(3),
        FrameworkConfig::Astro => bytes.push(4),
        FrameworkConfig::Remix => bytes.push(5),
    }
}

fn put_string_vec(bytes: &mut Vec<u8>, values: &[String]) {
    put_u32(bytes, values.len());
    for value in values {
        put_string(bytes, value);
    }
}

fn put_opt_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(1);
            put_string(bytes, value);
        }
        None => bytes.push(0),
    }
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u32(bytes, value.len());
    bytes.extend_from_slice(value.as_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&(value.min(u32::MAX as usize) as u32).to_le_bytes());
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take_exact(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take_exact(4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let bytes = self.take_exact(len)?;
        std::str::from_utf8(bytes).ok().map(str::to_string)
    }

    fn opt_string(&mut self) -> Option<Option<String>> {
        match self.u8()? {
            0 => Some(None),
            1 => self.string().map(Some),
            _ => None,
        }
    }

    fn string_vec(&mut self) -> Option<Vec<String>> {
        let len = self.u32()? as usize;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.string()?);
        }
        Some(out)
    }

    fn framework(&mut self) -> Option<FrameworkConfig> {
        match self.u8()? {
            0 => Some(FrameworkConfig::None),
            1 => Some(FrameworkConfig::Next(NextConfig {
                build_id: self.opt_string()?,
                asset_prefix: self.opt_string()?,
                base_path: self.opt_string()?,
                locales: self.string_vec()?,
                default_locale: self.opt_string()?,
                locale: self.opt_string()?,
                page: self.opt_string()?,
            })),
            2 => Some(FrameworkConfig::Nuxt),
            3 => Some(FrameworkConfig::SvelteKit),
            4 => Some(FrameworkConfig::Astro),
            5 => Some(FrameworkConfig::Remix),
            _ => None,
        }
    }

    fn shape(&mut self) -> Option<Shape> {
        let methods = self.u8()?;
        let has_body = self.bool()?;
        let has_headers = self.bool()?;
        let content_types = self.u8()?;
        let auth = self.bool()?;
        let next_server_action = self.bool()?;
        let query_params = self.string_vec()?;
        Some(Shape::from_binary_parts(
            methods,
            has_body,
            has_headers,
            content_types,
            auth,
            next_server_action,
            query_params,
        ))
    }

    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

fn evidence_kind_to_u8(kind: EvidenceKind) -> u8 {
    match kind {
        EvidenceKind::Api => 0,
        EvidenceKind::Route => 1,
        EvidenceKind::Candidate => 2,
    }
}

fn evidence_kind_from_u8(value: u8) -> Option<EvidenceKind> {
    match value {
        0 => Some(EvidenceKind::Api),
        1 => Some(EvidenceKind::Route),
        2 => Some(EvidenceKind::Candidate),
        _ => None,
    }
}

fn extractor_to_u8(extractor: Extractor) -> u8 {
    match extractor {
        Extractor::Literal => 0,
        Extractor::Manifest => 1,
        Extractor::Flight => 2,
        Extractor::ApiCall => 3,
        Extractor::RouteCall => 4,
        Extractor::ServerAction => 5,
        Extractor::NuxtPayload => 6,
        Extractor::SvelteKitData => 7,
        Extractor::RemixManifest => 8,
        Extractor::AstroIsland => 9,
        Extractor::ApiClient => 10,
    }
}

fn extractor_from_u8(value: u8) -> Option<Extractor> {
    match value {
        0 => Some(Extractor::Literal),
        1 => Some(Extractor::Manifest),
        2 => Some(Extractor::Flight),
        3 => Some(Extractor::ApiCall),
        4 => Some(Extractor::RouteCall),
        5 => Some(Extractor::ServerAction),
        6 => Some(Extractor::NuxtPayload),
        7 => Some(Extractor::SvelteKitData),
        8 => Some(Extractor::RemixManifest),
        9 => Some(Extractor::AstroIsland),
        10 => Some(Extractor::ApiClient),
        _ => None,
    }
}

fn confidence_to_u8(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Observed => 0,
        Confidence::Parsed => 1,
        Confidence::Inferred => 2,
        Confidence::Candidate => 3,
    }
}

fn confidence_from_u8(value: u8) -> Option<Confidence> {
    match value {
        0 => Some(Confidence::Observed),
        1 => Some(Confidence::Parsed),
        2 => Some(Confidence::Inferred),
        3 => Some(Confidence::Candidate),
        _ => None,
    }
}

fn completion_candidates(evidence: &[Evidence]) -> Vec<String> {
    let mut set = std::collections::BTreeSet::<String>::new();
    for item in evidence {
        if !matches!(
            item.kind,
            crate::scan::EvidenceKind::Route | crate::scan::EvidenceKind::Api
        ) {
            continue;
        }
        let path = normalize_completion_path(&item.url);
        if path.is_empty() {
            continue;
        }
        set.insert(path.clone());
        let mut current = path.as_str();
        while let Some(idx) = current.rfind('/') {
            let parent = &current[..idx];
            if parent.is_empty() {
                break;
            }
            set.insert(parent.to_string());
            current = parent;
        }
    }
    set.into_iter().collect()
}

fn normalize_completion_path(raw: &str) -> String {
    let raw = raw.split(['?', '#']).next().unwrap_or(raw);
    let path = url::Url::parse(raw)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| raw.to_string());
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let trimmed = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    trimmed.replace("{dynamic}", ":id")
}

fn prune_memory(entries: &mut LruCache<String, (Body, Instant)>, now: Instant) {
    let stale = entries
        .iter()
        .filter(|(_, (_, written))| {
            now.saturating_duration_since(*written).as_secs() >= cache::CACHE_STALE_SECS
        })
        .map(|(url, _)| url.clone())
        .collect::<Vec<_>>();
    for url in stale {
        entries.pop(&url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn build_manifest_seeds_extra_chunks() {
        let addr = serve(6, |req| {
            if req.starts_with("GET /_next/static/b1/_buildManifest.js ") {
                (
                    "200 OK",
                    r#"self.__BUILD_MANIFEST={"/extra":["static/chunks/app-extra.js"]};const u="/api/from-manifest";"#,
                )
            } else if req.starts_with("GET /_next/static/chunks/app-extra.js ") {
                ("200 OK", r#"fetch("/api/from-chunk",{method:"POST"})"#)
            } else if req.starts_with("GET /_next/static/b1/_ssgManifest.js ")
                || req.starts_with("GET /_next/static/b1/app-build-manifest.json ")
                || req.starts_with("GET /_next/static/b1/_clientReferenceManifest.json ")
            {
                ("404 Not Found", "")
            } else {
                (
                    "200 OK",
                    r#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process_for_display(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();

        assert!(has_evidence(
            &out,
            crate::scan::EvidenceKind::Api,
            "/api/from-chunk"
        ));
        assert!(has_evidence(
            &out,
            crate::scan::EvidenceKind::Candidate,
            "/api/from-manifest"
        ));
    }

    #[tokio::test]
    async fn generic_html_script_assets_are_scanned() {
        let addr = serve(2, |req| {
            if req.starts_with("GET /assets/app.js ") {
                (
                    "200 OK",
                    r#"fetch("/api/from-generic-script"); const hinted="/api/from-html-asset";"#,
                )
            } else {
                (
                    "200 OK",
                    r#"<script type="module" src="/assets/app.js"></script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process_for_display(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();

        assert!(has_evidence(
            &out,
            crate::scan::EvidenceKind::Api,
            "/api/from-generic-script"
        ));
        assert!(has_evidence(
            &out,
            crate::scan::EvidenceKind::Candidate,
            "/api/from-html-asset"
        ));
    }

    #[test]
    fn memory_cached_processed_output_is_remarked_on_read() {
        let memory = memory_cache();
        let url = "https://example.com/cache-regression";
        let path =
            std::env::temp_dir().join(format!("hifi-cache-regression-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let out = Output {
            evidence: Vec::new(),
            revision: None,
            framework: FrameworkConfig::default(),
            cache: CacheStatus::Miss,
            cache_age_secs: None,
            elapsed_us: None,
            warnings: Vec::new(),
        };

        let cache_store = cache::ScanCache::at_path(path.clone());
        write_caches(&cache_store, &out, url, Some(memory.clone())).unwrap();
        let (body, age) = read_memory(&memory, url).unwrap();
        let stored = serde_json::from_str::<Output>(&body).unwrap();
        assert_eq!(stored.cache, CacheStatus::Stored);

        let marked = mark_cached_body(&body, Instant::now(), CacheStatus::Fresh, age).unwrap();
        let marked = serde_json::from_str::<Output>(&marked).unwrap();
        assert_eq!(marked.cache, CacheStatus::Fresh);
        assert_eq!(marked.cache_age_secs, Some(age));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn asset_fetch_failures_are_reported_as_warnings() {
        let addr = serve(3, |req| {
            if req.starts_with("GET /_next/static/chunks/app/ok.js ") {
                ("200 OK", r#"fetch("/api/ok")"#)
            } else if req.starts_with("GET /_next/static/chunks/app/missing.js ") {
                ("404 Not Found", "")
            } else {
                (
                    "200 OK",
                    r#"<script src="/_next/static/chunks/app/ok.js"></script><script src="/_next/static/chunks/app/missing.js"></script>"#,
                )
            }
        })
        .await;
        let client = Client::new();
        let out = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        )
        .process_for_display(&format!("http://{addr}/"), true, Instant::now())
        .await
        .unwrap();

        assert!(has_evidence(
            &out,
            crate::scan::EvidenceKind::Api,
            "/api/ok"
        ));
        assert_eq!(
            out.warnings,
            vec!["failed to read 1 assets; results may be incomplete"]
        );
    }

    #[tokio::test]
    async fn no_cache_bypasses_page_cache() {
        let count = Arc::new(AtomicUsize::new(0));
        let addr = serve(2, move |_| match count.fetch_add(1, Ordering::Relaxed) {
            0 => ("200 OK", r#"<script>fetch("/api/first")</script>"#),
            _ => ("200 OK", r#"<script>fetch("/api/second")</script>"#),
        })
        .await;
        let client = Client::new();
        let processor = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        );
        let url = format!("http://{addr}/");

        let first = processor
            .process_for_display(&url, true, Instant::now())
            .await
            .unwrap();
        let second = processor
            .process_for_display(&url, true, Instant::now())
            .await
            .unwrap();

        assert!(has_evidence(
            &first,
            crate::scan::EvidenceKind::Api,
            "/api/first"
        ));
        assert!(has_evidence(
            &second,
            crate::scan::EvidenceKind::Api,
            "/api/second"
        ));
        assert!(!has_evidence(
            &second,
            crate::scan::EvidenceKind::Api,
            "/api/first"
        ));
    }

    #[tokio::test]
    async fn fresh_processed_cache_skips_network() {
        let addr = serve(1, |_| {
            ("200 OK", r#"<script>fetch("/api/cached")</script>"#)
        })
        .await;
        let client = Client::new();
        let processor = Processor::new(
            &client,
            2,
            CacheContext {
                allow_private: true,
                ..CacheContext::default()
            },
        );
        let url = format!("http://{addr}/");

        let first = processor
            .process_for_display(&url, false, Instant::now())
            .await
            .unwrap();
        let second = processor
            .process_for_display(&url, false, Instant::now())
            .await
            .unwrap();

        assert!(has_evidence(
            &first,
            crate::scan::EvidenceKind::Api,
            "/api/cached"
        ));
        assert!(has_evidence(
            &second,
            crate::scan::EvidenceKind::Api,
            "/api/cached"
        ));
        assert_eq!(second.cache, CacheStatus::Fresh);
    }

    fn has_evidence(out: &Output, kind: crate::scan::EvidenceKind, url: &str) -> bool {
        out.evidence
            .iter()
            .any(|evidence| evidence.kind == kind && evidence.url == url)
    }

    async fn serve(
        requests: usize,
        handler: impl Fn(&str) -> (&'static str, &'static str) + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            for _ in 0..requests {
                let (mut socket, _) = listener.accept().await.unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0; 2048];
                    let n = socket.read(&mut buf).await.unwrap();
                    let (status, body) = handler(std::str::from_utf8(&buf[..n]).unwrap());
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        addr
    }
}
