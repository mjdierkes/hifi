//! Best-effort disk cache.
//!
//! Cache failures should not prevent a scan from succeeding. Reads return
//! `Option` and writes intentionally swallow I/O errors; callers treat cache as
//! an accelerator, not as required state.
//!
//! The cache stores processed scan output, per-site asset scan data plus HTTP
//! validators, and content-addressed chunk scan data.

use super::cache_writer;
use crate::{
    discover::{AssetKind, AssetRef, AssetSource, DocumentScan},
    framework::FrameworkConfig,
    hash::FxHashMap,
    scan::next::NextConfig,
    scan::{Confidence, Evidence, EvidenceKind, Extractor, FindingsBuilder, Shape},
    url::Url,
};
use parking_lot::RwLock;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::SystemTime,
};

const SCANNER_CACHE_VERSION: &str = env!("HIFI_BUILD_HASH");
pub const CACHE_FRESH_SECS: u64 = 300;
pub const CACHE_STALE_SECS: u64 = 3600;
pub const CHUNK_URL_FRESH_SECS: u64 = 24 * 60 * 60;
/// Wide stale window because every stale hit returns instantly and triggers a
/// background revalidate. Past this point we still revalidate in the
/// foreground via a conditional GET; the content cache makes that cheap.
pub const CHUNK_URL_STALE_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone)]
pub struct ScanCache {
    path: PathBuf,
}

impl ScanCache {
    pub fn for_base(base: &Url) -> Self {
        Self {
            path: scanner_hashed_path("processed", base, None, "bin"),
        }
    }

    pub fn read_fresh_binary(&self) -> Option<(Vec<u8>, u64)> {
        read_fresh(&self.path, CACHE_FRESH_SECS)
    }

    pub fn read_stale_binary(&self) -> Option<Vec<u8>> {
        read_fresh(&self.path, CACHE_STALE_SECS).map(|(bytes, _)| bytes)
    }

    pub fn write_binary_deferred(&self, bytes: Arc<[u8]>) {
        let path = self.path.clone();
        spawn_cache_write(move || write_bytes(&path, &bytes));
    }
}

#[derive(Clone, Copy, Default)]
pub struct ChunkCache;

impl ChunkCache {
    pub fn new() -> Self {
        Self
    }

    pub fn read_fresh_url(&self, url: &Url) -> Option<CachedChunk> {
        self.read_url(url, CHUNK_URL_FRESH_SECS)
    }

    pub fn read_stale_url(&self, url: &Url) -> Option<CachedChunk> {
        self.read_url(url, CHUNK_URL_STALE_SECS)
    }

    fn read_url(&self, url: &Url, max_age_secs: u64) -> Option<CachedChunk> {
        if let Some(cached) = url_index_memory_get(url, max_age_secs) {
            return Some(cached);
        }
        let (cached, age_secs) = read_chunk_url(url, max_age_secs)?;
        url_index_memory_put(url, &cached, age_secs);
        Some(cached)
    }

    pub fn read_content_findings(&self, content_hash: &str) -> Option<FindingsBuilder> {
        if let Some(findings) = content_memory_get(content_hash) {
            // Memory cache stores Arc<FindingsBuilder> so the hot path is a
            // pointer clone, not a deep clone of the findings struct.
            return Some((*findings).clone());
        }
        let findings = read_chunk_findings(content_hash)?;
        content_memory_put(content_hash, &findings);
        Some(findings)
    }

    #[allow(dead_code)]
    pub fn write(
        &self,
        url: &Url,
        content_hash: &str,
        asset: &AssetData,
        validators: &AssetValidators,
    ) {
        let asset = Arc::new(asset.clone());
        self.remember(url, content_hash, asset.clone(), validators);
        write_chunk(url, content_hash, &asset, validators);
    }

    pub fn write_deferred(
        &self,
        url: &Url,
        content_hash: &str,
        asset: Arc<AssetData>,
        validators: &AssetValidators,
    ) {
        self.remember(url, content_hash, asset.clone(), validators);
        let url = url.clone();
        let content_hash = content_hash.to_owned();
        let validators = validators.clone();
        spawn_cache_write(move || write_chunk(&url, &content_hash, &asset, &validators));
    }

    fn remember(
        &self,
        url: &Url,
        content_hash: &str,
        asset: Arc<AssetData>,
        validators: &AssetValidators,
    ) {
        content_memory_put(content_hash, &asset.findings);
        url_index_memory_put(
            url,
            &CachedChunk {
                data: asset,
                validators: validators.clone(),
                content_hash: content_hash.to_owned(),
            },
            0,
        );
    }
}

#[derive(Clone)]
struct UrlIndexEntry {
    cached: CachedChunk,
    inserted_at: SystemTime,
}

// Conservative caps: each entry holds a full DocumentScan or findings struct,
// which can run into tens of KB on big chunks. Disk remains the source of truth
// when the process-local accelerator is cleared.
const URL_INDEX_MEMORY_MAX_ENTRIES: usize = 1024;
const CONTENT_MEMORY_MAX_ENTRIES: usize = 512;

/// Process-wide in-memory cache: chunk URL -> latest known index entry.
fn url_index_memory() -> &'static RwLock<BoundedMemory<UrlIndexEntry>> {
    static MEMORY: OnceLock<RwLock<BoundedMemory<UrlIndexEntry>>> = OnceLock::new();
    MEMORY.get_or_init(|| RwLock::new(BoundedMemory::new(URL_INDEX_MEMORY_MAX_ENTRIES)))
}

fn url_index_memory_get(url: &Url, max_age_secs: u64) -> Option<CachedChunk> {
    let mut map = url_index_memory().write();
    let entry = map.get(url.as_str())?.clone();
    (cache_age_secs(entry.inserted_at) < max_age_secs).then_some(entry.cached)
}

fn url_index_memory_put(url: &Url, cached: &CachedChunk, age_secs: u64) {
    let mut map = url_index_memory().write();
    map.put(
        url.as_str().to_owned(),
        UrlIndexEntry {
            cached: cached.clone(),
            inserted_at: SystemTime::now()
                .checked_sub(std::time::Duration::from_secs(age_secs))
                .unwrap_or_else(SystemTime::now),
        },
    );
}

fn cache_age_secs(inserted_at: SystemTime) -> u64 {
    SystemTime::now()
        .duration_since(inserted_at)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// Process-wide in-memory cache: content_hash -> findings.
///
/// Different URLs serving identical chunk bytes (same framework version across
/// sites) collapse to a single entry. Values are reference-counted so hits are
/// pointer clones, not deep copies of the findings struct.
fn content_memory() -> &'static RwLock<BoundedMemory<Arc<FindingsBuilder>>> {
    static MEMORY: OnceLock<RwLock<BoundedMemory<Arc<FindingsBuilder>>>> = OnceLock::new();
    MEMORY.get_or_init(|| RwLock::new(BoundedMemory::new(CONTENT_MEMORY_MAX_ENTRIES)))
}

fn content_memory_get(content_hash: &str) -> Option<Arc<FindingsBuilder>> {
    content_memory().write().get(content_hash)
}

fn content_memory_put(content_hash: &str, findings: &FindingsBuilder) {
    let mut map = content_memory().write();
    map.put(content_hash.to_owned(), Arc::new(findings.clone()));
}

struct BoundedMemory<V> {
    map: FxHashMap<String, V>,
    cap: usize,
}

impl<V: Clone> BoundedMemory<V> {
    fn new(cap: usize) -> Self {
        Self {
            map: FxHashMap::default(),
            cap,
        }
    }

    fn get(&mut self, key: &str) -> Option<V> {
        self.map.get(key).cloned()
    }

    fn put(&mut self, key: String, value: V) {
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            self.map.clear();
        }
        self.map.insert(key, value);
    }
}

fn hash_parts<'a>(parts: impl Iterator<Item = &'a str>) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for p in parts {
        for b in p.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= b'\n' as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub type AssetData = DocumentScan;

#[derive(Clone, Default)]
pub struct AssetValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl AssetValidators {
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

pub struct CachedAsset {
    pub data: AssetData,
    pub age_secs: u64,
    pub validators: AssetValidators,
}

#[derive(Clone)]
pub struct CachedChunk {
    pub data: Arc<AssetData>,
    pub validators: AssetValidators,
    pub content_hash: String,
}

const ASSET_MAGIC: &[u8; 8] = b"HIFICA1\0";
const CHUNK_INDEX_MAGIC: &[u8; 8] = b"HIFICI1\0";
const FINDINGS_MAGIC: &[u8; 8] = b"HIFICF1\0";

fn encode_cached_scan(
    magic: &[u8; 8],
    validators: &AssetValidators,
    content_hash: Option<&str>,
    data: &AssetData,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.findings.evidence.len() * 48 + 160);
    out.extend_from_slice(magic);
    put_validators(&mut out, validators);
    if let Some(content_hash) = content_hash {
        super::wire::put_string(&mut out, content_hash);
    }
    put_document_scan(&mut out, data);
    out
}

fn decode_cached_scan(
    bytes: &[u8],
    magic: &[u8; 8],
    has_content_hash: bool,
) -> Option<(AssetValidators, Option<String>, AssetData)> {
    let mut r = super::wire::Reader::new(bytes);
    (r.take_exact(magic.len())? == magic).then_some(())?;
    let validators = read_validators(&mut r)?;
    let content_hash = if has_content_hash {
        Some(r.string()?)
    } else {
        None
    };
    let data = read_document_scan(&mut r)?;
    r.finish()?;
    Some((validators, content_hash, data))
}

fn encode_findings(findings: &FindingsBuilder) -> Vec<u8> {
    let mut out = Vec::with_capacity(findings.evidence.len() * 48 + 16);
    out.extend_from_slice(FINDINGS_MAGIC);
    put_evidence_vec(&mut out, &findings.evidence);
    out
}

fn decode_findings(bytes: &[u8]) -> Option<FindingsBuilder> {
    let mut r = super::wire::Reader::new(bytes);
    (r.take_exact(FINDINGS_MAGIC.len())? == FINDINGS_MAGIC).then_some(())?;
    let findings = FindingsBuilder {
        evidence: read_evidence_vec(&mut r)?,
    };
    r.finish()?;
    Some(findings)
}

fn put_validators(out: &mut Vec<u8>, validators: &AssetValidators) {
    super::wire::put_opt_string(out, validators.etag.as_deref());
    super::wire::put_opt_string(out, validators.last_modified.as_deref());
}

fn read_validators(r: &mut super::wire::Reader<'_>) -> Option<AssetValidators> {
    Some(AssetValidators {
        etag: r.opt_string()?,
        last_modified: r.opt_string()?,
    })
}

fn put_document_scan(out: &mut Vec<u8>, data: &DocumentScan) {
    put_evidence_vec(out, &data.findings.evidence);
    super::wire::put_opt_string(out, data.revision.as_deref());
    put_framework(out, &data.framework_config);
    super::wire::put_u32(out, data.assets.len());
    for asset in &data.assets {
        super::wire::put_string(out, asset.url.as_str());
        out.push(asset_kind_to_u8(asset.kind));
        out.push(asset_source_to_u8(asset.source));
    }
}

fn read_document_scan(r: &mut super::wire::Reader<'_>) -> Option<DocumentScan> {
    let evidence = read_evidence_vec(r)?;
    let revision = r.opt_string()?;
    let framework_config = read_framework(r)?;
    let asset_len = r.u32()? as usize;
    let mut assets = Vec::with_capacity(asset_len);
    for _ in 0..asset_len {
        assets.push(AssetRef {
            url: Url::parse(&r.string()?).ok()?,
            kind: asset_kind_from_u8(r.u8()?)?,
            source: asset_source_from_u8(r.u8()?)?,
        });
    }
    Some(DocumentScan {
        findings: FindingsBuilder { evidence },
        assets,
        revision,
        framework_config,
    })
}

fn put_evidence_vec(out: &mut Vec<u8>, evidence: &[Evidence]) {
    super::wire::put_u32(out, evidence.len());
    for item in evidence {
        super::wire::put_string(out, &item.url);
        out.push(evidence_kind_to_u8(item.kind));
        out.push(extractor_to_u8(item.extractor));
        out.push(confidence_to_u8(item.confidence));
        match &item.shape {
            Some(shape) => {
                out.push(1);
                put_shape(out, shape);
            }
            None => out.push(0),
        }
    }
}

fn read_evidence_vec(r: &mut super::wire::Reader<'_>) -> Option<Vec<Evidence>> {
    let len = r.u32()? as usize;
    let mut evidence = Vec::with_capacity(len);
    for _ in 0..len {
        let url = r.string()?;
        let kind = evidence_kind_from_u8(r.u8()?)?;
        let extractor = extractor_from_u8(r.u8()?)?;
        let confidence = confidence_from_u8(r.u8()?)?;
        let shape = match r.u8()? {
            0 => None,
            1 => Some(read_shape(r)?),
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
    Some(evidence)
}

fn put_shape(out: &mut Vec<u8>, shape: &Shape) {
    let (methods, has_body, has_headers, content_types, auth, next_server_action, query_params) =
        shape.binary_parts();
    out.push(methods);
    out.push(has_body as u8);
    out.push(has_headers as u8);
    out.push(content_types);
    out.push(auth as u8);
    out.push(next_server_action as u8);
    super::wire::put_string_vec(out, query_params);
}

fn read_shape(r: &mut super::wire::Reader<'_>) -> Option<Shape> {
    Some(Shape::from_binary_parts(
        r.u8()?,
        r.bool()?,
        r.bool()?,
        r.u8()?,
        r.bool()?,
        r.bool()?,
        r.string_vec()?,
    ))
}

macro_rules! u8_codec {
    ($to:ident, $from:ident, $ty:ty, { $($variant:path => $value:literal),+ $(,)? }) => {
        fn $to(value: $ty) -> u8 {
            match value {
                $($variant => $value,)+
            }
        }

        fn $from(value: u8) -> Option<$ty> {
            match value {
                $($value => Some($variant),)+
                _ => None,
            }
        }
    };
}

fn put_framework(out: &mut Vec<u8>, framework: &FrameworkConfig) {
    match framework {
        FrameworkConfig::None => out.push(0),
        FrameworkConfig::Next(config) => {
            out.push(1);
            super::wire::put_opt_string(out, config.build_id.as_deref());
            super::wire::put_opt_string(out, config.asset_prefix.as_deref());
            super::wire::put_opt_string(out, config.base_path.as_deref());
            super::wire::put_string_vec(out, &config.locales);
            super::wire::put_opt_string(out, config.default_locale.as_deref());
            super::wire::put_opt_string(out, config.locale.as_deref());
            super::wire::put_opt_string(out, config.page.as_deref());
        }
        FrameworkConfig::Nuxt => out.push(2),
        FrameworkConfig::SvelteKit => out.push(3),
        FrameworkConfig::Astro => out.push(4),
        FrameworkConfig::Remix => out.push(5),
    }
}

fn read_framework(r: &mut super::wire::Reader<'_>) -> Option<FrameworkConfig> {
    match r.u8()? {
        0 => Some(FrameworkConfig::None),
        1 => Some(FrameworkConfig::Next(NextConfig {
            build_id: r.opt_string()?,
            asset_prefix: r.opt_string()?,
            base_path: r.opt_string()?,
            locales: r.string_vec()?,
            default_locale: r.opt_string()?,
            locale: r.opt_string()?,
            page: r.opt_string()?,
        })),
        2 => Some(FrameworkConfig::Nuxt),
        3 => Some(FrameworkConfig::SvelteKit),
        4 => Some(FrameworkConfig::Astro),
        5 => Some(FrameworkConfig::Remix),
        _ => None,
    }
}

u8_codec!(evidence_kind_to_u8, evidence_kind_from_u8, EvidenceKind, {
    EvidenceKind::Api => 0,
    EvidenceKind::Route => 1,
    EvidenceKind::Candidate => 2,
});

u8_codec!(extractor_to_u8, extractor_from_u8, Extractor, {
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
});

u8_codec!(confidence_to_u8, confidence_from_u8, Confidence, {
    Confidence::Observed => 0,
    Confidence::Parsed => 1,
    Confidence::Inferred => 2,
    Confidence::Candidate => 3,
});

u8_codec!(asset_kind_to_u8, asset_kind_from_u8, AssetKind, {
    AssetKind::Script => 0,
    AssetKind::Manifest => 1,
    AssetKind::Payload => 2,
});

u8_codec!(asset_source_to_u8, asset_source_from_u8, AssetSource, {
    AssetSource::HtmlScript => 0,
    AssetSource::HtmlPreload => 1,
    AssetSource::Literal => 2,
    AssetSource::DynamicImport => 3,
    AssetSource::NewUrl => 4,
    AssetSource::NextManifest => 5,
    AssetSource::FrameworkManifest => 6,
});

pub fn read_asset_cached(url: &Url, cache_key: Option<&str>) -> Option<CachedAsset> {
    let path = asset_path_for(url, cache_key);
    let (bytes, age_secs) = read_fresh(&path, CACHE_STALE_SECS)?;
    let (validators, _, data) = decode_cached_scan(&bytes, ASSET_MAGIC, false)?;
    Some(CachedAsset {
        data,
        age_secs,
        validators,
    })
}

#[allow(dead_code)]
pub fn write_asset_with_validators(
    url: &Url,
    asset: &AssetData,
    cache_key: Option<&str>,
    validators: &AssetValidators,
) {
    let path = asset_path_for(url, cache_key);
    write_bytes(
        &path,
        &encode_cached_scan(ASSET_MAGIC, validators, None, asset),
    );
}

pub fn write_asset_with_validators_deferred(
    url: &Url,
    asset: Arc<AssetData>,
    cache_key: Option<&str>,
    validators: &AssetValidators,
) {
    let path = asset_path_for(url, cache_key);
    let validators = validators.clone();
    spawn_cache_write(move || {
        write_bytes(
            &path,
            &encode_cached_scan(ASSET_MAGIC, &validators, None, &asset),
        );
    });
}

fn read_chunk_findings(content_hash: &str) -> Option<FindingsBuilder> {
    let bytes = fs::read(chunk_content_path_for(content_hash)).ok()?;
    decode_findings(&bytes)
}

fn write_chunk(url: &Url, content_hash: &str, asset: &AssetData, validators: &AssetValidators) {
    write_bytes(
        &chunk_content_path_for(content_hash),
        &encode_findings(&asset.findings),
    );
    write_bytes(
        &chunk_index_path_for(url),
        &encode_cached_scan(CHUNK_INDEX_MAGIC, validators, Some(content_hash), asset),
    );
}

fn asset_path_for(url: &Url, cache_key: Option<&str>) -> PathBuf {
    scanner_hashed_path("assets", url, cache_key, "bin")
}

fn read_chunk_url(url: &Url, max_age_secs: u64) -> Option<(CachedChunk, u64)> {
    let (bytes, age_secs) = read_fresh(&chunk_index_path_for(url), max_age_secs)?;
    let (validators, content_hash, data) = decode_cached_scan(&bytes, CHUNK_INDEX_MAGIC, true)?;
    Some((
        CachedChunk {
            data: Arc::new(data),
            validators,
            content_hash: content_hash?,
        },
        age_secs,
    ))
}

fn spawn_cache_write(write: impl FnOnce() + Send + 'static) {
    cache_writer::defer(write);
}

fn chunk_index_path_for(url: &Url) -> PathBuf {
    let hash = hash_parts([SCANNER_CACHE_VERSION, url.as_str()].into_iter());
    let hex = format!("{hash:016x}");
    prefixed_path("chunks/url-index", &hex, "bin")
}

fn chunk_content_path_for(content_hash: &str) -> PathBuf {
    let storage_hash = hash_parts([SCANNER_CACHE_VERSION, content_hash].into_iter());
    prefixed_path(
        "chunks/content",
        &format!("{storage_hash:016x}-{content_hash}"),
        "bin",
    )
}

fn prefixed_path(kind: &str, name: &str, ext: &str) -> PathBuf {
    use std::fmt::Write;
    let base = dir();
    let prefix_len = name.len().min(2);
    let mut p = PathBuf::with_capacity(base.as_os_str().len() + kind.len() + name.len() + 8);
    p.push(base);
    p.push(kind);
    p.push(&name[..prefix_len]);
    let mut leaf = String::with_capacity(name.len() + 1 + ext.len());
    write!(&mut leaf, "{name}.{ext}").expect("write to String");
    p.push(leaf);
    p
}

fn scanner_hashed_path(kind: &str, url: &Url, cache_key: Option<&str>, ext: &str) -> PathBuf {
    let hash = hash_parts(
        std::iter::once(SCANNER_CACHE_VERSION)
            .chain(cache_key)
            .chain(std::iter::once(url.as_str())),
    );
    use std::fmt::Write;
    let base = dir();
    let mut p = PathBuf::with_capacity(base.as_os_str().len() + kind.len() + 64);
    p.push(base);
    p.push(kind);
    push_host(&mut p, url);
    let mut leaf = String::with_capacity(24 + ext.len());
    write!(&mut leaf, "{hash:016x}.{ext}").expect("write to String");
    p.push(leaf);
    p
}

fn push_host(p: &mut PathBuf, url: &Url) {
    let host = url.host_str().unwrap_or("unknown");
    if host.contains('/') {
        p.push(host.replace('/', "_"));
    } else {
        p.push(host);
    }
}

fn read_fresh(path: &Path, max_age_secs: u64) -> Option<(Vec<u8>, u64)> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?.as_secs();
    if age >= max_age_secs {
        return None;
    }
    Some((fs::read(path).ok()?, age))
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    if let Some(dir) = path.parent() {
        let _ = create_private_dir_all(dir);
    }
    let _ = write_private_file(path, bytes);
}

fn dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        platform_cache_dir().unwrap_or_else(|| PathBuf::from(".").join(".cache").join("hifi"))
    })
}

#[cfg(target_os = "macos")]
fn platform_cache_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Caches/hifi"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(xdg).join("hifi"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".cache").join("hifi"))
}

#[cfg(windows)]
fn platform_cache_dir() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"))?;
    Some(PathBuf::from(base).join("hifi").join("Cache"))
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(path)?;
    let mut cur = PathBuf::new();
    for component in path.components() {
        cur.push(component);
        if cur.starts_with(dir()) {
            let _ = fs::set_permissions(&cur, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::DocumentKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn asset_cache_is_scoped_by_cache_key() {
        let url = Url::parse(&format!(
            "https://example.com/_next/static/chunks/shared-{}.js",
            TEST_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        let v1 = crate::discover::scan_document(br#"fetch("/api/v1")"#, &url, DocumentKind::Script);
        let v2 = crate::discover::scan_document(br#"fetch("/api/v2")"#, &url, DocumentKind::Script);

        write_asset_with_validators(&url, &v1, Some("build-1"), &AssetValidators::default());
        write_asset_with_validators(&url, &v2, Some("build-2"), &AssetValidators::default());

        assert!(read_asset_cached(&url, Some("build-1"))
            .unwrap()
            .data
            .findings
            .api_map()
            .contains_key("/api/v1"));
        assert!(read_asset_cached(&url, Some("build-2"))
            .unwrap()
            .data
            .findings
            .api_map()
            .contains_key("/api/v2"));
    }

    #[test]
    fn chunk_cache_reuses_full_scan_by_url_and_content_hash() {
        let url = Url::parse(&format!(
            "https://cdn.example.com/npm/next@15/dist/framework-{}.js",
            TEST_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        let scan = crate::discover::scan_document(
            br#"fetch("/api/shared");"static/chunks/child.js""#,
            &url,
            DocumentKind::Script,
        );
        let validators = AssetValidators {
            etag: Some(r#""framework-v1""#.to_string()),
            last_modified: None,
        };
        let content_hash = blake3::hash(br#"fetch("/api/shared");"static/chunks/child.js""#)
            .to_hex()
            .to_string();

        let chunks = ChunkCache::new();
        chunks.write(&url, &content_hash, &scan, &validators);
        let cached = chunks.read_fresh_url(&url).unwrap();

        assert_eq!(cached.validators.etag.as_deref(), Some(r#""framework-v1""#));
        assert_eq!(cached.content_hash, content_hash);
        assert!(cached.data.findings.api_map().contains_key("/api/shared"));
        assert_eq!(cached.data.assets.len(), 1);
        assert!(chunks
            .read_content_findings(&content_hash)
            .unwrap()
            .api_map()
            .contains_key("/api/shared"));
    }
}
