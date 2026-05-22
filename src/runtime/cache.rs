//! Best-effort disk cache.
//!
//! Cache failures should not prevent a scan from succeeding. Reads return
//! `Option` and writes intentionally swallow I/O errors; callers treat cache as
//! an accelerator, not as required state.
//!
//! The cache stores processed scan output, per-site asset scan data plus HTTP
//! validators, and content-addressed chunk scan data.

use super::{
    cache_writer,
    processor::{decode_output_binary, encode_output_binary, Output},
};
use crate::{
    discover::{AssetKind, AssetRef, AssetSource, DocumentScan},
    framework::FrameworkConfig,
    scan::FindingsBuilder,
    url::Url,
};
use lru::LruCache;
use parking_lot::RwLock;
use std::{
    fs,
    num::NonZeroUsize,
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
const CHUNK_CACHE_MAX_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Clone)]
pub struct ScanCache {
    path: PathBuf,
}

impl ScanCache {
    pub fn for_base(base: &Url) -> Self {
        Self {
            path: path_for(base),
        }
    }

    pub fn read_fresh_binary(&self) -> Option<(Vec<u8>, u64)> {
        read_fresh(&binary_path_for(&self.path), CACHE_FRESH_SECS)
    }

    pub fn read_stale_binary(&self) -> Option<Vec<u8>> {
        read_fresh(&binary_path_for(&self.path), CACHE_STALE_SECS).map(|(bytes, _)| bytes)
    }

    #[allow(dead_code)]
    pub fn write_binary(&self, bytes: &[u8]) {
        write_bytes(&binary_path_for(&self.path), bytes);
    }

    pub fn write_binary_deferred(&self, bytes: Arc<[u8]>) {
        let path = binary_path_for(&self.path);
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
        if let Some(entry) = url_index_memory_get(url) {
            if entry.age_secs < CHUNK_URL_FRESH_SECS {
                return Some(entry.into_cached());
            }
        }
        let cached = read_chunk_url(url, CHUNK_URL_FRESH_SECS)?;
        url_index_memory_put(url, &cached);
        Some(cached)
    }

    pub fn read_stale_url(&self, url: &Url) -> Option<CachedChunk> {
        if let Some(entry) = url_index_memory_get(url) {
            if entry.age_secs < CHUNK_URL_STALE_SECS {
                return Some(entry.into_cached());
            }
        }
        let cached = read_chunk_url(url, CHUNK_URL_STALE_SECS)?;
        url_index_memory_put(url, &cached);
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
        self.write_arc(url, content_hash, Arc::new(asset.clone()), validators);
    }

    #[allow(dead_code)]
    pub fn write_arc(
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
                data: asset.clone(),
                age_secs: 0,
                validators: validators.clone(),
                content_hash: content_hash.to_owned(),
            },
        );
        write_chunk(url, content_hash, &asset, validators);
    }

    pub fn write_deferred(
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
                data: asset.clone(),
                age_secs: 0,
                validators: validators.clone(),
                content_hash: content_hash.to_owned(),
            },
        );
        let url = url.clone();
        let content_hash = content_hash.to_owned();
        let validators = validators.clone();
        spawn_cache_write(move || write_chunk(&url, &content_hash, &asset, &validators));
    }
}

#[derive(Clone)]
struct UrlIndexEntry {
    data: Arc<AssetData>,
    validators: AssetValidators,
    content_hash: String,
    inserted_at: SystemTime,
}

impl UrlIndexEntry {
    fn age_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.inserted_at)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX)
    }
}

struct UrlIndexHit {
    entry: UrlIndexEntry,
    age_secs: u64,
}

impl UrlIndexHit {
    fn into_cached(self) -> CachedChunk {
        CachedChunk {
            data: self.entry.data,
            age_secs: self.age_secs,
            validators: self.entry.validators,
            content_hash: self.entry.content_hash,
        }
    }
}

// Conservative caps: each entry holds a full DocumentScan or findings struct,
// which can run into tens of KB on big chunks. The caps below put the
// worst-case ceiling for both LRUs around ~50 MB combined.
const URL_INDEX_MEMORY_MAX_ENTRIES: usize = 1024;
const CONTENT_MEMORY_MAX_ENTRIES: usize = 512;

/// Process-wide in-memory cache: chunk URL -> latest known index entry.
///
/// LRU-bounded so repeated scans in a long-running process cannot grow it
/// without limit. Disk remains the source of truth past the cap.
fn url_index_memory() -> &'static RwLock<LruCache<String, UrlIndexEntry>> {
    static MEMORY: OnceLock<RwLock<LruCache<String, UrlIndexEntry>>> = OnceLock::new();
    MEMORY.get_or_init(|| {
        RwLock::new(LruCache::new(
            NonZeroUsize::new(URL_INDEX_MEMORY_MAX_ENTRIES).expect("nonzero cache size"),
        ))
    })
}

fn url_index_memory_get(url: &Url) -> Option<UrlIndexHit> {
    let mut map = url_index_memory().write();
    let entry = map.get(url.as_str())?.clone();
    let age_secs = entry.age_secs();
    Some(UrlIndexHit { entry, age_secs })
}

fn url_index_memory_put(url: &Url, cached: &CachedChunk) {
    let mut map = url_index_memory().write();
    map.put(
        url.as_str().to_owned(),
        UrlIndexEntry {
            data: cached.data.clone(),
            validators: cached.validators.clone(),
            content_hash: cached.content_hash.clone(),
            inserted_at: SystemTime::now()
                .checked_sub(std::time::Duration::from_secs(cached.age_secs))
                .unwrap_or_else(SystemTime::now),
        },
    );
}

/// Process-wide in-memory cache: content_hash -> findings.
///
/// Different URLs serving identical chunk bytes (same framework version across
/// sites) collapse to a single entry. Values are reference-counted so hits are
/// pointer clones, not deep copies of the findings struct.
fn content_memory() -> &'static RwLock<LruCache<String, Arc<FindingsBuilder>>> {
    static MEMORY: OnceLock<RwLock<LruCache<String, Arc<FindingsBuilder>>>> = OnceLock::new();
    MEMORY.get_or_init(|| {
        RwLock::new(LruCache::new(
            NonZeroUsize::new(CONTENT_MEMORY_MAX_ENTRIES).expect("nonzero cache size"),
        ))
    })
}

fn content_memory_get(content_hash: &str) -> Option<Arc<FindingsBuilder>> {
    content_memory().write().get(content_hash).cloned()
}

fn content_memory_put(content_hash: &str, findings: &FindingsBuilder) {
    let mut map = content_memory().write();
    if map.contains(content_hash) {
        return;
    }
    map.put(content_hash.to_owned(), Arc::new(findings.clone()));
}

fn binary_path_for(json_path: &Path) -> PathBuf {
    json_path.with_extension("bin")
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

pub fn path_for(base: &Url) -> PathBuf {
    scanner_hashed_path("processed", base, None, "json")
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

struct AssetEnvelope {
    data: AssetData,
    validators: AssetValidators,
}

struct ChunkIndex {
    validators: AssetValidators,
    content_hash: String,
    data: AssetData,
}

pub struct CachedChunk {
    pub data: Arc<AssetData>,
    #[allow(dead_code)]
    pub age_secs: u64,
    pub validators: AssetValidators,
    pub content_hash: String,
}

const ASSET_MAGIC: &[u8; 8] = b"HIFICA1\0";
const CHUNK_INDEX_MAGIC: &[u8; 8] = b"HIFICI1\0";
const FINDINGS_MAGIC: &[u8; 8] = b"HIFICF1\0";

fn encode_asset_envelope(envelope: &AssetEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(envelope.data.findings.evidence.len() * 48 + 128);
    out.extend_from_slice(ASSET_MAGIC);
    put_validators(&mut out, &envelope.validators);
    put_document_scan(&mut out, &envelope.data);
    out
}

fn decode_asset_envelope(bytes: &[u8]) -> Option<AssetEnvelope> {
    let mut r = super::wire::Reader::new(bytes);
    (r.take_exact(ASSET_MAGIC.len())? == ASSET_MAGIC).then_some(())?;
    let validators = read_validators(&mut r)?;
    let data = read_document_scan(&mut r)?;
    r.finish()?;
    Some(AssetEnvelope { data, validators })
}

fn encode_chunk_index(index: &ChunkIndex) -> Vec<u8> {
    let mut out = Vec::with_capacity(index.data.findings.evidence.len() * 48 + 160);
    out.extend_from_slice(CHUNK_INDEX_MAGIC);
    put_validators(&mut out, &index.validators);
    super::wire::put_string(&mut out, &index.content_hash);
    put_document_scan(&mut out, &index.data);
    out
}

fn decode_chunk_index(bytes: &[u8]) -> Option<ChunkIndex> {
    let mut r = super::wire::Reader::new(bytes);
    (r.take_exact(CHUNK_INDEX_MAGIC.len())? == CHUNK_INDEX_MAGIC).then_some(())?;
    let validators = read_validators(&mut r)?;
    let content_hash = r.string()?;
    let data = read_document_scan(&mut r)?;
    r.finish()?;
    Some(ChunkIndex {
        validators,
        content_hash,
        data,
    })
}

fn encode_findings(findings: &FindingsBuilder) -> Vec<u8> {
    let mut out = Vec::with_capacity(findings.evidence.len() * 48 + 16);
    out.extend_from_slice(FINDINGS_MAGIC);
    put_findings(&mut out, findings);
    out
}

fn decode_findings(bytes: &[u8]) -> Option<FindingsBuilder> {
    let mut r = super::wire::Reader::new(bytes);
    (r.take_exact(FINDINGS_MAGIC.len())? == FINDINGS_MAGIC).then_some(())?;
    let findings = read_findings(&mut r)?;
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

fn put_findings(out: &mut Vec<u8>, findings: &FindingsBuilder) {
    let wrapped = Output {
        evidence: findings.evidence.clone(),
        revision: None,
        framework: FrameworkConfig::None,
        cache: Default::default(),
        cache_age_secs: None,
        elapsed_us: None,
        warnings: Vec::new(),
    };
    let bytes = encode_output_binary(&wrapped);
    super::wire::put_u32(out, bytes.len());
    out.extend_from_slice(&bytes);
}

fn read_findings(r: &mut super::wire::Reader<'_>) -> Option<FindingsBuilder> {
    let len = r.u32()? as usize;
    let bytes = r.take_exact(len)?;
    Some(FindingsBuilder {
        evidence: decode_output_binary(bytes)?.evidence,
    })
}

fn put_document_scan(out: &mut Vec<u8>, data: &DocumentScan) {
    let wrapped = Output {
        evidence: data.findings.evidence.clone(),
        revision: data.revision.clone(),
        framework: data.framework_config.clone(),
        cache: Default::default(),
        cache_age_secs: None,
        elapsed_us: None,
        warnings: Vec::new(),
    };
    let bytes = encode_output_binary(&wrapped);
    super::wire::put_u32(out, bytes.len());
    out.extend_from_slice(&bytes);
    super::wire::put_u32(out, data.assets.len());
    for asset in &data.assets {
        super::wire::put_string(out, asset.url.as_str());
        out.push(asset_kind_to_u8(asset.kind));
        out.push(asset_source_to_u8(asset.source));
    }
}

fn read_document_scan(r: &mut super::wire::Reader<'_>) -> Option<DocumentScan> {
    let len = r.u32()? as usize;
    let wrapped = decode_output_binary(r.take_exact(len)?)?;
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
        findings: FindingsBuilder {
            evidence: wrapped.evidence,
        },
        assets,
        revision: wrapped.revision,
        framework_config: wrapped.framework,
    })
}

fn asset_kind_to_u8(kind: AssetKind) -> u8 {
    match kind {
        AssetKind::Script => 0,
        AssetKind::Manifest => 1,
        AssetKind::Payload => 2,
    }
}

fn asset_kind_from_u8(value: u8) -> Option<AssetKind> {
    match value {
        0 => Some(AssetKind::Script),
        1 => Some(AssetKind::Manifest),
        2 => Some(AssetKind::Payload),
        _ => None,
    }
}

fn asset_source_to_u8(source: AssetSource) -> u8 {
    match source {
        AssetSource::HtmlScript => 0,
        AssetSource::HtmlPreload => 1,
        AssetSource::Literal => 2,
        AssetSource::DynamicImport => 3,
        AssetSource::NewUrl => 4,
        AssetSource::NextManifest => 5,
        AssetSource::FrameworkManifest => 6,
    }
}

fn asset_source_from_u8(value: u8) -> Option<AssetSource> {
    match value {
        0 => Some(AssetSource::HtmlScript),
        1 => Some(AssetSource::HtmlPreload),
        2 => Some(AssetSource::Literal),
        3 => Some(AssetSource::DynamicImport),
        4 => Some(AssetSource::NewUrl),
        5 => Some(AssetSource::NextManifest),
        6 => Some(AssetSource::FrameworkManifest),
        _ => None,
    }
}

pub fn read_asset_cached(url: &Url, cache_key: Option<&str>) -> Option<CachedAsset> {
    let path = asset_path_for(url, cache_key);
    let (bytes, age_secs) = read_fresh(&path, CACHE_STALE_SECS)?;
    let envelope = decode_asset_envelope(&bytes)?;
    Some(CachedAsset {
        data: envelope.data,
        age_secs,
        validators: envelope.validators,
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
        &encode_asset_envelope(&AssetEnvelope {
            data: asset.clone(),
            validators: validators.clone(),
        }),
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
            &encode_asset_envelope(&AssetEnvelope {
                data: (*asset).clone(),
                validators,
            }),
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
        &encode_chunk_index(&ChunkIndex {
            validators: validators.clone(),
            content_hash: content_hash.to_owned(),
            data: asset.clone(),
        }),
    );
    prune_chunk_cache(CHUNK_CACHE_MAX_BYTES);
}

fn asset_path_for(url: &Url, cache_key: Option<&str>) -> PathBuf {
    scanner_hashed_path("assets", url, cache_key, "bin")
}

fn read_chunk_url(url: &Url, max_age_secs: u64) -> Option<CachedChunk> {
    let (bytes, age_secs) = read_fresh(&chunk_index_path_for(url), max_age_secs)?;
    let index = decode_chunk_index(&bytes)?;
    Some(CachedChunk {
        data: Arc::new(index.data),
        age_secs,
        validators: index.validators,
        content_hash: index.content_hash,
    })
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

fn prune_chunk_cache(max_bytes: u64) {
    let mut files = Vec::new();
    collect_cache_files(&dir().join("chunks"), &mut files);
    let mut total: u64 = files.iter().map(|entry| entry.len).sum();
    if total <= max_bytes {
        return;
    }

    files.sort_by_key(|entry| entry.modified);
    for entry in files {
        if total <= max_bytes {
            break;
        }
        if fs::remove_file(&entry.path).is_ok() {
            total = total.saturating_sub(entry.len);
        }
    }
}

struct CacheFile {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
}

fn collect_cache_files(path: &Path, out: &mut Vec<CacheFile>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            collect_cache_files(&entry.path(), out);
        } else if meta.is_file() {
            out.push(CacheFile {
                path: entry.path(),
                len: meta.len(),
                modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
    }
}

fn scanner_hashed_path(kind: &str, url: &Url, cache_key: Option<&str>, ext: &str) -> PathBuf {
    let hash = hash_parts(
        std::iter::once(SCANNER_CACHE_VERSION)
            .chain(cache_key)
            .chain(std::iter::once(url.as_str())),
    );
    hashed_path_with_hash(kind, url, hash, ext)
}

fn hashed_path_with_hash(kind: &str, url: &Url, hash: u64, ext: &str) -> PathBuf {
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
