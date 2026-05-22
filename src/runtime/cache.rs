//! Best-effort disk cache.
//!
//! Cache failures should not prevent a scan from succeeding. Reads return
//! `Option` and writes intentionally swallow I/O errors; callers treat cache as
//! an accelerator, not as required state.
//!
//! The cache stores three related artifacts: processed scan output, root pages
//! plus final redirected URL, and per-asset scan data plus HTTP validators.

use crate::discover::{DocumentKind, DocumentScan};
use crate::scan::FindingsBuilder;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use url::Url;

const SCANNER_CACHE_VERSION: &str = env!("HIFI_BUILD_HASH");
pub const CACHE_FRESH_SECS: u64 = 300;
pub const CACHE_STALE_SECS: u64 = 3600;

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

    #[cfg(test)]
    pub fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn read_fresh_bytes(&self) -> Option<(Vec<u8>, u64)> {
        read_cached_value_bytes(&self.path, CACHE_FRESH_SECS)
    }

    pub fn read_revision_bytes(&self, revision: Option<&str>) -> Option<Vec<u8>> {
        read_revision_bytes(&self.path, revision)
    }

    pub fn write_with_revision<T: Serialize>(&self, value: &T, revision: Option<&str>) {
        write_with_revision(&self.path, value, revision);
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

pub fn path_for(base: &Url) -> PathBuf {
    scanner_hashed_path("processed", base, None, "json")
}

pub fn completion_path_for(base: &Url) -> PathBuf {
    hashed_path("completions", base, None, "json")
}

pub type AssetData = DocumentScan;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AssetValidators {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Serialize, Deserialize)]
struct AssetEnvelope {
    data: AssetData,
    #[serde(default, skip_serializing_if = "AssetValidators::is_empty")]
    validators: AssetValidators,
}

#[derive(Serialize, Deserialize)]
struct RevisionEnvelope<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    value: T,
}

pub fn read_asset_cached(url: &Url, cache_key: Option<&str>) -> Option<CachedAsset> {
    let path = asset_path_for(url, cache_key);
    let (bytes, age_secs) = read_fresh(&path, CACHE_STALE_SECS)?;
    let envelope: AssetEnvelope = serde_json::from_slice(&bytes).ok()?;
    Some(CachedAsset {
        data: envelope.data,
        age_secs,
        validators: envelope.validators,
    })
}

pub fn write_asset_with_validators(
    url: &Url,
    asset: &AssetData,
    cache_key: Option<&str>,
    validators: &AssetValidators,
) {
    let path = asset_path_for(url, cache_key);
    write_json(
        &path,
        &AssetEnvelope {
            data: asset.clone(),
            validators: validators.clone(),
        },
    );
}

pub fn body_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub fn read_findings_by_hash(hash: u64, kind: DocumentKind) -> Option<FindingsBuilder> {
    let path = findings_hash_path(hash, kind);
    let (bytes, _) = read_fresh(&path, CACHE_STALE_SECS)?;
    serde_json::from_slice(&bytes).ok()
}

pub fn write_findings_by_hash(hash: u64, kind: DocumentKind, findings: &FindingsBuilder) {
    write_json(&findings_hash_path(hash, kind), findings);
}

fn asset_path_for(url: &Url, cache_key: Option<&str>) -> PathBuf {
    scanner_hashed_path("assets", url, cache_key, "json")
}

fn findings_hash_path(hash: u64, kind: DocumentKind) -> PathBuf {
    let kind = match kind {
        DocumentKind::Html => "html",
        DocumentKind::Script => "script",
        DocumentKind::Manifest => "manifest",
        DocumentKind::Payload => "payload",
    };
    let cache_hash = hash_parts(
        [SCANNER_CACHE_VERSION, kind, &format!("{hash:016x}")]
            .into_iter()
            .map(|s| s as &str),
    );
    dir()
        .join("findings")
        .join(kind)
        .join(format!("{cache_hash:016x}.json"))
}

fn scanner_hashed_path(kind: &str, url: &Url, cache_key: Option<&str>, ext: &str) -> PathBuf {
    let hash = hash_parts(
        std::iter::once(SCANNER_CACHE_VERSION)
            .chain(cache_key)
            .chain(std::iter::once(url.as_str())),
    );
    hashed_path_with_hash(kind, url, hash, ext)
}

fn hashed_path(kind: &str, url: &Url, cache_key: Option<&str>, ext: &str) -> PathBuf {
    let hash = hash_parts(cache_key.into_iter().chain(std::iter::once(url.as_str())));
    hashed_path_with_hash(kind, url, hash, ext)
}

fn hashed_path_with_hash(kind: &str, url: &Url, hash: u64, ext: &str) -> PathBuf {
    dir()
        .join(kind)
        .join(host(url))
        .join(format!("{hash:016x}.{ext}"))
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("unknown").replace('/', "_")
}

pub fn read_revision_bytes(path: &Path, revision: Option<&str>) -> Option<Vec<u8>> {
    let expected = revision?;
    let envelope: RevisionEnvelope<serde_json::Value> =
        serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (envelope.revision.as_deref() == Some(expected))
        .then(|| serde_json::to_vec(&envelope.value).ok())?
}

pub fn read_cached_value_bytes(path: &Path, max_age_secs: u64) -> Option<(Vec<u8>, u64)> {
    let (bytes, age_secs) = read_fresh(path, max_age_secs)?;
    let envelope: RevisionEnvelope<serde_json::Value> = serde_json::from_slice(&bytes).ok()?;
    Some((serde_json::to_vec(&envelope.value).ok()?, age_secs))
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

pub fn write_with_revision<T: Serialize>(path: &Path, value: &T, revision: Option<&str>) {
    write_json(
        path,
        &RevisionEnvelope {
            revision: revision.map(str::to_string),
            value,
        },
    );
}

pub fn read_completion_candidates(base: &Url) -> Option<Vec<String>> {
    serde_json::from_slice(&fs::read(completion_path_for(base)).ok()?).ok()
}

pub fn write_completion_candidates(base: &Url, candidates: &[String]) {
    write_json(&completion_path_for(base), candidates);
}

fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        write_bytes(path, &bytes);
    }
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    if let Some(dir) = path.parent() {
        let _ = create_private_dir_all(dir);
    }
    let _ = write_private_file(path, bytes);
}

/// Hostnames present in the on-disk cache, sorted and deduplicated across cache kinds.
/// Used by shell completion to suggest previously scanned sites.
pub fn cached_hosts() -> Vec<String> {
    let mut hosts = std::collections::BTreeSet::new();
    for kind in ["processed", "assets"] {
        let Ok(entries) = fs::read_dir(dir().join(kind)) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if !name.is_empty() && name != "unknown" {
                    hosts.insert(name.to_string());
                }
            }
        }
    }
    hosts.into_iter().collect()
}

fn dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "hifi")
        .map(|dirs| dirs.cache_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".").join(".cache").join("hifi"))
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
}
