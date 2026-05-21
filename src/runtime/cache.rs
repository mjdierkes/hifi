//! Best-effort disk cache.
//!
//! Cache failures should not prevent a scan from succeeding. Reads return
//! `Option` and writes intentionally swallow I/O errors; callers treat cache as
//! an accelerator, not as required state.
//!
//! The cache stores three related artifacts: processed scan output, root pages
//! plus final redirected URL, and per-asset scan data plus HTTP validators.

use crate::discover::{AssetRef, DocumentScan};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use url::Url;

const SCANNER_CACHE_VERSION: &str = env!("HIFI_BUILD_HASH");

pub fn fingerprint_assets(assets: &[AssetRef]) -> String {
    let mut paths: Vec<&str> = assets.iter().map(|asset| asset.url.path()).collect();
    paths.sort();

    format!("{:016x}", hash_parts(paths.into_iter()))
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

pub fn read_asset_cached(url: &Url, cache_key: Option<&str>) -> Option<CachedAsset> {
    let path = asset_path_for(url, cache_key);
    let (bytes, age_secs) = read_fresh(&path, super::processor::CACHE_STALE_SECS)?;
    let data = serde_json::from_slice(&bytes).ok()?;
    Some(CachedAsset {
        data,
        age_secs,
        validators: read_asset_validators(&path).unwrap_or_default(),
    })
}

pub fn write_asset_with_validators(
    url: &Url,
    asset: &AssetData,
    cache_key: Option<&str>,
    validators: &AssetValidators,
) {
    let path = asset_path_for(url, cache_key);
    write_json(&path, asset);
    write_asset_validators(&path, validators);
}

pub fn read_page(url: &Url) -> Option<(Vec<u8>, Url)> {
    let path = page_path_for(url);
    let (body, _) = read_fresh(&path, super::processor::CACHE_STALE_SECS)?;
    let final_url = fs::read_to_string(sidecar_path(&path, ".url"))
        .ok()
        .and_then(|s| Url::parse(s.trim()).ok())
        .unwrap_or_else(|| url.clone());
    Some((body, final_url))
}

pub fn write_page(url: &Url, final_url: &Url, bytes: &[u8]) {
    let path = page_path_for(url);
    write_bytes(&path, bytes);
    write_bytes(&sidecar_path(&path, ".url"), final_url.as_str().as_bytes());
}

fn asset_path_for(url: &Url, cache_key: Option<&str>) -> PathBuf {
    scanner_hashed_path("assets", url, cache_key, "json")
}

fn page_path_for(url: &Url) -> PathBuf {
    hashed_path("pages", url, "html")
}

fn hashed_path(kind: &str, url: &Url, ext: &str) -> PathBuf {
    let hash = hash_parts(std::iter::once(url.as_str()));
    dir()
        .join(kind)
        .join(host(url))
        .join(format!("{hash:016x}.{ext}"))
}

fn scanner_hashed_path(kind: &str, url: &Url, cache_key: Option<&str>, ext: &str) -> PathBuf {
    let hash = hash_parts(
        std::iter::once(SCANNER_CACHE_VERSION)
            .chain(cache_key)
            .chain(std::iter::once(url.as_str())),
    );
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
    (read_revision(path)? == expected).then(|| fs::read(path).ok())?
}

pub fn read_any_bytes(path: &Path) -> Option<(Vec<u8>, u64)> {
    read_fresh(path, u64::MAX)
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
    write_json(path, value);
    if let Some(revision) = revision {
        write_bytes(&sidecar_path(path, ".revision"), revision.as_bytes());
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
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

fn read_revision(path: &Path) -> Option<String> {
    let meta_path = sidecar_path(path, ".revision");
    let bytes = fs::read(meta_path).ok()?;
    let id = std::str::from_utf8(&bytes).ok()?.trim_end();
    (!id.is_empty()).then(|| id.to_string())
}

fn read_asset_validators(path: &Path) -> Option<AssetValidators> {
    let bytes = fs::read(sidecar_path(path, ".http")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_asset_validators(path: &Path, validators: &AssetValidators) {
    let path = sidecar_path(path, ".http");
    if validators.is_empty() {
        let _ = fs::remove_file(path);
    } else {
        write_json(&path, validators);
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut meta = path.as_os_str().to_os_string();
    meta.push(suffix);
    meta.into()
}

fn dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".cache/hifi")
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
    use crate::discover::{AssetKind, AssetSource, DocumentKind};
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
            .apis
            .contains_key("/api/v1"));
        assert!(read_asset_cached(&url, Some("build-2"))
            .unwrap()
            .data
            .findings
            .apis
            .contains_key("/api/v2"));
    }

    #[test]
    fn fingerprint_uses_asset_urls() {
        let assets = vec![AssetRef {
            url: Url::parse("https://example.com/assets/app.js").unwrap(),
            kind: AssetKind::Script,
            source: AssetSource::HtmlScript,
        }];

        assert_eq!(fingerprint_assets(&assets).len(), 16);
    }

    #[test]
    fn page_cache_round_trips_body_and_final_url() {
        let url = Url::parse(&format!(
            "https://example.com/page-{}",
            TEST_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        let final_url = Url::parse("https://www.example.com/page").unwrap();
        let path = page_path_for(&url);
        let body = b"<script src=\"/_next/static/chunks/app.js\"></script>";
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".url"));

        write_page(&url, &final_url, body);
        let (cached_body, cached_final_url) = read_page(&url).unwrap();

        assert_eq!(cached_body, body);
        assert_eq!(cached_final_url, final_url);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, ".url"));
    }
}
