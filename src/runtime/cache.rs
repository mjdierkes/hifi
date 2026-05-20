use crate::scan::{ApiMap, CandidateMap, RouteMap};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use url::Url;

pub fn fingerprint(chunks: &[Url]) -> String {
    let mut paths: Vec<&str> = chunks.iter().map(|u| u.path()).collect();
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
    hashed_path("processed", base, "json")
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChunkData {
    pub apis: ApiMap,
    #[serde(default, skip_serializing_if = "RouteMap::is_empty")]
    pub routes: RouteMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
    pub refs: Vec<Url>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ChunkValidators {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl ChunkValidators {
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

pub struct CachedChunk {
    pub data: ChunkData,
    pub age_secs: u64,
    pub validators: ChunkValidators,
}

pub fn read_chunk(url: &Url, cache_key: Option<&str>) -> Option<ChunkData> {
    let cached = read_chunk_cached(url, cache_key)?;
    (cached.age_secs < super::processor::CACHE_FRESH_SECS).then_some(cached.data)
}

pub fn read_chunk_cached(url: &Url, cache_key: Option<&str>) -> Option<CachedChunk> {
    let path = chunk_path_for(url, cache_key);
    let (bytes, age_secs) = read_fresh(&path, super::processor::CACHE_STALE_SECS)?;
    let data = serde_json::from_slice(&bytes).ok()?;
    Some(CachedChunk {
        data,
        age_secs,
        validators: read_chunk_validators(&path).unwrap_or_default(),
    })
}

pub fn write_chunk(url: &Url, chunk: &ChunkData, cache_key: Option<&str>) {
    write_chunk_with_validators(url, chunk, cache_key, &ChunkValidators::default());
}

pub fn write_chunk_with_validators(
    url: &Url,
    chunk: &ChunkData,
    cache_key: Option<&str>,
    validators: &ChunkValidators,
) {
    let path = chunk_path_for(url, cache_key);
    write_json(&path, chunk);
    write_chunk_validators(&path, validators);
}

pub fn read_bundle_pack(seed: &[Url], cache_key: Option<&str>) -> Option<Vec<(Url, Vec<u8>)>> {
    let (bytes, _) = read_fresh(
        &bundle_pack_path_for(seed, cache_key)?,
        super::processor::CACHE_FRESH_SECS,
    )?;
    parse_bundle_pack(&bytes)
}

pub fn write_bundle_pack(seed: &[Url], entries: &[(Url, Vec<u8>)], cache_key: Option<&str>) {
    let Some(path) = bundle_pack_path_for(seed, cache_key) else {
        return;
    };
    let bytes_len = entries
        .iter()
        .map(|(url, body)| 12 + url.as_str().len() + body.len())
        .sum::<usize>();
    let mut out = Vec::with_capacity(BUNDLE_PACK_MAGIC.len() + bytes_len);
    out.extend_from_slice(BUNDLE_PACK_MAGIC);
    for (url, body) in entries {
        let url = url.as_str().as_bytes();
        out.extend_from_slice(&(url.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(url);
        out.extend_from_slice(body);
    }
    write_bytes(&path, &out);
}

pub fn read_page(url: &Url) -> Option<(Vec<u8>, Url)> {
    let path = page_path_for(url);
    let (body, _) = read_fresh(&path, super::processor::CACHE_STALE_SECS)?;
    let final_url = fs::read_to_string(url_sidecar_path(&path))
        .ok()
        .and_then(|s| Url::parse(s.trim()).ok())
        .unwrap_or_else(|| url.clone());
    Some((body, final_url))
}

pub fn write_page(url: &Url, final_url: &Url, bytes: &[u8]) {
    let path = page_path_for(url);
    write_bytes(&path, bytes);
    write_bytes(&url_sidecar_path(&path), final_url.as_str().as_bytes());
}

fn chunk_path_for(url: &Url, cache_key: Option<&str>) -> PathBuf {
    keyed_hashed_path("chunks", url, cache_key, "json")
}

fn bundle_pack_path_for(seed: &[Url], cache_key: Option<&str>) -> Option<PathBuf> {
    let first = seed.first()?;
    let mut parts: Vec<&str> = seed.iter().map(|u| u.as_str()).collect();
    parts.sort();
    let key = cache_key.unwrap_or("");
    let hash = hash_parts(std::iter::once(key).chain(parts));
    Some(
        dir()
            .join("bundle-packs")
            .join(host(first))
            .join(format!("{hash:016x}.bin")),
    )
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

fn keyed_hashed_path(kind: &str, url: &Url, cache_key: Option<&str>, ext: &str) -> PathBuf {
    let hash = hash_parts(cache_key.into_iter().chain(std::iter::once(url.as_str())));
    dir()
        .join(kind)
        .join(host(url))
        .join(format!("{hash:016x}.{ext}"))
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("unknown").replace('/', "_")
}

const BUNDLE_PACK_MAGIC: &[u8] = b"HIFI-BUNDLEPACK-1\n";

fn parse_bundle_pack(bytes: &[u8]) -> Option<Vec<(Url, Vec<u8>)>> {
    let mut pos = BUNDLE_PACK_MAGIC.len();
    bytes.starts_with(BUNDLE_PACK_MAGIC).then_some(())?;
    let mut entries = Vec::new();
    while pos < bytes.len() {
        let url_len = read_u32(bytes, &mut pos)? as usize;
        let body_len = read_u64(bytes, &mut pos)? as usize;
        let url_end = pos.checked_add(url_len)?;
        let body_end = url_end.checked_add(body_len)?;
        if body_end > bytes.len() {
            return None;
        }
        let url = std::str::from_utf8(&bytes[pos..url_end]).ok()?;
        let url = Url::parse(url).ok()?;
        entries.push((url, bytes[url_end..body_end].to_vec()));
        pos = body_end;
    }
    Some(entries)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let value = u32::from_le_bytes(bytes.get(*pos..end)?.try_into().ok()?);
    *pos = end;
    Some(value)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let value = u64::from_le_bytes(bytes.get(*pos..end)?.try_into().ok()?);
    *pos = end;
    Some(value)
}

pub fn read_build_bytes(path: &Path, build_id: Option<&str>) -> Option<Vec<u8>> {
    let expected = build_id?;
    (read_build_id(path)? == expected).then(|| fs::read(path).ok())?
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

pub fn write_with_build_id<T: Serialize>(path: &Path, value: &T, build_id: Option<&str>) {
    write_json(path, value);
    if let Some(build_id) = build_id {
        write_bytes(&meta_path(path), build_id.as_bytes());
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

fn read_build_id(path: &Path) -> Option<String> {
    let meta_path = meta_path(path);
    let bytes = fs::read(meta_path).ok()?;
    let id = std::str::from_utf8(&bytes).ok()?.trim_end();
    (!id.is_empty()).then(|| id.to_string())
}

fn read_chunk_validators(path: &Path) -> Option<ChunkValidators> {
    let bytes = fs::read(validators_path(path)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_chunk_validators(path: &Path, validators: &ChunkValidators) {
    let path = validators_path(path);
    if validators.is_empty() {
        let _ = fs::remove_file(path);
    } else {
        write_json(&path, validators);
    }
}

fn meta_path(path: &Path) -> PathBuf {
    let mut meta = path.as_os_str().to_os_string();
    meta.push(".build");
    meta.into()
}

fn validators_path(path: &Path) -> PathBuf {
    let mut meta = path.as_os_str().to_os_string();
    meta.push(".http");
    meta.into()
}

fn url_sidecar_path(path: &Path) -> PathBuf {
    let mut meta = path.as_os_str().to_os_string();
    meta.push(".url");
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
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_PATH_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn cache_without_build_sidecar_is_ignored() {
        let path = test_path();
        std::fs::write(&path, br#"{"build_id":"a","apis":{}}"#).unwrap();

        assert!(read_build_bytes(&path, Some("a")).is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn chunk_cache_round_trips_api_map_and_refs() {
        let url = Url::parse("https://example.com/_next/static/chunks/app-abc.js").unwrap();
        let path = chunk_path_for(&url, Some("b1"));
        let _ = std::fs::remove_file(&path);

        let mut apis = ApiMap::default();
        crate::scan::scan(br#"fetch("/api/users", {method:"POST"})"#, &mut apis);
        let refs = vec![Url::parse("https://example.com/_next/static/chunks/app-def.js").unwrap()];

        write_chunk(
            &url,
            &ChunkData {
                apis: apis.clone(),
                routes: RouteMap::default(),
                candidates: CandidateMap::default(),
                refs: refs.clone(),
            },
            Some("b1"),
        );
        let cached = read_chunk(&url, Some("b1")).unwrap();

        assert_eq!(
            serde_json::to_value(&cached.apis).unwrap(),
            serde_json::to_value(&apis).unwrap()
        );
        assert_eq!(cached.refs, refs);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn chunk_cache_is_scoped_by_cache_key() {
        let url = Url::parse(&format!(
            "https://example.com/_next/static/chunks/shared-{}.js",
            TEST_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        let mut v1 = ApiMap::default();
        let mut v2 = ApiMap::default();
        crate::scan::scan(br#"fetch("/api/v1")"#, &mut v1);
        crate::scan::scan(br#"fetch("/api/v2")"#, &mut v2);

        write_chunk(
            &url,
            &ChunkData {
                apis: v1,
                routes: RouteMap::default(),
                candidates: CandidateMap::default(),
                refs: Vec::new(),
            },
            Some("build-1"),
        );
        write_chunk(
            &url,
            &ChunkData {
                apis: v2,
                routes: RouteMap::default(),
                candidates: CandidateMap::default(),
                refs: Vec::new(),
            },
            Some("build-2"),
        );

        assert!(read_chunk(&url, Some("build-1"))
            .unwrap()
            .apis
            .contains_key("/api/v1"));
        assert!(read_chunk(&url, Some("build-2"))
            .unwrap()
            .apis
            .contains_key("/api/v2"));
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
        let _ = std::fs::remove_file(url_sidecar_path(&path));

        write_page(&url, &final_url, body);
        let (cached_body, cached_final_url) = read_page(&url).unwrap();

        assert_eq!(cached_body, body);
        assert_eq!(cached_final_url, final_url);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(url_sidecar_path(&path));
    }

    #[test]
    fn bundle_pack_round_trips_entries() {
        let a = Url::parse(&format!(
            "https://example.com/_next/static/chunks/a-{}.js",
            TEST_PATH_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        let b = Url::parse("https://example.com/_next/static/chunks/b.js").unwrap();
        let seed = vec![a.clone()];
        let path = bundle_pack_path_for(&seed, Some("b1")).unwrap();
        let _ = std::fs::remove_file(&path);

        write_bundle_pack(
            &seed,
            &[
                (a.clone(), b"fetch('/api/a')".to_vec()),
                (b.clone(), b"fetch('/api/b')".to_vec()),
            ],
            Some("b1"),
        );
        let entries = read_bundle_pack(&seed, Some("b1")).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, a);
        assert_eq!(entries[0].1, b"fetch('/api/a')");
        assert_eq!(entries[1].0, b);
        assert_eq!(entries[1].1, b"fetch('/api/b')");
        let _ = std::fs::remove_file(path);
    }

    fn test_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = TEST_PATH_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("hifi-cache-test-{nanos}-{id}.json"))
    }
}
