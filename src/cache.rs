use crate::scan::ApiMap;
use serde::{Deserialize, Serialize};
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

pub fn path_for(base: &Url) -> std::path::PathBuf {
    let host = base.host_str().unwrap_or("unknown").replace('/', "_");
    dir().join(format!("{host}.json"))
}

pub struct CachedChunk {
    pub apis: ApiMap,
    pub refs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ChunkFile {
    apis: ApiMap,
    refs: Vec<String>,
}

pub fn read_chunk(url: &Url) -> Option<CachedChunk> {
    let bytes = std::fs::read(chunk_path_for(url)).ok()?;
    let chunk = serde_json::from_slice::<ChunkFile>(&bytes).ok()?;
    Some(CachedChunk {
        apis: chunk.apis,
        refs: chunk.refs,
    })
}

pub fn write_chunk(url: &Url, apis: &ApiMap, refs: &[Url]) {
    let path = chunk_path_for(url);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let refs = refs.iter().map(|u| u.as_str().to_string()).collect();
    let chunk = ChunkFile {
        apis: apis.clone(),
        refs,
    };
    if let Ok(bytes) = serde_json::to_vec(&chunk) {
        let _ = std::fs::write(path, bytes);
    }
}

fn chunk_path_for(url: &Url) -> std::path::PathBuf {
    let host = url.host_str().unwrap_or("unknown").replace('/', "_");
    let hash = hash_parts(std::iter::once(url.as_str()));
    dir()
        .join("chunks")
        .join(host)
        .join(format!("{hash:016x}.json"))
}

pub fn read(path: &std::path::Path, build_id: Option<&str>) -> Option<serde_json::Value> {
    let expected = build_id?;
    if let Some(cached) = read_build_id(path) {
        return (cached == expected).then(|| read_any(path).map(|(v, _)| v))?;
    }

    let (v, _) = read_any(path)?;
    let cached_build = v.get("build_id").and_then(|b| b.as_str());
    (cached_build == Some(expected)).then_some(v)
}

pub fn read_any(path: &std::path::Path) -> Option<(serde_json::Value, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .ok()?
        .as_secs();
    let v = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    Some((v, age))
}

pub fn write(path: &std::path::Path, value: &serde_json::Value) -> Option<Vec<u8>> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let bytes = serde_json::to_vec(value).ok()?;
    let _ = std::fs::write(path, &bytes);
    write_meta(path, value);
    Some(bytes)
}

fn read_build_id(path: &std::path::Path) -> Option<String> {
    let meta_path = meta_path(path);
    let bytes = std::fs::read(meta_path).ok()?;
    let id = std::str::from_utf8(&bytes).ok()?.trim_end();
    (!id.is_empty()).then(|| id.to_string())
}

fn write_meta(path: &std::path::Path, value: &serde_json::Value) {
    if let Some(build_id) = value.get("build_id").and_then(|b| b.as_str()) {
        let _ = std::fs::write(meta_path(path), build_id);
    }
}

fn meta_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut meta = path.as_os_str().to_os_string();
    meta.push(".build");
    meta.into()
}

fn dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".cache/hifi")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn build_id_sidecar_skips_mismatched_cache_body() {
        let path = test_path();
        write(&path, &json!({"build_id": "a", "apis": {}}));

        assert!(read(&path, Some("b")).is_none());
        assert!(read(&path, Some("a")).is_some());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(meta_path(&path));
    }

    #[test]
    fn chunk_cache_round_trips_api_map_and_refs() {
        let url = Url::parse("https://example.com/_next/static/chunks/app-abc.js").unwrap();
        let path = chunk_path_for(&url);
        let _ = std::fs::remove_file(&path);

        let mut apis = ApiMap::default();
        crate::scan::scan(br#"fetch("/api/users", {method:"POST"})"#, &mut apis);
        let refs = vec![Url::parse("https://example.com/_next/static/chunks/app-def.js").unwrap()];

        write_chunk(&url, &apis, &refs);
        let cached = read_chunk(&url).unwrap();

        assert_eq!(
            serde_json::to_value(&cached.apis).unwrap(),
            serde_json::to_value(&apis).unwrap()
        );
        assert_eq!(cached.refs, vec![refs[0].as_str()]);

        let _ = std::fs::remove_file(path);
    }

    fn test_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hifi-cache-test-{nanos}.json"))
    }
}
