use crate::scan::{ApiMap, CandidateMap};
use rustc_hash::FxHashMap;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt, fs,
    hash::Hash,
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
    let host = base.host_str().unwrap_or("unknown").replace('/', "_");
    dir().join(format!("{host}.json"))
}

#[derive(Clone)]
pub struct ChunkData {
    pub apis: ApiMap,
    pub candidates: CandidateMap,
    pub refs: Vec<Url>,
}

impl Serialize for ChunkData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let refs: Vec<&str> = self.refs.iter().map(Url::as_str).collect();
        let mut st = serializer.serialize_struct("ChunkData", 3)?;
        st.serialize_field("apis", &self.apis)?;
        st.serialize_field("candidates", &self.candidates)?;
        st.serialize_field("refs", &refs)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for ChunkData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        enum Field {
            Apis,
            Candidates,
            Refs,
            Ignore,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("chunk field")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        Ok(match value {
                            "apis" => Field::Apis,
                            "candidates" => Field::Candidates,
                            "refs" => Field::Refs,
                            _ => Field::Ignore,
                        })
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ChunkVisitor;

        impl<'de> Visitor<'de> for ChunkVisitor {
            type Value = ChunkData;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("chunk data object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut apis = ApiMap::default();
                let mut candidates = CandidateMap::default();
                let mut refs = Vec::new();
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Apis => apis = map.next_value()?,
                        Field::Candidates => candidates = map.next_value()?,
                        Field::Refs => {
                            let raw: Vec<String> = map.next_value()?;
                            refs = raw
                                .into_iter()
                                .filter_map(|s| Url::parse(&s).ok())
                                .collect();
                        }
                        Field::Ignore => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(ChunkData {
                    apis,
                    candidates,
                    refs,
                })
            }
        }

        deserializer.deserialize_struct("ChunkData", &["apis", "candidates", "refs"], ChunkVisitor)
    }
}

pub fn read_chunk(url: &Url) -> Option<ChunkData> {
    serde_json::from_slice(&fs::read(chunk_path_for(url)).ok()?).ok()
}

pub fn write_chunk(url: &Url, chunk: &ChunkData) {
    write_json(&chunk_path_for(url), chunk);
}

fn chunk_path_for(url: &Url) -> PathBuf {
    let host = url.host_str().unwrap_or("unknown").replace('/', "_");
    let hash = hash_parts(std::iter::once(url.as_str()));
    dir()
        .join("chunks")
        .join(host)
        .join(format!("{hash:016x}.json"))
}

pub fn read(path: &Path, build_id: Option<&str>) -> Option<serde_json::Value> {
    let expected = build_id?;
    (read_build_id(path)? == expected).then(|| read_any(path).map(|(v, _)| v))?
}

pub fn read_any(path: &Path) -> Option<(serde_json::Value, u64)> {
    let (bytes, age) = read_any_bytes(path)?;
    let v = serde_json::from_slice(&bytes).ok()?;
    Some((v, age))
}

pub fn read_build_bytes(path: &Path, build_id: Option<&str>) -> Option<Vec<u8>> {
    let expected = build_id?;
    (read_build_id(path)? == expected).then(|| fs::read(path).ok())?
}

pub fn read_any_bytes(path: &Path) -> Option<(Vec<u8>, u64)> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?.as_secs();
    Some((fs::read(path).ok()?, age))
}

pub fn write(path: &Path, value: &serde_json::Value) {
    write_json(path, value);
    write_meta(path, value);
}

pub fn write_with_build_id<T: Serialize>(path: &Path, value: &T, build_id: Option<&str>) {
    write_json(path, value);
    if let Some(build_id) = build_id {
        let _ = fs::write(meta_path(path), build_id);
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(bytes) = serde_json::to_vec(value) {
        let _ = fs::write(path, bytes);
    }
}

pub fn prune_overflow<K: Clone + Eq + Hash, V>(entries: &mut FxHashMap<K, V>, max: usize) {
    let overflow = entries.len().saturating_sub(max);
    for key in entries.keys().take(overflow).cloned().collect::<Vec<_>>() {
        entries.remove(&key);
    }
}

fn read_build_id(path: &Path) -> Option<String> {
    let meta_path = meta_path(path);
    let bytes = fs::read(meta_path).ok()?;
    let id = std::str::from_utf8(&bytes).ok()?.trim_end();
    (!id.is_empty()).then(|| id.to_string())
}

fn write_meta(path: &Path, value: &serde_json::Value) {
    if let Some(build_id) = value.get("build_id").and_then(|b| b.as_str()) {
        let _ = fs::write(meta_path(path), build_id);
    }
}

fn meta_path(path: &Path) -> PathBuf {
    let mut meta = path.as_os_str().to_os_string();
    meta.push(".build");
    meta.into()
}

fn dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".cache/hifi")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_PATH_ID: AtomicU64 = AtomicU64::new(0);

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
    fn cache_without_build_sidecar_is_ignored() {
        let path = test_path();
        std::fs::write(&path, br#"{"build_id":"a","apis":{}}"#).unwrap();

        assert!(read(&path, Some("a")).is_none());
        assert!(read_build_bytes(&path, Some("a")).is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn chunk_cache_round_trips_api_map_and_refs() {
        let url = Url::parse("https://example.com/_next/static/chunks/app-abc.js").unwrap();
        let path = chunk_path_for(&url);
        let _ = std::fs::remove_file(&path);

        let mut apis = ApiMap::default();
        crate::scan::scan(br#"fetch("/api/users", {method:"POST"})"#, &mut apis);
        let refs = vec![Url::parse("https://example.com/_next/static/chunks/app-def.js").unwrap()];

        write_chunk(
            &url,
            &ChunkData {
                apis: apis.clone(),
                candidates: CandidateMap::default(),
                refs: refs.clone(),
            },
        );
        let cached = read_chunk(&url).unwrap();

        assert_eq!(
            serde_json::to_value(&cached.apis).unwrap(),
            serde_json::to_value(&apis).unwrap()
        );
        assert_eq!(cached.refs, refs);

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
