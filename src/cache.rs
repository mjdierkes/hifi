use url::Url;

pub fn fingerprint(chunks: &[Url]) -> String {
    let mut paths: Vec<&str> = chunks.iter().map(|u| u.path()).collect();
    paths.sort();

    let mut h: u64 = 0xcbf29ce484222325;
    for p in paths {
        for b in p.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= b'\n' as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

pub fn path_for(base: &Url) -> std::path::PathBuf {
    let host = base.host_str().unwrap_or("unknown").replace('/', "_");
    dir().join(format!("{host}.json"))
}

pub fn read(path: &std::path::Path, build_id: Option<&str>) -> Option<serde_json::Value> {
    let (v, _) = read_any(path)?;
    let cached_build = v.get("build_id").and_then(|b| b.as_str());
    matches!((build_id, cached_build), (Some(a), Some(b)) if a == b).then_some(v)
}

pub fn read_any(path: &std::path::Path) -> Option<(serde_json::Value, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .ok()?
        .as_secs();
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some((v, age))
}

pub fn write(path: &std::path::Path, value: &serde_json::Value) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_vec(value) {
        let _ = std::fs::write(path, s);
    }
}

fn dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".cache/hifi")
}
