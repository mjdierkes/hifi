use std::{
    fs,
    path::{Path, PathBuf},
};

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn main() {
    println!("cargo:rerun-if-env-changed=HIFI_BUILD_REV");

    let mut hash = FNV_OFFSET;
    hash_str(&mut hash, env!("CARGO_PKG_VERSION"));
    if let Ok(rev) = std::env::var("HIFI_BUILD_REV") {
        hash_str(&mut hash, &rev);
    } else {
        hash_git_head(&mut hash);
    }

    for path in build_inputs() {
        println!("cargo:rerun-if-changed={}", path.display());
        hash_str(&mut hash, &path.display().to_string());
        if let Ok(bytes) = fs::read(&path) {
            hash_bytes(&mut hash, &bytes);
        }
    }

    println!("cargo:rustc-env=HIFI_BUILD_HASH={hash:016x}");
}

fn build_inputs() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("build.rs"),
    ];
    collect_rs_files(Path::new("src"), &mut paths);
    paths.sort();
    paths
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn hash_git_head(hash: &mut u64) {
    let head_path = Path::new(".git/HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());
    let Ok(head) = fs::read_to_string(head_path) else {
        return;
    };
    hash_str(hash, head.trim());
    if let Some(reference) = head.trim().strip_prefix("ref: ") {
        let ref_path = Path::new(".git").join(reference);
        println!("cargo:rerun-if-changed={}", ref_path.display());
        if let Ok(value) = fs::read_to_string(ref_path) {
            hash_str(hash, value.trim());
        }
    }
}

fn hash_str(hash: &mut u64, value: &str) {
    hash_bytes(hash, value.as_bytes());
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= *byte as u64;
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
    *hash ^= b'\n' as u64;
    *hash = hash.wrapping_mul(FNV_PRIME);
}
