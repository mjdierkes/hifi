//! Inline fast hash. Replaces the `rustc-hash` dep.
//!
//! This is a fast non-cryptographic hash for `HashMap` keys we control
//! (URLs, route strings, headers). It is intentionally small and local.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
const SEED2: u64 = 0x9e_37_79_b9_7f_4a_7c_15;
const ROTATE: u32 = 5;

#[derive(Default, Clone)]
pub struct FxHasher {
    h: u64,
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 8 {
            let v = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
            self.h = (self.h.rotate_left(ROTATE) ^ v).wrapping_mul(SEED);
            bytes = &bytes[8..];
        }
        if bytes.len() >= 4 {
            let v = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64;
            self.h = (self.h.rotate_left(ROTATE) ^ v).wrapping_mul(SEED);
            bytes = &bytes[4..];
        }
        if bytes.len() >= 2 {
            let v = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as u64;
            self.h = (self.h.rotate_left(ROTATE) ^ v).wrapping_mul(SEED);
            bytes = &bytes[2..];
        }
        if let Some(&b) = bytes.first() {
            self.h = (self.h.rotate_left(ROTATE) ^ b as u64).wrapping_mul(SEED);
        }
    }

    #[inline]
    fn write_u8(&mut self, b: u8) {
        self.h = (self.h.rotate_left(ROTATE) ^ b as u64).wrapping_mul(SEED);
    }

    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.h = (self.h.rotate_left(ROTATE) ^ v).wrapping_mul(SEED);
    }

    #[inline]
    fn write_usize(&mut self, v: usize) {
        self.h = (self.h.rotate_left(ROTATE) ^ v as u64).wrapping_mul(SEED);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.h
    }
}

pub type FxBuildHasher = BuildHasherDefault<FxHasher>;
pub type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
pub type FxHashSet<T> = HashSet<T, FxBuildHasher>;

pub(crate) fn hash128_hex(bytes: &[u8]) -> String {
    let a = hash64(bytes, SEED);
    let b = hash64(bytes, SEED2 ^ bytes.len() as u64);
    format!("{a:016x}{b:016x}")
}

fn hash64(mut bytes: &[u8], seed: u64) -> u64 {
    let mut h = seed ^ ((bytes.len() as u64).wrapping_mul(SEED2));
    while bytes.len() >= 8 {
        let v = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        h = mix(h, v);
        bytes = &bytes[8..];
    }
    if bytes.len() >= 4 {
        let v = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64;
        h = mix(h, v);
        bytes = &bytes[4..];
    }
    if bytes.len() >= 2 {
        let v = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as u64;
        h = mix(h, v);
        bytes = &bytes[2..];
    }
    if let Some(&b) = bytes.first() {
        h = mix(h, b as u64);
    }
    avalanche(h)
}

#[inline]
fn mix(h: u64, v: u64) -> u64 {
    (h.rotate_left(ROTATE) ^ v).wrapping_mul(SEED)
}

#[inline]
fn avalanche(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}
