//! Inline fast hash. Replaces the `rustc-hash` dep.
//!
//! This is a fast non-cryptographic hash for `HashMap` keys we control
//! (URLs, route strings, headers). It is intentionally small and local.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
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
