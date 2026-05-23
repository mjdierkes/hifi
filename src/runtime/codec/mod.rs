pub(crate) mod wire;

pub(crate) mod document;

pub(crate) use wire::{put_opt_string, put_string, put_string_vec, put_u32, Reader};
pub(crate) use document::{put_shape, read_shape};
