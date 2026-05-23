//! Shared document/shape wire encoding used by cache and engine output.

use crate::scan::Shape;

use super::wire::{put_string_vec, Reader};

pub(crate) fn put_shape(out: &mut Vec<u8>, shape: &Shape) {
    let (methods, has_body, has_headers, content_types, auth, next_server_action, query_params) =
        shape.binary_parts();
    out.push(methods);
    out.push(has_body as u8);
    out.push(has_headers as u8);
    out.push(content_types);
    out.push(auth as u8);
    out.push(next_server_action as u8);
    put_string_vec(out, query_params);
}

pub(crate) fn read_shape(r: &mut Reader<'_>) -> Option<Shape> {
    Some(Shape::from_binary_parts(
        r.u8()?,
        r.bool()?,
        r.bool()?,
        r.u8()?,
        r.bool()?,
        r.bool()?,
        r.string_vec()?,
    ))
}
