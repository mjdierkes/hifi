use crate::runtime::bytes::HiBuf;

pub(super) fn value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(super) fn reserve_body(headers: &[(String, String)], body: &mut HiBuf) {
    if body.capacity() != 0 {
        return;
    }
    let Some(len) = value(headers, "content-length").and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    body.reserve(len);
}

pub(super) fn http1_content_length(head: &str) -> Option<usize> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}
