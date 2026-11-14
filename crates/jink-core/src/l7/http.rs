//! HTTP/1.x request detection and `Host` header location (zapret `IsHttp`,
//! `HttpExtractHost`).

use super::host::HostName;

/// Request-line prefixes zapret recognises (`http_methods` in protocol.c).
const METHODS: [&[u8]; 8] = [
    b"GET /",
    b"POST /",
    b"HEAD /",
    b"OPTIONS ",
    b"PUT /",
    b"DELETE /",
    b"CONNECT ",
    b"TRACE /",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// The `Host` header value, as sent (may include `:port`). `None` if the
    /// header is absent or not yet received.
    pub host: Option<HostName<'a>>,
}

#[must_use]
pub fn is_request(payload: &[u8]) -> bool {
    METHODS.iter().any(|m| payload.starts_with(m))
}

/// Parses an HTTP request at the start of `payload`; `None` if it is not one.
#[must_use]
pub fn parse_request(payload: &[u8]) -> Option<HttpRequest<'_>> {
    is_request(payload).then(|| HttpRequest {
        host: find_host(payload),
    })
}

/// Finds `\nHost:` case-insensitively, skips spaces/tabs, and takes the value
/// up to the next whitespace or line end.
fn find_host(payload: &[u8]) -> Option<HostName<'_>> {
    const NEEDLE: &[u8] = b"\nhost:";
    let header = payload
        .windows(NEEDLE.len())
        .position(|w| w.eq_ignore_ascii_case(NEEDLE))?;
    let after_colon = header.checked_add(NEEDLE.len())?;
    let rest = payload.get(after_colon..)?;
    let skipped = rest
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    let start = after_colon.checked_add(skipped)?;
    let value = payload.get(start..)?;
    let len = value
        .iter()
        .position(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(value.len());
    if len == 0 {
        return None;
    }
    HostName::at(value.get(..len)?, start)
}

#[cfg(test)]
mod tests {
    use super::{is_request, parse_request};

    #[test]
    fn finds_host_case_insensitively_with_positions() {
        let req = b"GET /x HTTP/1.1\r\nUser-Agent: t\r\nhOsT: \t Example.COM:8080\r\n\r\n";
        let host = parse_request(req).unwrap().host.unwrap();
        assert_eq!(host.name, "Example.COM:8080");
        assert_eq!(&req[host.range.clone()], b"Example.COM:8080");
        let sld = host.sld_range.unwrap();
        assert_eq!(&req[sld], b"Example");
    }

    #[test]
    fn request_without_host_header() {
        assert_eq!(parse_request(b"GET / HTTP/1.0\r\n\r\n").unwrap().host, None);
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost:\r\n").unwrap().host,
            None
        );
    }

    #[test]
    fn only_known_methods_are_requests() {
        assert!(is_request(b"CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(
            !is_request(b"get / HTTP/1.1\r\n"),
            "methods are case-sensitive"
        );
        assert!(
            !is_request(b"HTTP/1.1 200 OK\r\n"),
            "a response is not a request"
        );
        assert!(!is_request(b"GET"));
    }
}
