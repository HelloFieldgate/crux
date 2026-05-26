//! Minimal HTTP/1.1 server over std::net::TcpListener.
//!
//! Handles GET and POST requests for the Helm UI.
//! Localhost-only; no auth, no cookies, no TLS.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

// ===========================================================================
// Request
// ===========================================================================

/// A parsed HTTP request.
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    /// Convenience: body as UTF-8 string.
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }
}

/// Parse an HTTP/1.1 request from a TCP stream.
/// Returns None if the request is malformed or the connection closed.
pub fn parse_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);

    // Request line
    let mut first_line = String::new();
    reader.read_line(&mut first_line).ok()?;
    let first_line = first_line.trim();
    if first_line.is_empty() {
        return None;
    }

    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let raw_path = parts.next()?;

    let (path, query_str) = if let Some(q) = raw_path.find('?') {
        (&raw_path[..q], &raw_path[q + 1..])
    } else {
        (raw_path, "")
    };
    let path = path.to_string();
    let query = parse_query(query_str);

    // Headers
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            content_length = lower["content-length:".len()..].trim().parse().unwrap_or(0);
        }
    }

    // Body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }

    Some(Request { method, path, query, body })
}

fn parse_query(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in s.split('&') {
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let key = url_decode(&part[..eq]);
            let val = url_decode(&part[eq + 1..]);
            map.insert(key, val);
        } else {
            map.insert(url_decode(part), String::new());
        }
    }
    map
}

fn url_decode(s: &str) -> String {
    let input = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let Ok(hex) = std::str::from_utf8(&input[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(if input[i] == b'+' { b' ' } else { input[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ===========================================================================
// Response
// ===========================================================================

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok_json(body: String) -> Self {
        Response { status: 200, content_type: "application/json", body: body.into_bytes() }
    }

    pub fn ok_html(body: &'static str) -> Self {
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn ok_js(body: &'static str) -> Self {
        Response {
            status: 200,
            content_type: "application/javascript",
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn ok_css(body: &'static str) -> Self {
        Response {
            status: 200,
            content_type: "text/css",
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn ok_png(body: &'static [u8]) -> Self {
        Response { status: 200, content_type: "image/png", body: body.to_vec() }
    }

    pub fn ok_svg(body: &'static [u8]) -> Self {
        Response { status: 200, content_type: "image/svg+xml", body: body.to_vec() }
    }

    pub fn not_found() -> Self {
        Response { status: 404, content_type: "text/plain", body: b"Not Found".to_vec() }
    }

    pub fn bad_request(msg: &str) -> Self {
        let escaped = msg.replace('"', "\\\"");
        Response {
            status: 400,
            content_type: "application/json",
            body: format!("{{\"error\": \"{}\"}}", escaped).into_bytes(),
        }
    }

    pub fn server_error(msg: &str) -> Self {
        let escaped = msg.replace('"', "\\\"");
        Response {
            status: 500,
            content_type: "application/json",
            body: format!("{{\"error\": \"{}\"}}", escaped).into_bytes(),
        }
    }
}

pub fn write_response(stream: &mut TcpStream, resp: Response) {
    let status_text = match resp.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status, status_text, resp.content_type, resp.body.len()
    );
    let _ = stream.write_all(&resp.body);
}
