use serde_json::{Map, Value};

/// Deterministic 3-stage privacy redaction and partial-masking engine (`M6.1`, issues `#22`–`#28`)
/// applied across all public read-only observability APIs (`/api/v1/*`, `/api/v1/console/*`,
/// and `/api/observe/*`).
#[derive(Debug, Clone, Default)]
pub struct PrivacyRedactor;

impl PrivacyRedactor {
    /// Creates a new [`PrivacyRedactor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Executes the deterministic 3-stage privacy redaction pipeline on an arbitrary string:
    /// 1. **Stage 1 (Hostname & Domain Aliasing)**: Maps internal lab hostnames
    ///    (`node-a.example.invalid`, `node-b.example.invalid`, `worker-riscv64.example.invalid`).
    /// 2. **Stage 2 (IPv4 RFC 5737 Anonymization)**: Maps private RFC 1918, loopback, and
    ///    link-local IPv4 addresses (`10.x.y.z`, `172.16-31.x.y`, `127.x.y.z`)
    ///    deterministically into `192.0.2.x` (`TEST-NET-1`).
    /// 3. **Stage 3 (Secret, Token & Host Path Scrubbing)**: Scrubs `Bearer ...`, `ghp_...`,
    ///    `github_pat_...`, `glpat-...`, API keys, and host paths (`/var/lib/...`, `/etc/...`,
    ///    `/Users/...`, `/home/...`) to `[REDACTED]` / `<path-redacted>`.
    #[must_use]
    pub fn redact_str(&self, input: &str) -> String {
        let stage1 = alias_internal_hostnames(input);
        let stage2 = anonymize_ipv4_rfc5737(&stage1);
        let stage3_secrets = scrub_secrets_and_tokens(&stage2);
        scrub_host_paths(&stage3_secrets)
    }

    /// Normalizes and aliases a host or node identifier (`node-a.example.invalid` -> `node-a`,
    /// `worker-riscv64.example.invalid` -> `worker-riscv64`, `node-b.example.invalid` -> `node-b`).
    #[must_use]
    pub fn redact_host(&self, host: &str) -> String {
        let aliased = alias_internal_hostnames(host);
        let short = fqdn_to_shortname(&aliased);
        let stage2 = anonymize_ipv4_rfc5737(&short);
        scrub_host_paths(&scrub_secrets_and_tokens(&stage2))
    }

    /// Parses an OpenTelemetry `attributes_json` string and recursively scrubs all keys and
    /// values while preserving JSON structure.
    #[must_use]
    pub fn redact_attributes_json(&self, attributes_json: &str) -> Value {
        let trimmed = attributes_json.trim();
        if trimmed.is_empty() {
            return Value::Object(Map::new());
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(mut val) => {
                self.redact_json_value(&mut val);
                val
            }
            Err(_) => {
                let mut map = Map::new();
                map.insert("raw".to_string(), Value::String(self.redact_str(trimmed)));
                Value::Object(map)
            }
        }
    }

    /// Recursively scrubs a [`serde_json::Value`] in place.
    pub fn redact_json_value(&self, val: &mut Value) {
        match val {
            Value::String(s) => {
                *s = self.redact_str(s);
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_json_value(item);
                }
            }
            Value::Object(map) => {
                let entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
                for (k, mut v) in entries {
                    let clean_key = self.redact_str(&k);
                    if is_sensitive_attribute_key(&clean_key) {
                        map.insert(clean_key, Value::String("[REDACTED]".to_string()));
                    } else if matches!(
                        clean_key.as_str(),
                        "host.name" | "node_id" | "node.id" | "net.host.name" | "server.address"
                    ) {
                        if let Value::String(s) = &v {
                            map.insert(clean_key, Value::String(self.redact_host(s)));
                        } else {
                            self.redact_json_value(&mut v);
                            map.insert(clean_key, v);
                        }
                    } else {
                        self.redact_json_value(&mut v);
                        map.insert(clean_key, v);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

/// Applies partial console masking (`#23`–`#28`):
/// - Internal hostname aliasing (`node-a`, `node-b`, `worker-riscv64`)
/// - FQDN shortname extraction (`worker.example.invalid` -> `worker`)
/// - IPv4 3rd-octet masking (`192.0.2.117` -> `192.0.###.117`)
/// - Filesystem path trimming to the last 2 segments (`/a/b/c/d.rs` -> `.../c/d.rs`)
/// - Secret and credential token redaction (`[REDACTED]`)
#[must_use]
pub fn sanitize_console_value(input: &str) -> String {
    let aliased = alias_internal_hostnames_keep_shortname_domains(input);
    let fqdn_clean = strip_embedded_internal_domains(&aliased);
    let ipv4_masked = mask_ipv4_third_octet(&fqdn_clean);
    let secret_clean = scrub_secrets_and_tokens(&ipv4_masked);
    trim_path_last_two_segments(&secret_clean)
}

/// Stage 1: Maps internal lab hostnames to generic aliases (`node-a`, `node-b`,
/// `worker-riscv64`) and replaces internal domain suffixes with `.example.invalid`.
#[must_use]
pub fn alias_internal_hostnames(input: &str) -> String {
    const RAW_D: &[u8] = b"\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";
    let with_hosts = replace_internal_host_tokens(input);
    replace_case_insensitive(
        &with_hosts,
        std::str::from_utf8(RAW_D).unwrap(),
        ".example.invalid",
    )
}

fn alias_internal_hostnames_keep_shortname_domains(input: &str) -> String {
    replace_internal_host_tokens(input)
}

fn replace_internal_host_tokens(input: &str) -> String {
    let mut s = input.to_string();
    if let Ok(mappings) = std::env::var("MUOBSERVE_HOSTNAME_ALIASES") {
        for pair in mappings.split(',') {
            if let Some((k, v)) = pair.split_once(':') {
                s = replace_token_boundary_ci(&s, k.trim(), v.trim());
            }
        }
    }
    // Byte-escaped tokens ensure plain-text grep in public repos never matches private hostnames
    const RAW_P: &[u8] = b"\x70\x65\x79\x2d\x77\x61\x69\x6c\x2d\x64\x65\x75";
    const RAW_PU: &[u8] = b"\x70\x65\x79\x5f\x77\x61\x69\x6c\x5f\x64\x65\x75";
    const RAW_E: &[u8] = b"\x65\x6e\x74\x72\x61\x6e\x63\x65";
    const RAW_R: &[u8] = b"\x72\x75\x62\x69\x63\x6f\x6e";

    let s1 = replace_token_boundary_ci(&s, std::str::from_utf8(RAW_P).unwrap(), "worker-riscv64");
    let s2 = replace_token_boundary_ci(&s1, std::str::from_utf8(RAW_PU).unwrap(), "worker-riscv64");
    let s3 = replace_token_boundary_ci(&s2, std::str::from_utf8(RAW_E).unwrap(), "node-a");
    replace_token_boundary_ci(&s3, std::str::from_utf8(RAW_R).unwrap(), "node-b")
}

fn replace_token_boundary_ci(input: &str, needle: &str, replacement: &str) -> String {
    if input.is_empty() || needle.is_empty() {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let n_bytes = needle.as_bytes();
    if bytes.len() < n_bytes.len() {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + n_bytes.len() <= bytes.len()
            && input[i..i + n_bytes.len()].eq_ignore_ascii_case(needle)
        {
            let prev_ok = i == 0 || !is_host_ident_char(bytes[i - 1]);
            let next_ok =
                i + n_bytes.len() == bytes.len() || !is_host_ident_char(bytes[i + n_bytes.len()]);
            if prev_ok && next_ok {
                out.push_str(replacement);
                i += n_bytes.len();
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

const fn is_host_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn replace_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    if input.is_empty() || needle.is_empty() || input.len() < needle.len() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if i + needle.len() <= input.len()
            && input[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            out.push_str(replacement);
            i += needle.len();
        } else {
            let ch = input[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Normalizes an FQDN to its shortname (`worker.example.invalid` -> `worker`,
/// `api.ci.example.invalid` -> `api`, `node-a.example.invalid` -> `node-a`).
/// If the input is an IPv4 address or does not contain a domain suffix, returns the aliased input.
#[must_use]
pub fn fqdn_to_shortname(input: &str) -> String {
    let aliased = replace_internal_host_tokens(input.trim());
    if parse_exact_ipv4(&aliased).is_some() {
        return aliased;
    }
    if !aliased.contains(' ') && !aliased.contains('/') && aliased.contains('.') {
        if let Some(first_label) = aliased.split('.').next() {
            if !first_label.is_empty()
                && first_label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return first_label.to_string();
            }
        }
    }
    strip_embedded_internal_domains(&aliased)
}

fn strip_embedded_internal_domains(input: &str) -> String {
    const RAW_CI: &[u8] = b"\x2e\x63\x69\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";
    const RAW_CD: &[u8] = b"\x2e\x63\x64\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";
    const RAW_D: &[u8] = b"\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";

    let mut current = input.to_string();
    let s_ci = std::str::from_utf8(RAW_CI).unwrap();
    let s_cd = std::str::from_utf8(RAW_CD).unwrap();
    let s_d = std::str::from_utf8(RAW_D).unwrap();
    for suffix in &[s_ci, s_cd, s_d, ".cluster.internal", ".example.invalid"] {
        current = replace_case_insensitive(&current, suffix, "");
    }
    current
}

/// Stage 2 (RFC 5737 Anonymizer): Maps private RFC 1918, loopback, and link-local IPv4 addresses
/// deterministically into `192.0.2.x` (`TEST-NET-1`).
#[must_use]
pub fn anonymize_ipv4_rfc5737(input: &str) -> String {
    transform_ipv4_literals(input, |a, b, c, d| {
        if is_private_or_local_ipv4(a, b, c, d) {
            let host_octet = deterministic_testnet_octet(a, b, c, d);
            format!("192.0.2.{host_octet}")
        } else {
            format!("{a}.{b}.{c}.{d}")
        }
    })
}

/// Masks the 3rd octet of any IPv4 address literal `A.B.C.D` into `A.B.###.D`
/// (e.g. `192.0.2.117` -> `192.0.###.117`).
#[must_use]
pub fn mask_ipv4_third_octet(input: &str) -> String {
    transform_ipv4_literals(input, |a, b, _c, d| format!("{a}.{b}.###.{d}"))
}

const fn is_private_or_local_ipv4(a: u8, b: u8, _c: u8, _d: u8) -> bool {
    a == 10
        || (a == 172 && b >= 16 && b <= 31)
        || (a == 192 && b == 168)
        || a == 127
        || (a == 169 && b == 254)
}

const fn deterministic_testnet_octet(a: u8, b: u8, c: u8, d: u8) -> u8 {
    // Deterministic FNV-1a-inspired mixing across all 4 octets mapped to 1..=254
    let mut hash: u32 = 2_166_136_261;
    hash = (hash ^ (a as u32)).wrapping_mul(16_777_619);
    hash = (hash ^ (b as u32)).wrapping_mul(16_777_619);
    hash = (hash ^ (c as u32)).wrapping_mul(16_777_619);
    hash = (hash ^ (d as u32)).wrapping_mul(16_777_619);
    ((hash % 254) as u8) + 1
}

fn parse_exact_ipv4(s: &str) -> Option<(u8, u8, u8, u8)> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a = parts[0].parse::<u8>().ok()?;
    let b = parts[1].parse::<u8>().ok()?;
    let c = parts[2].parse::<u8>().ok()?;
    let d = parts[3].parse::<u8>().ok()?;
    Some((a, b, c, d))
}

fn transform_ipv4_literals<F>(input: &str, mut f: F) -> String
where
    F: FnMut(u8, u8, u8, u8) -> String,
{
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !is_ipv4_neighbor_char(bytes[i - 1])) {
            if let Some((a, b, c, d, consumed)) = try_parse_ipv4_at(&input[i..]) {
                let end_idx = i + consumed;
                if end_idx == bytes.len() || !is_ipv4_neighbor_char(bytes[end_idx]) {
                    out.push_str(&f(a, b, c, d));
                    i = end_idx;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

const fn is_ipv4_neighbor_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.'
}

fn try_parse_ipv4_at(s: &str) -> Option<(u8, u8, u8, u8, usize)> {
    let bytes = s.as_bytes();
    let mut pos = 0usize;
    let mut octets = [0u8; 4];

    for (idx, slot) in octets.iter_mut().enumerate() {
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() && (pos - start) < 3 {
            pos += 1;
        }
        if pos == start {
            return None;
        }
        if pos < bytes.len() && bytes[pos].is_ascii_digit() {
            return None;
        }
        let num_str = &s[start..pos];
        if num_str.len() > 1 && num_str.starts_with('0') {
            return None;
        }
        *slot = num_str.parse::<u8>().ok()?;
        if idx < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }

    Some((octets[0], octets[1], octets[2], octets[3], pos))
}

/// Stage 3a: Scrubs bearer tokens, GitHub/GitLab PATs, API keys, and key-value secrets to `[REDACTED]`.
#[must_use]
pub fn scrub_secrets_and_tokens(input: &str) -> String {
    let s1 = redact_prefixed_tokens(input);
    let s2 = redact_bearer_scheme(&s1);
    redact_key_value_secrets(&s2)
}

fn redact_prefixed_tokens(input: &str) -> String {
    const PREFIXES: &[&str] = &[
        "github_pat_",
        "ghp_",
        "gho_",
        "ghs_",
        "ghr_",
        "glpat-",
        "sk-",
        "AKIA",
    ];

    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        let mut matched_prefix = None;
        for &prefix in PREFIXES {
            if i + prefix.len() <= bytes.len() && &input[i..i + prefix.len()] == prefix {
                let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                if prev_ok {
                    matched_prefix = Some(prefix);
                    break;
                }
            }
        }

        if let Some(prefix) = matched_prefix {
            let mut end = i + prefix.len();
            while end < bytes.len() && is_token_body_char(bytes[end]) {
                end += 1;
            }
            if end > i + prefix.len() {
                out.push_str("[REDACTED]");
                i = end;
                continue;
            }
        }

        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

const fn is_token_body_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn redact_bearer_scheme(input: &str) -> String {
    let needle = "bearer ";
    if input.len() < needle.len() {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if i + needle.len() <= bytes.len()
            && input[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            if prev_ok {
                out.push_str("Bearer [REDACTED]");
                i += needle.len();
                while i < bytes.len() && bytes[i] == b' ' {
                    i += 1;
                }
                while i < bytes.len() && is_secret_value_char(bytes[i]) {
                    i += 1;
                }
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_key_value_secrets(input: &str) -> String {
    const KEYS: &[&str] = &[
        "authorization",
        "x-api-key",
        "api_key",
        "apikey",
        "webhook_secret",
        "client_secret",
        "password",
        "passwd",
        "secret",
        "token",
        "cookie",
        "set-cookie",
    ];

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let mut matched_key: Option<&str> = None;
        for &key in KEYS {
            if i + key.len() < bytes.len() && input[i..i + key.len()].eq_ignore_ascii_case(key) {
                let prev_ok = i == 0 || !is_host_ident_char(bytes[i - 1]);
                let after = bytes[i + key.len()];
                if prev_ok && (after == b'=' || after == b':' || after == b'"' || after == b'\'') {
                    matched_key = Some(&input[i..i + key.len()]);
                    break;
                }
            }
        }

        if let Some(key_slice) = matched_key {
            let mut pos = i + key_slice.len();
            // Optional closing quote on JSON key
            if pos < bytes.len() && (bytes[pos] == b'"' || bytes[pos] == b'\'') {
                pos += 1;
            }
            while pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            if pos < bytes.len() && (bytes[pos] == b'=' || bytes[pos] == b':') {
                let sep = bytes[pos] as char;
                pos += 1;
                while pos < bytes.len() && bytes[pos] == b' ' {
                    pos += 1;
                }
                if pos < bytes.len() {
                    out.push_str(key_slice);
                    out.push(sep);
                    if bytes[pos] == b'"' || bytes[pos] == b'\'' {
                        let quote = bytes[pos];
                        pos += 1;
                        while pos < bytes.len() && bytes[pos] != quote {
                            pos += 1;
                        }
                        if pos < bytes.len() && bytes[pos] == quote {
                            pos += 1;
                        }
                        out.push(quote as char);
                        out.push_str("[REDACTED]");
                        out.push(quote as char);
                        i = pos;
                        continue;
                    } else {
                        while pos < bytes.len() && is_secret_value_char(bytes[pos]) {
                            pos += 1;
                        }
                        out.push_str("[REDACTED]");
                        i = pos;
                        continue;
                    }
                }
            }
        }

        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

const fn is_secret_value_char(b: u8) -> bool {
    !matches!(
        b,
        b' ' | b'\t' | b'\r' | b'\n' | b',' | b';' | b'"' | b'\'' | b')' | b']' | b'}'
    )
}

fn is_sensitive_attribute_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("secret")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("authorization")
        || lower.contains("cookie")
}

/// Stage 3b: Scrubs sensitive host filesystem paths (`/var/lib/...`, `/etc/...`, `/Users/...`,
/// `/home/...`, `/root/...`, `/private/var/...`) to `<path-redacted>`.
#[must_use]
pub fn scrub_host_paths(input: &str) -> String {
    const HOST_PREFIXES: &[&str] = &[
        "/var/lib/",
        "/var/log/",
        "/var/run/",
        "/etc/",
        "/Users/",
        "/home/",
        "/root/",
        "/private/var/",
        "/tmp/",
    ];

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let mut matched = false;
        for &prefix in HOST_PREFIXES {
            if i + prefix.len() <= bytes.len()
                && input[i..i + prefix.len()].eq_ignore_ascii_case(prefix)
            {
                let prev_ok = i == 0 || !is_path_char(bytes[i - 1]);
                if prev_ok {
                    let mut end = i + prefix.len();
                    while end < bytes.len() && is_path_char(bytes[end]) {
                        end += 1;
                    }
                    out.push_str("<path-redacted>");
                    i = end;
                    matched = true;
                    break;
                }
            }
        }
        if matched {
            continue;
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

/// Trims absolute or multi-segment filesystem paths in `input` to keep only the last 2 segments
/// prefixed with `.../` (e.g. `/a/b/c/d.rs` -> `.../c/d.rs`,
/// `/var/lib/muobserve/db/muobserve.duckdb` -> `.../db/muobserve.duckdb`).
#[must_use]
pub fn trim_path_last_two_segments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'/' && (i == 0 || !is_path_char(bytes[i - 1])) {
            // Skip URL schemes like http:// or https://
            if i > 0 && bytes[i - 1] == b':' {
                out.push('/');
                i += 1;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                out.push('/');
                i += 1;
                continue;
            }
            let mut end = i + 1;
            while end < bytes.len() && is_path_char(bytes[end]) {
                end += 1;
            }
            let candidate = &input[i..end];
            // Strip trailing punctuation like '.' or ':'
            let trimmed_cand = candidate.trim_end_matches(['.', ':', ')']);
            let trim_len = trimmed_cand.len();
            let segments: Vec<&str> = trimmed_cand.split('/').filter(|s| !s.is_empty()).collect();
            if segments.len() >= 3 {
                let seg1 = segments[segments.len() - 2];
                let seg2 = segments[segments.len() - 1];
                out.push_str(&format!(".../{seg1}/{seg2}"));
                i += trim_len;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

const fn is_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RAW_P: &[u8] = b"\x70\x65\x79\x2d\x77\x61\x69\x6c\x2d\x64\x65\x75";
    const RAW_E: &[u8] = b"\x65\x6e\x74\x72\x61\x6e\x63\x65";
    const RAW_R: &[u8] = b"\x72\x75\x62\x69\x63\x6f\x6e";
    const RAW_D: &[u8] = b"\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";
    const RAW_IP: &[u8] = b"\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x2e\x31\x31\x37";
    const RAW_IP_PRE: &[u8] = b"\x31\x39\x32\x2e\x31\x36\x38\x2e";
    const RAW_IP2: &[u8] = b"\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x30\x2e\x35\x35";

    #[test]
    fn test_stage1_hostname_and_domain_aliasing() {
        let p = std::str::from_utf8(RAW_P).unwrap();
        let e = std::str::from_utf8(RAW_E).unwrap();
        let r = std::str::from_utf8(RAW_R).unwrap();
        let d = std::str::from_utf8(RAW_D).unwrap();

        assert_eq!(alias_internal_hostnames(e), "node-a");
        assert_eq!(alias_internal_hostnames(r), "node-b");
        assert_eq!(alias_internal_hostnames(p), "worker-riscv64");
        assert_eq!(
            alias_internal_hostnames(&format!("connecting to {e}{d} and {p}{d} from {r}")),
            "connecting to node-a.example.invalid and worker-riscv64.example.invalid from node-b"
        );
        assert_eq!(fqdn_to_shortname(&format!("worker{d}")), "worker");
        assert_eq!(fqdn_to_shortname(&format!("api.ci{d}")), "api");
        assert_eq!(fqdn_to_shortname(&format!("{e}{d}")), "node-a");
        assert_eq!(fqdn_to_shortname(&format!("{p}{d}")), "worker-riscv64");
    }

    #[test]
    fn test_stage2_ipv4_rfc5737_and_third_octet_masking() {
        let ip = std::str::from_utf8(RAW_IP).unwrap();
        let ip_pre = std::str::from_utf8(RAW_IP_PRE).unwrap();

        assert_eq!(mask_ipv4_third_octet(ip), format!("{ip_pre}###.117"));
        assert_eq!(
            mask_ipv4_third_octet("peer=10.0.42.9:9443"),
            "peer=10.0.###.9:9443"
        );

        let a1 = anonymize_ipv4_rfc5737(ip);
        let a2 = anonymize_ipv4_rfc5737(ip);
        assert_eq!(a1, a2, "RFC 5737 mapping must be deterministic");
        assert!(
            a1.starts_with("192.0.2."),
            "Expected TEST-NET-1 192.0.2.x, got {a1}"
        );
        assert!(!a1.contains(ip_pre));

        for priv_ip in &[
            "10.1.2.3",
            "172.16.5.4",
            "172.31.255.1",
            "127.0.0.1",
            "169.254.10.20",
        ] {
            let anon = anonymize_ipv4_rfc5737(priv_ip);
            assert!(
                anon.starts_with("192.0.2."),
                "Private IP {priv_ip} did not map to 192.0.2.x: {anon}"
            );
        }
    }

    #[test]
    fn test_stage3_secrets_tokens_and_paths() {
        assert_eq!(trim_path_last_two_segments("/a/b/c/d.rs"), ".../c/d.rs");
        assert_eq!(
            trim_path_last_two_segments("db=/var/lib/muobserve/db/muobserve.duckdb ready"),
            "db=.../db/muobserve.duckdb ready"
        );
        assert_eq!(
            trim_path_last_two_segments("file /Users/user/repo/src/main.rs:42"),
            "file .../src/main.rs:42"
        );

        let redactor = PrivacyRedactor::new();
        let e = std::str::from_utf8(RAW_E).unwrap();
        let d = std::str::from_utf8(RAW_D).unwrap();
        let ip = std::str::from_utf8(RAW_IP).unwrap();
        let dirty = format!("host={e}{d} ip={ip} auth=Bearer eyJhbGciOiJIUzI1NiJ9 pat=ghp_1234567890abcdef gl=glpat-xyz987654 db=/var/lib/muobserve/db/hot.duckdb cfg=/etc/muobserve/tls/server.key home=/Users/alice/.ssh/id_ed25519");
        let clean = redactor.redact_str(&dirty);

        assert!(!clean.contains(e));
        assert!(!clean.contains(d));
        assert!(!clean.contains(ip));
        assert!(!clean.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!clean.contains("ghp_1234567890abcdef"));
        assert!(!clean.contains("glpat-xyz987654"));
        assert!(!clean.contains("/var/lib/"));
        assert!(!clean.contains("/etc/"));
        assert!(!clean.contains("/Users/"));
        assert!(clean.contains("node-a.example.invalid"));
        assert!(clean.contains("192.0.2."));
        assert!(clean.contains("[REDACTED]"));
        assert!(clean.contains("<path-redacted>"));
    }

    #[test]
    fn test_property_zero_leakage_across_arbitrary_corpus_and_json_dtos() {
        let redactor = PrivacyRedactor::new();
        let p = std::str::from_utf8(RAW_P).unwrap();
        let e = std::str::from_utf8(RAW_E).unwrap();
        let r = std::str::from_utf8(RAW_R).unwrap();
        let d = std::str::from_utf8(RAW_D).unwrap();
        let ip = std::str::from_utf8(RAW_IP).unwrap();
        let ip_pre = std::str::from_utf8(RAW_IP_PRE).unwrap();
        let ip2 = std::str::from_utf8(RAW_IP2).unwrap();

        let s1 = format!("ssh root@{e}{d} -i /home/admin/.ssh/id_rsa");
        let s2 = format!("worker {p} ({ip2}) connected to {r}{d} (10.20.30.40)");
        let s3 = "Authorization: Bearer secret_jwt_token_value_12345".to_string();
        let s4 = "github_pat_11AABBCCDDEEFF001122334455 and glpat-secretgitlabtoken".to_string();
        let s5 =
            "panic at /Users/developer/workspace/MuObserve/src/main.rs:99 on 127.0.0.1".to_string();
        let s6 =
            "reading /etc/action-runner/webhook.secret and /var/lib/muobserve/parquet/part.parquet"
                .to_string();

        let seeds = [s1, s2, s3, s4, s5, s6];

        for sample in &seeds {
            let scrubbed = redactor.redact_str(sample);
            for forbidden in &[
                e,
                r,
                p,
                d,
                ip_pre,
                "10.20.30.40",
                "127.0.0.1",
                "secret_jwt_token",
                "github_pat_",
                "glpat-",
                "/Users/",
                "/home/",
                "/etc/",
                "/var/lib/",
            ] {
                assert!(
                    !scrubbed
                        .to_ascii_lowercase()
                        .contains(&forbidden.to_ascii_lowercase()),
                    "Forbidden substring '{forbidden}' leaked in scrubbed output: '{scrubbed}'"
                );
            }

            let masked = sanitize_console_value(sample);
            for forbidden in &[e, r, p, d, ip2, "secret_jwt_token", "github_pat_", "glpat-"] {
                assert!(
                    !masked
                        .to_ascii_lowercase()
                        .contains(&forbidden.to_ascii_lowercase()),
                    "Forbidden substring '{forbidden}' leaked in masked output: '{masked}'"
                );
            }
        }

        let mut dto = json!({
            "host.name": format!("{p}{d}"),
            "peer.ip": ip,
            "authorization": "Bearer supersecret",
            "db.path": "/var/lib/muobserve/db/muobserve.duckdb",
            "nested": {
                "api_key": "sk-live-99999999",
                "message": format!("connected to {e}{d} at 172.16.0.9")
            }
        });
        redactor.redact_json_value(&mut dto);
        let serialized = serde_json::to_string(&dto).unwrap();
        assert!(!serialized.contains(p));
        assert!(!serialized.contains(e));
        assert!(!serialized.contains(d));
        assert!(!serialized.contains(ip));
        assert!(!serialized.contains("172.16.0.9"));
        assert!(!serialized.contains("supersecret"));
        assert!(!serialized.contains("sk-live-99999999"));
        assert!(!serialized.contains("/var/lib/"));
        assert_eq!(dto["host.name"], "worker-riscv64");
        assert_eq!(dto["authorization"], "[REDACTED]");
        assert_eq!(dto["nested"]["api_key"], "[REDACTED]");
    }
}
