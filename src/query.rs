/// Structured query filtering for crux nodes.
///
/// All filter fields are optional. Any missing field is a no-op.
/// Multiple fields AND together. Deleted nodes are always excluded.
use std::collections::HashMap;

use crate::json::{extract_string_value, extract_u64_value};
use crate::schema::CruxNode;

// ===========================================================================
// Property filter
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum PropertyOp {
    Eq,
    Gt,
    Lt,
}

#[derive(Debug, Clone)]
pub struct PropertyFilter {
    pub key: String,
    pub op: PropertyOp,
    pub value: String,
}

/// Parse `"key=value"`, `"key>N"`, or `"key<N"` from a filter string.
pub fn parse_property_filter(s: &str) -> Option<PropertyFilter> {
    if let Some(pos) = s.find('>') {
        let key = s[..pos].trim().to_string();
        let value = s[pos + 1..].trim().to_string();
        if !key.is_empty() {
            return Some(PropertyFilter { key, op: PropertyOp::Gt, value });
        }
    }
    if let Some(pos) = s.find('<') {
        let key = s[..pos].trim().to_string();
        let value = s[pos + 1..].trim().to_string();
        if !key.is_empty() {
            return Some(PropertyFilter { key, op: PropertyOp::Lt, value });
        }
    }
    if let Some(pos) = s.find('=') {
        let key = s[..pos].trim().to_string();
        let value = s[pos + 1..].trim().to_string();
        if !key.is_empty() {
            return Some(PropertyFilter { key, op: PropertyOp::Eq, value });
        }
    }
    None
}

// ===========================================================================
// Sort field
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum SortField {
    Priority,
    Name,
    Created,
}

fn parse_sort(s: &str) -> Option<SortField> {
    match s.trim().to_lowercase().as_str() {
        "priority" => Some(SortField::Priority),
        "name" => Some(SortField::Name),
        "created" => Some(SortField::Created),
        _ => None,
    }
}

// ===========================================================================
// Date parsing (no chrono)
// ===========================================================================

/// Parse `"YYYY-MM-DD"` → unix timestamp (seconds since epoch) at midnight UTC.
/// Returns `None` for invalid input.
pub fn parse_date_to_unix(s: &str) -> Option<u64> {
    let s = s.trim();
    // Try as raw integer first
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    // Parse YYYY-MM-DD
    let parts: Vec<&str> = s.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year = parts[0].parse::<i64>().ok()?;
    let month = parts[1].parse::<u32>().ok()?;
    let day = parts[2].parse::<u32>().ok()?;
    if month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }
    // Days since Unix epoch (1970-01-01)
    let days = days_since_epoch(year, month, day)?;
    Some(days * 86400)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap_year(y) { 29 } else { 28 },
        _ => 0,
    }
}

fn days_since_epoch(year: i64, month: u32, day: u32) -> Option<u64> {
    // Count days from 1970-01-01
    let mut total: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            total += if is_leap_year(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            total -= if is_leap_year(y) { 366 } else { 365 };
        }
    }
    for m in 1..month {
        total += days_in_month(year, m) as i64;
    }
    total += (day as i64) - 1;
    if total < 0 { None } else { Some(total as u64) }
}

// ===========================================================================
// NodeFilter
// ===========================================================================

#[derive(Debug, Clone)]
pub struct NodeFilter {
    /// Substring match on name / kind / any tag / summary.
    pub query: Option<String>,
    /// Exact match on node.kind (case-insensitive).
    pub kind: Option<String>,
    /// Exact match on node.planning.status (case-insensitive).
    pub status: Option<String>,
    /// Exact match on any tag (case-insensitive).
    pub tag: Option<String>,
    /// Property filter: `key=value`, `key>N`, or `key<N`.
    pub property: Option<PropertyFilter>,
    /// Filter by `planning.updated_at >= since` (unix timestamp).
    /// Note: nodes without planning.updated_at are excluded when this is set.
    pub since: Option<u64>,
    /// Sort order applied after filtering.
    pub sort: Option<SortField>,
    /// Maximum number of results to return. Default: 50.
    pub limit: usize,
    /// When true, `mesh_query` follows `mesh_link` edges into linked remote cruxes
    /// and merges their matching nodes into the result set.
    pub follow_links: bool,
}

impl Default for NodeFilter {
    fn default() -> Self {
        NodeFilter {
            query: None,
            kind: None,
            status: None,
            tag: None,
            property: None,
            since: None,
            sort: None,
            limit: 50,
            follow_links: false,
        }
    }
}

impl NodeFilter {
    /// Parse from MCP tool JSON args string.
    ///
    /// Reads: `query`, `filter_kind` (falls back to `kind`),
    /// `filter_status` (falls back to `status`), `tag`, `property`,
    /// `since`, `sort`, `limit`.
    pub fn from_args(args: &str) -> Self {
        let query = extract_string_value(args, "query")
            .filter(|s| !s.is_empty());
        let kind = extract_string_value(args, "filter_kind")
            .or_else(|| extract_string_value(args, "kind"))
            .filter(|s| !s.is_empty());
        let status = extract_string_value(args, "filter_status")
            .or_else(|| extract_string_value(args, "status"))
            .filter(|s| !s.is_empty());
        let tag = extract_string_value(args, "tag")
            .filter(|s| !s.is_empty());
        let property = extract_string_value(args, "property")
            .and_then(|s| parse_property_filter(&s));
        let since = extract_string_value(args, "since")
            .and_then(|s| parse_date_to_unix(&s))
            .or_else(|| extract_u64_value(args, "since"));
        let sort = extract_string_value(args, "sort")
            .and_then(|s| parse_sort(&s));
        let limit = extract_string_value(args, "limit")
            .and_then(|s| s.parse::<usize>().ok())
            .or_else(|| extract_u64_value(args, "limit").map(|n| n as usize))
            .unwrap_or(50);
        let follow_links = extract_string_value(args, "follow_links")
            .map(|s| s == "true")
            .unwrap_or(false);

        NodeFilter { query, kind, status, tag, property, since, sort, limit, follow_links }
    }

    /// Parse from URL query params (HashMap from Helm HTTP request).
    ///
    /// Maps: `q`→query, `kind`, `status`, `tag`, `property`, `since`, `sort`, `limit`, `follow_links`.
    pub fn from_query_params(params: &HashMap<String, String>) -> Self {
        let query = params.get("q").filter(|s| !s.is_empty()).cloned();
        let kind = params.get("kind").filter(|s| !s.is_empty()).cloned();
        let status = params.get("status").filter(|s| !s.is_empty()).cloned();
        let tag = params.get("tag").filter(|s| !s.is_empty()).cloned();
        let property = params.get("property")
            .and_then(|s| parse_property_filter(s));
        let since = params.get("since")
            .and_then(|s| parse_date_to_unix(s));
        let sort = params.get("sort")
            .and_then(|s| parse_sort(s));
        let limit = params.get("limit")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);
        let follow_links = params.get("follow_links").map(|s| s == "true").unwrap_or(false);

        NodeFilter { query, kind, status, tag, property, since, sort, limit, follow_links }
    }

    /// Return `true` if the node passes all active filters.
    /// Deleted nodes always fail (return false).
    pub fn matches(&self, node: &CruxNode) -> bool {
        // Always exclude soft-deleted nodes
        if node.deleted_at.is_some() {
            return false;
        }

        // query: substring on name / kind / any tag / summary
        if let Some(q) = &self.query {
            let q = q.to_lowercase();
            let hit = node.name.to_lowercase().contains(&q)
                || node.kind.to_lowercase().contains(&q)
                || node.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || node.summary.to_lowercase().contains(&q);
            if !hit {
                return false;
            }
        }

        // kind: exact match (case-insensitive)
        if let Some(k) = &self.kind {
            if !node.kind.eq_ignore_ascii_case(k) {
                return false;
            }
        }

        // status: exact match on planning.status (case-insensitive)
        if let Some(s) = &self.status {
            match &node.planning.status {
                Some(ps) => {
                    if !ps.eq_ignore_ascii_case(s) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // tag: exact match on any tag (case-insensitive)
        if let Some(t) = &self.tag {
            let t_lower = t.to_lowercase();
            if !node.tags.iter().any(|tag| tag.to_lowercase() == t_lower) {
                return false;
            }
        }

        // property: key=value / key>N / key<N
        if let Some(pf) = &self.property {
            if !matches_property(&node.properties, pf) {
                return false;
            }
        }

        // since: planning.updated_at >= since (nodes without it are excluded)
        if let Some(since_ts) = self.since {
            match node.planning.updated_at {
                Some(ts) => {
                    if ts < since_ts {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    /// Sort `nodes` in-place according to the `sort` field.
    pub fn apply_sort<'a>(&self, nodes: &mut Vec<&'a CruxNode>) {
        match &self.sort {
            Some(SortField::Priority) => {
                nodes.sort_by_key(|n| n.planning.priority.unwrap_or(u8::MAX));
            }
            Some(SortField::Name) => {
                nodes.sort_by(|a, b| a.name.cmp(&b.name));
            }
            Some(SortField::Created) => {
                // Newest first (descending); nodes without updated_at sort last
                nodes.sort_by(|a, b| {
                    let ta = a.planning.updated_at.unwrap_or(0);
                    let tb = b.planning.updated_at.unwrap_or(0);
                    tb.cmp(&ta)
                });
            }
            None => {}
        }
    }

    /// True if no filter fields are set (empty filter = match everything).
    pub fn is_empty(&self) -> bool {
        self.query.is_none()
            && self.kind.is_none()
            && self.status.is_none()
            && self.tag.is_none()
            && self.property.is_none()
            && self.since.is_none()
    }

    /// Human-readable description of active filters (for output headers).
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(q) = &self.query {
            parts.push(format!("query={:?}", q));
        }
        if let Some(k) = &self.kind {
            parts.push(format!("kind={:?}", k));
        }
        if let Some(s) = &self.status {
            parts.push(format!("status={:?}", s));
        }
        if let Some(t) = &self.tag {
            parts.push(format!("tag={:?}", t));
        }
        if let Some(pf) = &self.property {
            let op = match pf.op {
                PropertyOp::Eq => "=",
                PropertyOp::Gt => ">",
                PropertyOp::Lt => "<",
            };
            parts.push(format!("property={}{}{}", pf.key, op, pf.value));
        }
        if let Some(since) = self.since {
            parts.push(format!("since={}", since));
        }
        if let Some(sf) = &self.sort {
            let s = match sf {
                SortField::Priority => "priority",
                SortField::Name => "name",
                SortField::Created => "created",
            };
            parts.push(format!("sort={}", s));
        }
        if parts.is_empty() {
            "(all nodes)".to_string()
        } else {
            parts.join(", ")
        }
    }
}

// ===========================================================================
// Property matching helpers
// ===========================================================================

fn matches_property(properties: &[String], pf: &PropertyFilter) -> bool {
    let key_prefix = format!("{}=", pf.key);
    for prop in properties {
        if let Some(val_str) = prop.strip_prefix(&key_prefix) {
            match &pf.op {
                PropertyOp::Eq => {
                    return val_str == pf.value;
                }
                PropertyOp::Gt => {
                    if let (Ok(a), Ok(b)) = (val_str.parse::<f64>(), pf.value.parse::<f64>()) {
                        return a > b;
                    }
                    // Non-numeric: no match
                }
                PropertyOp::Lt => {
                    if let (Ok(a), Ok(b)) = (val_str.parse::<f64>(), pf.value.parse::<f64>()) {
                        return a < b;
                    }
                }
            }
        }
    }
    false
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date_to_unix_epoch() {
        assert_eq!(parse_date_to_unix("1970-01-01"), Some(0));
    }

    #[test]
    fn test_parse_date_to_unix_known() {
        // 2026-04-09: count days manually
        // Years 1970..2026: 56 years, 14 leap years (72,76,80,84,88,92,96,2000,04,08,12,16,20,24)
        // = 42*365 + 14*366 = 15330 + 5124 = 20454 days through end of 2025
        // 2026 is not leap. Jan=31, Feb=28, Mar=31 = 90 days + 8 (Apr 9 = day 9, offset 8)
        // Total: 20454 + 90 + 8 = 20552 days → 20552 * 86400
        let expected = 20552u64 * 86400;
        assert_eq!(parse_date_to_unix("2026-04-09"), Some(expected));
    }

    #[test]
    fn test_parse_date_to_unix_raw_int() {
        assert_eq!(parse_date_to_unix("1741000000"), Some(1741000000));
    }

    #[test]
    fn test_parse_property_filter_eq() {
        let pf = parse_property_filter("cost=5000").unwrap();
        assert_eq!(pf.key, "cost");
        assert_eq!(pf.op, PropertyOp::Eq);
        assert_eq!(pf.value, "5000");
    }

    #[test]
    fn test_parse_property_filter_gt() {
        let pf = parse_property_filter("cost>5000").unwrap();
        assert!(pf.op == PropertyOp::Gt);
    }

    #[test]
    fn test_parse_property_filter_lt() {
        let pf = parse_property_filter("lines<100").unwrap();
        assert_eq!(pf.key, "lines");
        assert!(pf.op == PropertyOp::Lt);
        assert_eq!(pf.value, "100");
    }

    #[test]
    fn test_filter_from_args_basic() {
        let args = r#"{"action":"query","path":"/foo","filter_kind":"task","filter_status":"Todo","sort":"priority","limit":10}"#;
        let f = NodeFilter::from_args(args);
        assert_eq!(f.kind, Some("task".to_string()));
        assert_eq!(f.status, Some("Todo".to_string()));
        assert_eq!(f.sort, Some(SortField::Priority));
        assert_eq!(f.limit, 10);
    }

    #[test]
    fn test_filter_from_query_params() {
        let mut params = HashMap::new();
        params.insert("q".to_string(), "auth".to_string());
        params.insert("kind".to_string(), "module".to_string());
        params.insert("sort".to_string(), "name".to_string());
        let f = NodeFilter::from_query_params(&params);
        assert_eq!(f.query, Some("auth".to_string()));
        assert_eq!(f.kind, Some("module".to_string()));
        assert_eq!(f.sort, Some(SortField::Name));
    }
}
