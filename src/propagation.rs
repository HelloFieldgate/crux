//! Vector clocks for causal consistency across the crux mesh.
//!
//! Each crux maintains a local counter. Audit events carry the writer's
//! full clock at write time. Recipients can detect causal ordering and
//! out-of-order delivery by comparing clocks.

use std::collections::HashMap;
use crate::json::json_escape;

// ===========================================================================
// VectorClock
// ===========================================================================

/// A vector clock mapping crux_id → sequence number.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VectorClock {
    pub entries: HashMap<String, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        VectorClock { entries: HashMap::new() }
    }

    /// Increment the counter for `crux_id` and return the new value.
    pub fn increment(&mut self, crux_id: &str) -> u64 {
        let counter = self.entries.entry(crux_id.to_string()).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Current counter for `crux_id` (0 if absent).
    pub fn get(&self, crux_id: &str) -> u64 {
        self.entries.get(crux_id).copied().unwrap_or(0)
    }

    /// Merge another clock into this one: take the max of each entry.
    pub fn merge(&mut self, other: &VectorClock) {
        for (k, v) in &other.entries {
            let entry = self.entries.entry(k.clone()).or_insert(0);
            if *v > *entry {
                *entry = *v;
            }
        }
    }

    /// Returns true if this clock causally covers `update_clock` from `sender_id`.
    ///
    /// For the sender's own entry: update must be exactly local + 1 (next in sequence).
    /// For all other entries: our value must be ≥ the update's view (we've seen those events).
    pub fn is_causally_ready(&self, update_clock: &VectorClock, sender_id: &str) -> bool {
        for (k, v) in &update_clock.entries {
            if k == sender_id {
                if *v != self.get(k) + 1 {
                    return false;
                }
            } else if self.get(k) < *v {
                return false;
            }
        }
        true
    }

    /// Returns true if every entry in `other` is ≤ the corresponding entry in self.
    /// Used to filter audit events already covered by a client's clock.
    pub fn dominates(&self, other: &VectorClock) -> bool {
        for (k, v) in &other.entries {
            if self.get(k) < *v {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // Canonical serialization (sorted keys, no whitespace)
    // Used as input to sha256 for prev_hash and signing.
    // -----------------------------------------------------------------------

    /// Emit `{"k1":v1,"k2":v2}` with keys in lexicographic order.
    pub fn to_json_inline(&self) -> String {
        let mut keys: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        let mut out = String::from("{");
        for (i, k) in keys.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            // json_escape returns `"escaped_string"` (with surrounding quotes)
            out.push_str(&json_escape(k));
            out.push(':');
            out.push_str(&self.entries[*k].to_string());
        }
        out.push('}');
        out
    }

    /// Parse a clock from the format produced by `to_json_inline`.
    ///
    /// Accepts `{}` for an empty clock. Returns `Err` on malformed input.
    pub fn parse_inline(s: &str) -> Result<VectorClock, String> {
        let s = s.trim();
        if !s.starts_with('{') || !s.ends_with('}') {
            return Err(format!("VectorClock: expected {{…}}, got: {s}"));
        }
        let inner = &s[1..s.len() - 1];
        let mut vc = VectorClock::new();
        if inner.trim().is_empty() {
            return Ok(vc);
        }
        // Parse "key":u64 pairs separated by commas.
        // Keys contain no embedded quotes (they are sha256:… crux IDs).
        let mut pos = 0;
        let bytes = inner.as_bytes();
        while pos < bytes.len() {
            // Skip whitespace and commas
            while pos < bytes.len() && (bytes[pos] == b',' || bytes[pos] == b' ') {
                pos += 1;
            }
            if pos >= bytes.len() {
                break;
            }
            // Expect opening quote for key
            if bytes[pos] != b'"' {
                return Err(format!("VectorClock: expected '\"' at pos {pos} in: {inner}"));
            }
            pos += 1;
            let key_start = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                pos += 1;
            }
            if pos >= bytes.len() {
                return Err(format!("VectorClock: unterminated key in: {inner}"));
            }
            let key = &inner[key_start..pos];
            pos += 1; // skip closing quote
            // Skip ':' (with optional whitespace)
            while pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            if pos >= bytes.len() || bytes[pos] != b':' {
                return Err(format!("VectorClock: expected ':' after key '{key}'"));
            }
            pos += 1;
            while pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            // Parse numeric value
            let val_start = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            let val_str = &inner[val_start..pos];
            let val: u64 = val_str.parse().map_err(|_| {
                format!("VectorClock: invalid number '{val_str}' for key '{key}'")
            })?;
            vc.entries.insert(key.to_string(), val);
        }
        Ok(vc)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vc_increment_starts_at_one() {
        let mut vc = VectorClock::new();
        let v = vc.increment("c1");
        assert_eq!(v, 1);
        let v2 = vc.increment("c1");
        assert_eq!(v2, 2);
        assert_eq!(vc.get("c1"), 2);
        assert_eq!(vc.get("missing"), 0);
    }

    #[test]
    fn vc_merge_takes_max() {
        let mut a = VectorClock::new();
        a.increment("c1");
        a.increment("c1");
        a.increment("c2");

        let mut b = VectorClock::new();
        b.increment("c1");
        b.increment("c3");

        a.merge(&b);
        assert_eq!(a.get("c1"), 2); // max(2, 1)
        assert_eq!(a.get("c2"), 1); // from a only
        assert_eq!(a.get("c3"), 1); // from b only
    }

    #[test]
    fn vc_is_causally_ready() {
        let mut local = VectorClock::new();
        local.increment("c1"); // c1=1

        let mut update = VectorClock::new();
        update.increment("c2"); // sender=c2 at 1; c2=1
        update.increment("c1"); // c1=1 (others we must have seen)

        // local has c1=1, c2=0 — sender c2's update is seq 1, our c2 is 0 → 0+1=1 ✓
        // c1: other entry, update has 1, we have 1 ✓
        assert!(local.is_causally_ready(&update, "c2"));

        // If sender already at c2=2 and we have c2=0 → not ready
        update.increment("c2"); // c2=2
        assert!(!local.is_causally_ready(&update, "c2"));
    }

    #[test]
    fn vc_dominates() {
        let mut big = VectorClock::new();
        big.increment("c1");
        big.increment("c1"); // c1=2
        big.increment("c2"); // c2=1

        let mut small = VectorClock::new();
        small.increment("c1"); // c1=1

        assert!(big.dominates(&small));
        assert!(!small.dominates(&big));

        // Equal clocks dominate each other
        let equal = big.clone();
        assert!(big.dominates(&equal));
    }

    #[test]
    fn vc_canonical_roundtrip() {
        let mut vc = VectorClock::new();
        vc.increment("sha256:bbb");
        vc.increment("sha256:aaa");
        vc.increment("sha256:aaa"); // aaa=2, bbb=1

        let json = vc.to_json_inline();
        // Keys must be sorted: aaa before bbb
        assert_eq!(json, r#"{"sha256:aaa":2,"sha256:bbb":1}"#);

        let parsed = VectorClock::parse_inline(&json).unwrap();
        assert_eq!(parsed, vc);

        // Empty clock
        let empty_json = VectorClock::new().to_json_inline();
        assert_eq!(empty_json, "{}");
        let empty_parsed = VectorClock::parse_inline("{}").unwrap();
        assert_eq!(empty_parsed, VectorClock::new());
    }
}
