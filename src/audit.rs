//! Append-only audit log for crux and mesh operations.
//!
//! Records every node/edge addition, modification, deletion, and query into
//! `.crux-audit.json` alongside the crux file. Each log entry is a JSON line
//! (newline-delimited JSON / NDJSON).
//!
//! **v2 chain format** (Phase 4A+):
//! - A header line `{"audit_version":2,"chain_start":<ts>}` is written first.
//! - Each event carries `seq` (monotonic from 1), `clock` (VectorClock at write
//!   time), and `prev_hash` (sha256 of the preceding line).
//! - `verify_chain` checks seq contiguity and the hash chain for tamper evidence.
//!
//! v1 files (no seq/clock/prev_hash) can be read for forward-compat; they parse
//! with `seq=0` and an empty clock. Use `migrate_v1` to upgrade them.

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

use crate::json::{extract_string_value, extract_u64_value, json_escape};
use crate::crypto::sha256_hex;
use crate::propagation::VectorClock;
use crate::schema::now_unix;

/// The audit log filename written alongside `.crux.json`.
pub const AUDIT_LOG_FILE: &str = ".crux-audit.json";

/// 64-zero string used as prev_hash for the first event.
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

// ===========================================================================
// Event types
// ===========================================================================

/// The kind of operation recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventKind {
    NodeAdded,
    NodeUpdated,
    NodeDeleted,
    EdgeAdded,
    EdgeDeleted,
    CruxCreated,
    CruxGenerated,
    MeshJoined,
    MeshLeft,
    Query,
    Verify,
}

impl AuditEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventKind::NodeAdded => "node_added",
            AuditEventKind::NodeUpdated => "node_updated",
            AuditEventKind::NodeDeleted => "node_deleted",
            AuditEventKind::EdgeAdded => "edge_added",
            AuditEventKind::EdgeDeleted => "edge_deleted",
            AuditEventKind::CruxCreated => "crux_created",
            AuditEventKind::CruxGenerated => "crux_generated",
            AuditEventKind::MeshJoined => "mesh_joined",
            AuditEventKind::MeshLeft => "mesh_left",
            AuditEventKind::Query => "query",
            AuditEventKind::Verify => "verify",
        }
    }
}

/// A single audit log entry (v2 chain format).
///
/// When constructing partial events for `AuditLog::append`, `seq`, `clock`,
/// and `prev_hash` may be left at their defaults — `append` fills them in.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Monotonic sequence number within this log (1-based). Set by `append`.
    pub seq: u64,
    pub timestamp: u64,
    pub event: AuditEventKind,
    /// The crux ID this event applies to.
    pub crux_id: String,
    /// The primary subject (node name, edge id, query string, etc.)
    pub subject: String,
    /// Optional actor — the agent or user who triggered the event.
    pub actor: Option<String>,
    /// Additional detail (e.g. updated fields, result count).
    pub detail: Option<String>,
    /// VectorClock at the moment this event was appended. Set by `append`.
    pub clock: VectorClock,
    /// sha256 of the preceding line in the file (or ZERO_HASH for seq=1).
    /// Set by `append`.
    pub prev_hash: String,
    /// W-OTS signature (hex) over sha256(canonical_bytes). Empty for unsigned events.
    /// Set by `append` when the log has a signing key.
    pub signature: String,
    /// sha256 of the subkey public key used to sign this event. Empty for unsigned events.
    pub pubkey_hash: String,
}

impl Default for AuditEvent {
    fn default() -> Self {
        AuditEvent {
            seq: 0,
            timestamp: 0,
            event: AuditEventKind::Query,
            crux_id: String::new(),
            subject: String::new(),
            actor: None,
            detail: None,
            clock: VectorClock::new(),
            prev_hash: String::new(),
            signature: String::new(),
            pubkey_hash: String::new(),
        }
    }
}

impl AuditEvent {
    /// Serialize to a single-line JSON string (canonical key order, no extra whitespace).
    ///
    /// Format: `{"seq":N,"ts":T,"event":"...","crux_id":"...","subject":"...",
    ///            "actor":"...","detail":"...","clock":{...},"prev_hash":"sha256:..."}`
    pub fn to_json_line(&self) -> String {
        let mut out = String::new();
        out.push('{');
        let _ = write!(out, "\"seq\":{}", self.seq);
        let _ = write!(out, ",\"ts\":{}", self.timestamp);
        let _ = write!(out, ",\"event\":{}", json_escape(self.event.as_str()));
        let _ = write!(out, ",\"crux_id\":{}", json_escape(&self.crux_id));
        let _ = write!(out, ",\"subject\":{}", json_escape(&self.subject));
        if let Some(ref actor) = self.actor {
            let _ = write!(out, ",\"actor\":{}", json_escape(actor));
        }
        if let Some(ref detail) = self.detail {
            let _ = write!(out, ",\"detail\":{}", json_escape(detail));
        }
        let _ = write!(out, ",\"clock\":{}", self.clock.to_json_inline());
        let _ = write!(out, ",\"prev_hash\":{}", json_escape(&self.prev_hash));
        if !self.signature.is_empty() {
            let _ = write!(out, ",\"signature\":{}", json_escape(&self.signature));
            let _ = write!(out, ",\"pubkey_hash\":{}", json_escape(&self.pubkey_hash));
        }
        out.push('}');
        out
    }

    /// Canonical bytes used for hashing and (in Phase 4B) signing.
    ///
    /// Fields joined with `\x1f` (ASCII unit separator), excluding the
    /// `signature` field (added in Phase 4B). Hashing `canonical_bytes` of
    /// event N produces the `prev_hash` stored in event N+1.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let seq_s = self.seq.to_string();
        let ts_s = self.timestamp.to_string();
        let actor = self.actor.as_deref().unwrap_or("");
        let detail = self.detail.as_deref().unwrap_or("");
        let clock_s = self.clock.to_json_inline();
        let parts = [
            seq_s.as_str(),
            ts_s.as_str(),
            self.event.as_str(),
            &self.crux_id,
            &self.subject,
            actor,
            detail,
            &clock_s,
            &self.prev_hash,
        ];
        parts.join("\x1f").into_bytes()
    }
}

// ===========================================================================
// ChainError
// ===========================================================================

/// Errors returned by `AuditLog::verify_chain`.
#[derive(Debug, PartialEq)]
pub enum ChainErrorKind {
    SeqGap,
    PrevHashMismatch,
    ClockRegression,
    MissingHeader,
    BadSignature,
    MissingKey,
}

#[derive(Debug, PartialEq)]
pub struct ChainError {
    pub at_seq: u64,
    pub kind: ChainErrorKind,
    pub detail: String,
}

// ===========================================================================
// AuditLog
// ===========================================================================

/// Append-only audit log backed by a file.
pub struct AuditLog {
    pub path: PathBuf,
    /// The crux_id used to increment the local vector clock on each append.
    /// Empty string disables clock advancement (anonymous / legacy usage).
    pub crux_id: String,
    /// W-OTS master private key for signing appended events.
    /// If `None`, events are written unsigned.
    pub signing_key: Option<Vec<u8>>,
}

impl AuditLog {
    /// Open (or create) an audit log at the given path.
    pub fn open(path: PathBuf) -> Self {
        AuditLog { path, crux_id: String::new(), signing_key: None }
    }

    /// Open the audit log next to a crux file or directory.
    pub fn for_crux(crux_dir: &Path) -> Self {
        let dir = if crux_dir.is_file() {
            crux_dir.parent().unwrap_or(crux_dir).to_path_buf()
        } else {
            crux_dir.to_path_buf()
        };
        AuditLog { path: dir.join(AUDIT_LOG_FILE), crux_id: String::new(), signing_key: None }
    }

    /// Open with a known crux_id so the vector clock is properly advanced.
    pub fn with_id(path: PathBuf, crux_id: &str) -> Self {
        AuditLog { path, crux_id: crux_id.to_string(), signing_key: None }
    }

    /// Open a signing audit log: loads the master private key from
    /// `~/.crux-keys/<mesh_id>.priv`. Events appended will be W-OTS signed.
    ///
    /// Returns `Err` if the key file cannot be read; use `with_id` for unsigned logs.
    pub fn open_signed(path: PathBuf, crux_id: &str, mesh_id: &str) -> Result<Self, String> {
        let key = crate::crypto::read_crux_key(mesh_id)?;
        Ok(AuditLog { path, crux_id: crux_id.to_string(), signing_key: Some(key) })
    }

    // -----------------------------------------------------------------------
    // Append
    // -----------------------------------------------------------------------

    /// Append a single event. Fills in `seq`, `clock`, and `prev_hash`
    /// automatically based on the current file state.
    ///
    /// Writes a v2 header line on the very first append if the file is empty.
    pub fn append(&self, mut event: AuditEvent) -> Result<(), String> {
        use std::fs::OpenOptions;
        use std::io::Write;

        // Read current state from the file (O(N) but correct and safe).
        let (seq, prev_hash, mut clock) = self.read_chain_state();

        // Ensure v2 header exists if file is new.
        let needs_header = seq == 0 && !self.path.exists();

        // Advance the local clock.
        if !self.crux_id.is_empty() {
            clock.increment(&self.crux_id);
        }

        event.seq = seq + 1;
        event.prev_hash = prev_hash;
        event.clock = clock;
        if event.timestamp == 0 {
            event.timestamp = now_unix();
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("Cannot open audit log '{}': {e}", self.path.display()))?;

        if needs_header {
            writeln!(file, "{{\"audit_version\":2,\"chain_start\":{}}}", now_unix())
                .map_err(|e| format!("Cannot write audit log header: {e}"))?;
        }

        // Sign if a master private key is configured.
        if let Some(ref master_priv) = self.signing_key {
            let subkey = crate::crypto::derive_subkey(master_priv, event.seq);
            let cb = event.canonical_bytes();
            let hash_vec = crate::crypto::sha256(&cb);
            let hash_arr: [u8; 32] = hash_vec.try_into().expect("sha256 is 32 bytes");
            let sig = crate::crypto::wots_sign_raw(&subkey, &hash_arr);
            let subkey_pub = crate::crypto::wots_pubkey_from_privkey(&subkey);
            event.signature = crate::crypto::bytes_to_hex(&sig);
            event.pubkey_hash = format!("sha256:{}", crate::crypto::sha256_hex(&subkey_pub));
        }

        let line = event.to_json_line();
        writeln!(file, "{line}").map_err(|e| format!("Cannot write audit log: {e}"))
    }

    // -----------------------------------------------------------------------
    // Read helpers
    // -----------------------------------------------------------------------

    /// Read all events from the log, skipping header/meta lines.
    pub fn read_all(&self) -> Vec<AuditEvent> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        content.lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| !l.contains("\"audit_version\""))
            .filter_map(|line| parse_audit_line(line))
            .collect()
    }

    /// Count total event entries in the log (excludes header lines).
    pub fn count(&self) -> usize {
        self.read_all().len()
    }

    /// Return the current merged VectorClock across all logged events.
    pub fn current_clock(&self) -> VectorClock {
        let mut vc = VectorClock::new();
        for e in self.read_all() {
            vc.merge(&e.clock);
        }
        vc
    }

    /// Return events whose clock is NOT dominated by `since`.
    ///
    /// An event is "already covered" by `since` if `since.dominates(event.clock)`.
    /// Events not covered are those with causal progress the caller hasn't seen.
    pub fn diff_since_clock(&self, since: &VectorClock) -> Vec<AuditEvent> {
        self.read_all()
            .into_iter()
            .filter(|e| !since.dominates(&e.clock))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Chain verification
    // -----------------------------------------------------------------------

    /// Verify the chain: seq is consecutive from 1, prev_hash links each line,
    /// and (if events carry signatures) each signature is valid.
    ///
    /// `key_resolver(crux_id)` returns the master private key for that crux.
    /// Pass `&|_| None` to skip signature verification (chain integrity only).
    ///
    /// Returns `Ok(n)` for n verified events, or the first `ChainError`.
    pub fn verify_chain(&self, key_resolver: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<usize, ChainError> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return Ok(0),
        };

        let raw_lines: Vec<&str> = content.lines()
            .filter(|l| !l.trim().is_empty())
            .collect();

        if raw_lines.is_empty() {
            return Ok(0);
        }

        let event_lines: Vec<&str> = raw_lines.iter()
            .copied()
            .filter(|l| !l.contains("\"audit_version\""))
            .collect();

        let mut expected_seq = 1u64;
        let mut prev_line_hash = ZERO_HASH.to_string();

        for (i, &raw) in event_lines.iter().enumerate() {
            let event = parse_audit_line(raw).ok_or_else(|| ChainError {
                at_seq: expected_seq,
                kind: ChainErrorKind::SeqGap,
                detail: format!("unparseable line at index {i}"),
            })?;

            // Seq check
            if event.seq != 0 && event.seq != expected_seq {
                return Err(ChainError {
                    at_seq: event.seq,
                    kind: ChainErrorKind::SeqGap,
                    detail: format!("expected seq {expected_seq}, got {}", event.seq),
                });
            }

            // prev_hash check (only when events carry a non-empty prev_hash)
            if !event.prev_hash.is_empty() && event.prev_hash != prev_line_hash {
                return Err(ChainError {
                    at_seq: event.seq,
                    kind: ChainErrorKind::PrevHashMismatch,
                    detail: format!(
                        "expected prev_hash {prev_line_hash}, got {}",
                        event.prev_hash
                    ),
                });
            }

            // Signature check (only when the event carries a signature)
            if !event.signature.is_empty() {
                match key_resolver(&event.crux_id) {
                    None => return Err(ChainError {
                        at_seq: event.seq,
                        kind: ChainErrorKind::MissingKey,
                        detail: format!("no key for crux_id '{}'", event.crux_id),
                    }),
                    Some(master_priv) => {
                        let subkey = crate::crypto::derive_subkey(&master_priv, event.seq);
                        let subkey_pub = crate::crypto::wots_pubkey_from_privkey(&subkey);
                        let cb = event.canonical_bytes();
                        let hash_vec = crate::crypto::sha256(&cb);
                        let hash_arr: [u8; 32] = hash_vec.try_into().expect("sha256 is 32 bytes");
                        let sig_bytes = crate::crypto::hex_to_bytes(&event.signature)
                            .map_err(|e| ChainError {
                                at_seq: event.seq,
                                kind: ChainErrorKind::BadSignature,
                                detail: format!("invalid signature hex: {e}"),
                            })?;
                        if !crate::crypto::wots_verify_raw(&subkey_pub, &hash_arr, &sig_bytes) {
                            return Err(ChainError {
                                at_seq: event.seq,
                                kind: ChainErrorKind::BadSignature,
                                detail: "W-OTS signature verification failed".to_string(),
                            });
                        }
                    }
                }
            }

            // Advance for next iteration
            prev_line_hash = format!("sha256:{}", sha256_hex(raw.as_bytes()));
            expected_seq += 1;
        }

        Ok(event_lines.len())
    }

    // -----------------------------------------------------------------------
    // v1 migration
    // -----------------------------------------------------------------------

    /// Migrate a v1 log (no seq/clock/prev_hash) to v2 in-place.
    ///
    /// The original file is copied to `<path>.v1.bak`. A fresh v2 file is
    /// written with a header and all events re-emitted with proper seq and
    /// prev_hash. Returns `Ok(n)` for n migrated events, or `Err` on I/O failure.
    pub fn migrate_v1(&self) -> Result<usize, String> {
        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("Cannot read log for migration: {e}"))?;

        let bak = PathBuf::from(format!("{}.v1.bak", self.path.display()));
        std::fs::copy(&self.path, &bak)
            .map_err(|e| format!("Cannot create backup {}: {e}", bak.display()))?;

        // Parse all v1 events (they may have seq=0 and empty clocks)
        let raw_events: Vec<_> = content.lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| !l.contains("\"audit_version\""))
            .filter_map(|l| parse_audit_line(l))
            .collect();

        // Write new v2 file
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|e| format!("Cannot open log for migration write: {e}"))?;

        writeln!(file, "{{\"audit_version\":2,\"chain_start\":{},\"migrated_from_v1\":true}}", now_unix())
            .map_err(|e| format!("Cannot write v2 header: {e}"))?;

        let mut prev_hash = ZERO_HASH.to_string();
        let mut clock = VectorClock::new();
        let n = raw_events.len();
        for (i, mut ev) in raw_events.into_iter().enumerate() {
            ev.seq = (i + 1) as u64;
            ev.prev_hash = prev_hash.clone();
            if !self.crux_id.is_empty() {
                clock.increment(&self.crux_id);
            }
            ev.clock = clock.clone();
            let line = ev.to_json_line();
            prev_hash = format!("sha256:{}", sha256_hex(line.as_bytes()));
            writeln!(file, "{line}").map_err(|e| format!("Cannot write migrated event: {e}"))?;
        }

        Ok(n)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Read the file and return `(last_seq, prev_hash_of_last_line, current_clock)`.
    /// Returns `(0, ZERO_HASH, empty_clock)` when the file is empty or absent.
    fn read_chain_state(&self) -> (u64, String, VectorClock) {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return (0, ZERO_HASH.to_string(), VectorClock::new()),
        };

        let event_lines: Vec<&str> = content.lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| !l.contains("\"audit_version\""))
            .collect();

        if event_lines.is_empty() {
            return (0, ZERO_HASH.to_string(), VectorClock::new());
        }

        let last_line = event_lines[event_lines.len() - 1];
        let last_hash = format!("sha256:{}", sha256_hex(last_line.as_bytes()));
        let seq = event_lines.len() as u64;

        // Build clock from all events (merge for multi-writer support)
        let mut clock = VectorClock::new();
        for line in &event_lines {
            if let Some(ev) = parse_audit_line(line) {
                clock.merge(&ev.clock);
            }
        }

        (seq, last_hash, clock)
    }
}

// ===========================================================================
// Convenience constructors
// ===========================================================================

fn partial_event(
    timestamp: u64,
    event: AuditEventKind,
    crux_id: &str,
    subject: &str,
    actor: Option<&str>,
    detail: Option<String>,
) -> AuditEvent {
    AuditEvent {
        seq: 0,
        timestamp,
        event,
        crux_id: crux_id.to_string(),
        subject: subject.to_string(),
        actor: actor.map(|s| s.to_string()),
        detail,
        clock: VectorClock::new(),
        prev_hash: String::new(),
        signature: String::new(),
        pubkey_hash: String::new(),
    }
}

/// Log a node addition.
pub fn log_node_added(log: &AuditLog, crux_id: &str, node_name: &str, actor: Option<&str>) {
    let _ = log.append(partial_event(
        now_unix(), AuditEventKind::NodeAdded, crux_id, node_name, actor, None,
    ));
}

/// Log a node update.
pub fn log_node_updated(
    log: &AuditLog,
    crux_id: &str,
    node_name: &str,
    fields_changed: &[&str],
    actor: Option<&str>,
) {
    let _ = log.append(partial_event(
        now_unix(), AuditEventKind::NodeUpdated, crux_id, node_name, actor,
        Some(fields_changed.join(", ")),
    ));
}

/// Log a node deletion (soft or hard).
pub fn log_node_deleted(
    log: &AuditLog,
    crux_id: &str,
    node_name: &str,
    hard: bool,
    actor: Option<&str>,
) {
    let _ = log.append(partial_event(
        now_unix(), AuditEventKind::NodeDeleted, crux_id, node_name, actor,
        Some(if hard { "hard-delete" } else { "soft-delete" }.to_string()),
    ));
}

/// Log an edge addition.
pub fn log_edge_added(log: &AuditLog, crux_id: &str, src: &str, dst: &str, actor: Option<&str>) {
    let _ = log.append(partial_event(
        now_unix(), AuditEventKind::EdgeAdded, crux_id,
        &format!("{src} -> {dst}"), actor, None,
    ));
}

/// Log a query.
pub fn log_query(
    log: &AuditLog,
    crux_id: &str,
    query: &str,
    result_count: usize,
    actor: Option<&str>,
) {
    let _ = log.append(partial_event(
        now_unix(), AuditEventKind::Query, crux_id, query, actor,
        Some(format!("{result_count} result(s)")),
    ));
}

// ===========================================================================
// Parsing
// ===========================================================================

fn parse_audit_line(line: &str) -> Option<AuditEvent> {
    let timestamp = extract_u64_value(line, "ts")?;
    let event_str = extract_string_value(line, "event")?;
    let crux_id = extract_string_value(line, "crux_id").unwrap_or_default();
    let subject = extract_string_value(line, "subject").unwrap_or_default();
    let actor = extract_string_value(line, "actor");
    let detail = extract_string_value(line, "detail");

    // v2 fields — default to zero/empty for v1 lines
    let seq = extract_u64_value(line, "seq").unwrap_or(0);
    let prev_hash = extract_string_value(line, "prev_hash").unwrap_or_default();
    let clock = extract_clock_inline(line).unwrap_or_default();

    let event = match event_str.as_str() {
        "node_added" => AuditEventKind::NodeAdded,
        "node_updated" => AuditEventKind::NodeUpdated,
        "node_deleted" => AuditEventKind::NodeDeleted,
        "edge_added" => AuditEventKind::EdgeAdded,
        "edge_deleted" => AuditEventKind::EdgeDeleted,
        "crux_created" => AuditEventKind::CruxCreated,
        "crux_generated" => AuditEventKind::CruxGenerated,
        "mesh_joined" => AuditEventKind::MeshJoined,
        "mesh_left" => AuditEventKind::MeshLeft,
        "query" => AuditEventKind::Query,
        "verify" => AuditEventKind::Verify,
        _ => return None,
    };

    let signature = extract_string_value(line, "signature").unwrap_or_default();
    let pubkey_hash = extract_string_value(line, "pubkey_hash").unwrap_or_default();

    Some(AuditEvent { seq, timestamp, event, crux_id, subject, actor, detail, clock, prev_hash, signature, pubkey_hash })
}

/// Extract the inline `{"k":v}` object stored under the `"clock"` key.
fn extract_clock_inline(line: &str) -> Option<VectorClock> {
    let key = "\"clock\":";
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    // Find the matching closing brace (simple: no nested objects in VectorClock)
    let open = rest.find('{')?;
    let close = rest[open..].find('}')? + open + 1;
    VectorClock::parse_inline(&rest[open..close]).ok()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_log_with_id(crux_id: &str) -> (AuditLog, PathBuf) {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir()
            .join(format!("crux_audit_test_{}_{}", now_unix(), id));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::with_id(dir.join(AUDIT_LOG_FILE), crux_id);
        (log, dir)
    }

    fn temp_log() -> (AuditLog, PathBuf) {
        temp_log_with_id("test-crux")
    }

    // ----- Existing tests (forward-compat) ----------------------------------

    #[test]
    fn test_audit_event_to_json_line() {
        let event = AuditEvent {
            seq: 1,
            timestamp: 1700000000,
            event: AuditEventKind::NodeAdded,
            crux_id: "sha256:abc".to_string(),
            subject: "@my_func".to_string(),
            actor: Some("agent-1".to_string()),
            detail: None,
            clock: VectorClock::new(),
            prev_hash: ZERO_HASH.to_string(),
            signature: String::new(),
            pubkey_hash: String::new(),
        };
        let line = event.to_json_line();
        assert!(line.contains("\"node_added\""), "missing event");
        assert!(line.contains("@my_func"), "missing subject");
        assert!(line.contains("agent-1"), "missing actor");
        assert!(line.contains("1700000000"), "missing timestamp");
        assert!(line.contains("\"seq\":1"), "missing seq");
        assert!(line.contains("\"prev_hash\""), "missing prev_hash");
    }

    #[test]
    fn test_audit_log_append_and_read() {
        let (log, dir) = temp_log();

        log_node_added(&log, "sha256:crux1", "@auth", Some("agent-1"));
        log_node_added(&log, "sha256:crux1", "@login", None);
        log_query(&log, "sha256:crux1", "auth", 5, None);

        let events = log.read_all();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event, AuditEventKind::NodeAdded);
        assert_eq!(events[0].subject, "@auth");
        assert_eq!(events[0].actor, Some("agent-1".to_string()));
        assert_eq!(events[2].event, AuditEventKind::Query);
        assert_eq!(events[2].subject, "auth");
        assert_eq!(events[2].detail, Some("5 result(s)".to_string()));
        assert_eq!(log.count(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_log_for_crux() {
        let dir = std::env::temp_dir()
            .join(format!("crux_audit_forcrux_{}", now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::for_crux(&dir);
        assert_eq!(log.path, dir.join(AUDIT_LOG_FILE));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_log_missing_file_returns_empty() {
        let log = AuditLog::open(PathBuf::from("/tmp/definitely_nonexistent_crux_audit.json"));
        assert_eq!(log.read_all().len(), 0);
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn test_log_node_updated() {
        let (log, dir) = temp_log();
        log_node_updated(&log, "sha256:c1", "@fn", &["summary", "tags"], Some("agent"));
        let events = log.read_all();
        assert_eq!(events[0].event, AuditEventKind::NodeUpdated);
        assert_eq!(events[0].detail, Some("summary, tags".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_node_deleted() {
        let (log, dir) = temp_log();
        log_node_deleted(&log, "sha256:c1", "@old", false, None);
        let events = log.read_all();
        assert_eq!(events[0].event, AuditEventKind::NodeDeleted);
        assert_eq!(events[0].detail, Some("soft-delete".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_edge_added() {
        let (log, dir) = temp_log();
        log_edge_added(&log, "sha256:c1", "@src", "@dst", None);
        let events = log.read_all();
        assert_eq!(events[0].event, AuditEventKind::EdgeAdded);
        assert!(events[0].subject.contains("@src"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- New v2 chain tests -----------------------------------------------

    #[test]
    fn audit_seq_starts_at_one() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@first", None);
        let events = log.read_all();
        assert_eq!(events[0].seq, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_seq_increments() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@a", None);
        log_node_added(&log, "c1", "@b", None);
        log_node_added(&log, "c1", "@c", None);
        let events = log.read_all();
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(events[2].seq, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_clock_bumps_on_append() {
        let (log, dir) = temp_log_with_id("crux-x");
        log_node_added(&log, "c1", "@a", None);
        log_node_added(&log, "c1", "@b", None);
        let events = log.read_all();
        assert_eq!(events[0].clock.get("crux-x"), 1);
        assert_eq!(events[1].clock.get("crux-x"), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_first_event_prev_hash_is_zero() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@a", None);
        let events = log.read_all();
        assert_eq!(events[0].prev_hash, ZERO_HASH);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_prev_hash_chains_across_three_events() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@a", None);
        log_node_added(&log, "c1", "@b", None);
        log_node_added(&log, "c1", "@c", None);

        // Read raw lines to verify hashing
        let content = std::fs::read_to_string(&log.path).unwrap();
        let lines: Vec<&str> = content.lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| !l.contains("\"audit_version\""))
            .collect();
        assert_eq!(lines.len(), 3);

        let events = log.read_all();
        // Event 2's prev_hash should be sha256 of event 1's raw line
        let expected_e2_prev = format!("sha256:{}", sha256_hex(lines[0].as_bytes()));
        assert_eq!(events[1].prev_hash, expected_e2_prev);
        // Event 3's prev_hash should be sha256 of event 2's raw line
        let expected_e3_prev = format!("sha256:{}", sha256_hex(lines[1].as_bytes()));
        assert_eq!(events[2].prev_hash, expected_e3_prev);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_chain_ok() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@a", None);
        log_node_added(&log, "c1", "@b", None);
        let n = log.verify_chain(&|_| None).unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_chain_detects_seq_gap() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@a", None);
        log_node_added(&log, "c1", "@b", None);

        // Tamper: replace seq=2 with seq=5 in the raw file
        let content = std::fs::read_to_string(&log.path).unwrap();
        let tampered = content.replace("\"seq\":2", "\"seq\":5");
        std::fs::write(&log.path, tampered).unwrap();

        let err = log.verify_chain(&|_| None).unwrap_err();
        assert_eq!(err.kind, ChainErrorKind::SeqGap);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_chain_detects_tampered_subject() {
        let (log, dir) = temp_log();
        log_node_added(&log, "c1", "@a", None);
        log_node_added(&log, "c1", "@b", None);

        // Read raw lines; tamper with the subject of line 1
        let content = std::fs::read_to_string(&log.path).unwrap();
        let tampered = content.replace("\"@a\"", "\"@evil\"");
        std::fs::write(&log.path, tampered).unwrap();

        // The hash of the now-modified line 1 will differ from what line 2
        // has stored as prev_hash → PrevHashMismatch
        let result = log.verify_chain(&|_| None);
        assert!(
            result.is_err(),
            "verify_chain should detect tampered subject"
        );
        assert_eq!(result.unwrap_err().kind, ChainErrorKind::PrevHashMismatch);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_migrate_v1_preserves_all_events() {
        let (log, dir) = temp_log();

        // Write a v1-style file manually (no seq/clock/prev_hash)
        let v1_line1 = r#"{"ts":1700000001,"event":"node_added","crux_id":"c1","subject":"@old_fn"}"#;
        let v1_line2 = r#"{"ts":1700000002,"event":"query","crux_id":"c1","subject":"search"}"#;
        std::fs::write(&log.path, format!("{v1_line1}\n{v1_line2}\n")).unwrap();

        let n = log.migrate_v1().unwrap();
        assert_eq!(n, 2);

        // Backup exists
        let bak = PathBuf::from(format!("{}.v1.bak", log.path.display()));
        assert!(bak.exists());

        // New file has proper v2 chain
        let events = log.read_all();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].subject, "@old_fn");
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(events[0].prev_hash, ZERO_HASH);
        assert_ne!(events[1].prev_hash, ""); // has a real hash now

        log.verify_chain(&|_| None).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_diff_since_clock_filters_covered_events() {
        let (log, dir) = temp_log_with_id("crux-x");
        log_node_added(&log, "c1", "@a", None); // seq=1, clock={crux-x:1}
        log_node_added(&log, "c1", "@b", None); // seq=2, clock={crux-x:2}
        log_node_added(&log, "c1", "@c", None); // seq=3, clock={crux-x:3}

        // Client has already seen up to crux-x:2 → should only get seq=3
        let mut seen = VectorClock::new();
        seen.increment("crux-x");
        seen.increment("crux-x"); // crux-x:2

        let diff = log.diff_since_clock(&seen);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].subject, "@c");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- Phase 4B: signing tests ------------------------------------------

    fn make_signed_log(label: &str) -> (AuditLog, PathBuf, Vec<u8>) {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir()
            .join(format!("crux_audit_signed_{}_{}", now_unix(), id));
        std::fs::create_dir_all(&dir).unwrap();
        let keypair = crate::crypto::generate_keypair();
        let master_priv = keypair.private_key.clone();
        let path = dir.join(AUDIT_LOG_FILE);
        let log = AuditLog {
            path,
            crux_id: format!("crux-{label}"),
            signing_key: Some(keypair.private_key),
        };
        (log, dir, master_priv)
    }

    #[test]
    fn audit_signed_append_chain_verifies_ok() {
        let (log, dir, master_priv) = make_signed_log("signed-ok");
        let crux_id = log.crux_id.clone();

        log_node_added(&log, &crux_id, "@auth", None);
        log_node_added(&log, &crux_id, "@login", None);
        log_node_updated(&log, &crux_id, "@auth", &["summary"], None);

        let events = log.read_all();
        assert_eq!(events.len(), 3);
        // All events carry a signature
        assert!(!events[0].signature.is_empty(), "seq1 must have signature");
        assert!(!events[0].pubkey_hash.is_empty(), "seq1 must have pubkey_hash");

        // verify_chain with the correct key
        let n = log.verify_chain(&|id| {
            if id == crux_id { Some(master_priv.clone()) } else { None }
        }).unwrap();
        assert_eq!(n, 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_unsigned_events_pass_verify_without_key() {
        let (log, dir) = temp_log_with_id("unsigned-vc");
        log_node_added(&log, "crux-u", "@x", None);
        log_node_added(&log, "crux-u", "@y", None);

        let events = log.read_all();
        assert!(events[0].signature.is_empty(), "unsigned log must have no sig");

        let n = log.verify_chain(&|_| None).unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_chain_detects_bad_signature() {
        let (log, dir, master_priv) = make_signed_log("bad-sig");
        let crux_id = log.crux_id.clone();
        log_node_added(&log, &crux_id, "@fn", None);

        // Tamper with the signature: find the "signature":"<hex>" field and
        // flip the first byte of the hex value (XOR first two chars with "ff").
        let content = std::fs::read_to_string(&log.path).unwrap();
        let sig_key = "\"signature\":\"";
        let tampered = if let Some(sig_pos) = content.find(sig_key) {
            let val_start = sig_pos + sig_key.len();
            // Replace first 2 hex chars (one byte) with "ff" (unless it's already "ff" → use "00")
            let first_byte = &content[val_start..val_start + 2];
            let replacement = if first_byte == "ff" { "00" } else { "ff" };
            format!("{}{}{}", &content[..val_start], replacement, &content[val_start + 2..])
        } else {
            panic!("no signature field found in audit log — test setup error");
        };
        std::fs::write(&log.path, tampered).unwrap();

        let err = log.verify_chain(&|id| {
            if id == crux_id { Some(master_priv.clone()) } else { None }
        }).unwrap_err();
        assert_eq!(err.kind, ChainErrorKind::BadSignature, "expected BadSignature, got {:?}", err.kind);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_chain_missing_key_returns_error() {
        let (log, dir, _master_priv) = make_signed_log("missing-key");
        let crux_id = log.crux_id.clone();
        log_node_added(&log, &crux_id, "@secret", None);

        // Resolver returns None → MissingKey
        let err = log.verify_chain(&|_| None).unwrap_err();
        assert_eq!(err.kind, ChainErrorKind::MissingKey);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_pubkey_hash_populated_on_signed_append() {
        let (log, dir, master_priv) = make_signed_log("pkh");
        let crux_id = log.crux_id.clone();
        log_node_added(&log, &crux_id, "@node", None);

        let events = log.read_all();
        assert_eq!(events.len(), 1);
        assert!(events[0].pubkey_hash.starts_with("sha256:"), "pubkey_hash must be sha256:...");

        // The pubkey_hash matches the actual subkey_pub
        let subkey = crate::crypto::derive_subkey(&master_priv, 1);
        let subkey_pub = crate::crypto::wots_pubkey_from_privkey(&subkey);
        let expected = format!("sha256:{}", crate::crypto::sha256_hex(&subkey_pub));
        assert_eq!(events[0].pubkey_hash, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
