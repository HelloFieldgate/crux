//! Encrypted on-disk token store for OAuth 2.1 token sets.
//!
//! Tokens are encrypted with AEAD (ChaCha20 + HMAC-SHA256) using a
//! machine-derived key. Files live in `~/.crux-tokens/<alias>.tok` as
//! hex-encoded ciphertext.
//!
//! Security invariant: tokens/secrets never enter the policy crux; only
//! this encrypted store.

use std::path::PathBuf;

use crate::crypto::{aead_decrypt, aead_encrypt, bytes_to_hex, hex_to_bytes, machine_key, sha256};
use crate::json::{extract_string_value, extract_u64_value, is_null_value, json_escape, json_opt_str, json_opt_u64};

// ===========================================================================
// TokenSet
// ===========================================================================

/// OAuth 2.1 tokens for a registered MCP server alias.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp when `access_token` expires. `None` if unknown.
    pub expires_at: Option<u64>,
    pub scope: Option<String>,
    pub token_type: String,
}

impl TokenSet {
    fn to_json(&self) -> String {
        format!(
            "{{\"access_token\":{},\"refresh_token\":{},\"expires_at\":{},\"scope\":{},\"token_type\":{}}}",
            json_escape(&self.access_token),
            json_opt_str(&self.refresh_token),
            json_opt_u64(&self.expires_at),
            json_opt_str(&self.scope),
            json_escape(&self.token_type),
        )
    }

    fn from_json(json: &str) -> Result<Self, String> {
        let access_token = extract_string_value(json, "access_token")
            .ok_or_else(|| "missing access_token in token file".to_string())?;
        let refresh_token = if is_null_value(json, "refresh_token") {
            None
        } else {
            extract_string_value(json, "refresh_token")
        };
        let expires_at = if is_null_value(json, "expires_at") {
            None
        } else {
            extract_u64_value(json, "expires_at")
        };
        let scope = if is_null_value(json, "scope") {
            None
        } else {
            extract_string_value(json, "scope")
        };
        let token_type = extract_string_value(json, "token_type")
            .unwrap_or_else(|| "Bearer".to_string());
        Ok(TokenSet { access_token, refresh_token, expires_at, scope, token_type })
    }
}

// ===========================================================================
// Path helpers
// ===========================================================================

fn token_store_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|h| PathBuf::from(h).join(".crux-tokens"))
}

fn token_path(alias: &str) -> Option<PathBuf> {
    // Use sha256 of the alias as the filename to prevent collisions between aliases
    // that differ only in characters that would otherwise map to the same safe string
    // (e.g. "corp/api" and "corp@api" must not share a token file).
    let hash = bytes_to_hex(&sha256(alias.as_bytes()));
    token_store_dir().map(|d| d.join(format!("{hash}.tok")))
}

fn ensure_token_dir(dir: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("cannot create token dir {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot chmod token dir: {e}"))?;
    }
    Ok(())
}

// ===========================================================================
// Public API
// ===========================================================================

/// Encrypt and persist a `TokenSet` for `alias` to `~/.crux-tokens/<alias>.tok`.
pub fn save(alias: &str, tokens: &TokenSet) -> Result<(), String> {
    use std::io::Write;
    let path = token_path(alias).ok_or("cannot determine home directory")?;
    let dir = path.parent().ok_or("token path has no parent")?;
    ensure_token_dir(dir)?;
    let key = machine_key();
    let json = tokens.to_json();
    let encrypted = aead_encrypt(&key, json.as_bytes());
    let hex = bytes_to_hex(&encrypted);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("cannot open token file {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot chmod token file: {e}"))?;
    }
    f.write_all(hex.as_bytes())
        .map_err(|e| format!("cannot write token file {}: {e}", path.display()))
}

/// Load and decrypt the `TokenSet` for `alias` from `~/.crux-tokens/<alias>.tok`.
pub fn load(alias: &str) -> Result<TokenSet, String> {
    let path = token_path(alias).ok_or("cannot determine home directory")?;
    let hex = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read token file {}: {e}", path.display()))?;
    let key = machine_key();
    let encrypted = hex_to_bytes(hex.trim())?;
    let json_bytes = aead_decrypt(&key, &encrypted)?;
    let json = String::from_utf8(json_bytes)
        .map_err(|e| format!("token file not valid UTF-8: {e}"))?;
    TokenSet::from_json(&json)
}

/// Delete the token file for `alias`. No-ops if the file does not exist.
pub fn delete(alias: &str) -> Result<(), String> {
    let path = token_path(alias).ok_or("cannot determine home directory")?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot delete token file {}: {e}", path.display())),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenset_json_roundtrip_full() {
        let t = TokenSet {
            access_token: "acc_abc123".to_string(),
            refresh_token: Some("ref_xyz456".to_string()),
            expires_at: Some(9_999_999_999),
            scope: Some("read write".to_string()),
            token_type: "Bearer".to_string(),
        };
        let json = t.to_json();
        let recovered = TokenSet::from_json(&json).unwrap();
        assert_eq!(recovered, t);
    }

    #[test]
    fn tokenset_json_roundtrip_minimal() {
        let t = TokenSet {
            access_token: "tok".to_string(),
            refresh_token: None,
            expires_at: None,
            scope: None,
            token_type: "Bearer".to_string(),
        };
        let json = t.to_json();
        let recovered = TokenSet::from_json(&json).unwrap();
        assert_eq!(recovered, t);
    }

    #[test]
    fn tokenset_json_escapes_special_chars() {
        let t = TokenSet {
            access_token: "tok\"with\\quotes\nand\nnewlines".to_string(),
            refresh_token: None,
            expires_at: None,
            scope: None,
            token_type: "Bearer".to_string(),
        };
        let json = t.to_json();
        let recovered = TokenSet::from_json(&json).unwrap();
        assert_eq!(recovered.access_token, t.access_token);
    }

    #[test]
    #[cfg(unix)]
    fn token_store_save_load_delete() {
        use std::os::unix::fs::PermissionsExt;
        let alias = "crux-test-phase2-oauth";
        let tokens = TokenSet {
            access_token: "access_abc".to_string(),
            refresh_token: Some("refresh_xyz".to_string()),
            expires_at: Some(1_234_567_890),
            scope: Some("read write".to_string()),
            token_type: "Bearer".to_string(),
        };

        // Clean up any leftover from a previous run
        let _ = delete(alias);

        save(alias, &tokens).expect("save should succeed");

        // Verify file permissions
        if let Some(path) = token_path(alias) {
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let loaded = load(alias).expect("load should succeed");
        assert_eq!(loaded, tokens);

        delete(alias).expect("delete should succeed");
        assert!(load(alias).is_err(), "load after delete must fail");
    }

    #[test]
    fn token_store_delete_nonexistent_is_ok() {
        assert!(delete("crux-nonexistent-alias-zzzzzzz").is_ok());
    }
}
