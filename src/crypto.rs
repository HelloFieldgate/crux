//! Cryptographic primitives: SHA-256 (FIPS 180-4) and W-OTS key generation.
//!
//! Pure Rust, zero external dependencies.
//!
//! Dead code removed in H-8: hmac_sha256, sign_message, verify_signature,
//! hash_file, wots_sign_raw, wots_verify_raw, wots_message_nibbles,
//! bytes_to_chains. LML rewrites exist in src/lml/crypto.lml.
//! Originals preserved in legacy/retired/crypto_full.rs.

// ===========================================================================
// SHA-256
// ===========================================================================

/// Initial hash values: first 32 bits of fractional parts of sqrt(first 8 primes).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants: first 32 bits of fractional parts of cbrt(first 64 primes).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn ch(e: u32, f: u32, g: u32) -> u32 { (e & f) ^ (!e & g) }

#[inline(always)]
fn maj(a: u32, b: u32, c: u32) -> u32 { (a & b) ^ (a & c) ^ (b & c) }

#[inline(always)]
fn big_sigma0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }

#[inline(always)]
fn big_sigma1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }

#[inline(always)]
fn small_sigma0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }

#[inline(always)]
fn small_sigma1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i*4], block[i*4+1], block[i*4+2], block[i*4+3]]);
    }
    for i in 16..64 {
        w[i] = small_sigma1(w[i-2]).wrapping_add(w[i-7])
            .wrapping_add(small_sigma0(w[i-15])).wrapping_add(w[i-16]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let t1 = h.wrapping_add(big_sigma1(e)).wrapping_add(ch(e, f, g))
            .wrapping_add(K[i]).wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Compute the SHA-256 hash of `data`. Returns 32 bytes.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut state = H_INIT;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        compress(&mut state, chunk.try_into().unwrap());
    }
    let mut out = Vec::with_capacity(32);
    for w in &state {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out
}

/// Compute SHA-256 and return as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    let mut hex = String::with_capacity(64);
    for byte in &hash {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

// ===========================================================================
// W-OTS Key Generation (quantum-resistant)
//
// Parameters: w=16 (4-bit chunks), SHA-256, n=32 bytes, 67 chains.
// Only keygen is kept in Rust — sign/verify use the LML rewrite (crypto.lml).
// ===========================================================================

const WOTS_W: usize = 16;
const WOTS_CHAINS: usize = 67;
const WOTS_N: usize = 32;

/// A W-OTS public/private key pair for quantum-resistant signatures.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

struct WotsPrivateKey([[u8; WOTS_N]; WOTS_CHAINS]);
struct WotsPublicKey([[u8; WOTS_N]; WOTS_CHAINS]);

fn wots_chain(value: &[u8; WOTS_N], steps: usize) -> [u8; WOTS_N] {
    let mut cur = *value;
    for _ in 0..steps {
        let h = sha256(&cur);
        cur.copy_from_slice(&h);
    }
    cur
}

/// Read cryptographically random bytes from /dev/urandom.
pub fn secure_random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut buf = vec![0u8; n];
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let cnt = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&ts.to_le_bytes());
    seed.extend_from_slice(&cnt.to_le_bytes());
    let mut out = Vec::with_capacity(n);
    let mut state = sha256(&seed);
    while out.len() < n {
        out.extend_from_slice(&state);
        state = sha256(&state);
    }
    out.truncate(n);
    out
}

fn wots_keygen() -> (WotsPrivateKey, WotsPublicKey) {
    let raw = secure_random_bytes(WOTS_CHAINS * WOTS_N);
    let mut priv_chains = [[0u8; WOTS_N]; WOTS_CHAINS];
    let mut pub_chains  = [[0u8; WOTS_N]; WOTS_CHAINS];
    for i in 0..WOTS_CHAINS {
        priv_chains[i].copy_from_slice(&raw[i * WOTS_N..(i + 1) * WOTS_N]);
        pub_chains[i] = wots_chain(&priv_chains[i], WOTS_W - 1);
    }
    (WotsPrivateKey(priv_chains), WotsPublicKey(pub_chains))
}

fn chains_to_bytes(chains: &[[u8; WOTS_N]; WOTS_CHAINS]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WOTS_CHAINS * WOTS_N);
    for chain in chains {
        out.extend_from_slice(chain);
    }
    out
}

/// Generate a new W-OTS key pair for quantum-resistant signatures.
pub fn generate_keypair() -> KeyPair {
    let (priv_key, pub_key) = wots_keygen();
    KeyPair {
        private_key: chains_to_bytes(&priv_key.0),
        public_key:  chains_to_bytes(&pub_key.0),
    }
}

/// Split `WOTS_CHAINS * WOTS_N` bytes into an array of 67 chains.
pub fn bytes_to_chains(bytes: &[u8]) -> [[u8; WOTS_N]; WOTS_CHAINS] {
    let mut chains = [[0u8; WOTS_N]; WOTS_CHAINS];
    for i in 0..WOTS_CHAINS {
        chains[i].copy_from_slice(&bytes[i * WOTS_N..(i + 1) * WOTS_N]);
    }
    chains
}

/// Extract 67 message nibbles from a 32-byte hash (64 data + 3 checksum).
///
/// W-OTS with w=16: each byte yields two 4-bit nibbles; the checksum
/// = Σ(15 − ni) for the 64 data nibbles is encoded as 3 more nibbles.
pub fn wots_message_nibbles(hash: &[u8; WOTS_N]) -> [usize; WOTS_CHAINS] {
    let mut nibbles = [0usize; WOTS_CHAINS];
    for i in 0..32 {
        nibbles[2 * i]     = ((hash[i] >> 4) & 0xF) as usize;
        nibbles[2 * i + 1] = (hash[i] & 0xF) as usize;
    }
    let checksum: usize = nibbles[..64].iter().map(|&ni| WOTS_W - 1 - ni).sum();
    nibbles[64] = (checksum >> 8) & 0xF;
    nibbles[65] = (checksum >> 4) & 0xF;
    nibbles[66] = checksum & 0xF;
    nibbles
}

/// Sign a 32-byte hash with a W-OTS private key.
///
/// `priv_key` must be exactly `WOTS_CHAINS * WOTS_N` bytes as returned by
/// `generate_keypair`. Returns a signature of the same length.
pub fn wots_sign_raw(priv_key: &[u8], hash: &[u8; WOTS_N]) -> Vec<u8> {
    let chains = bytes_to_chains(priv_key);
    let nibbles = wots_message_nibbles(hash);
    let mut sig = Vec::with_capacity(WOTS_CHAINS * WOTS_N);
    for i in 0..WOTS_CHAINS {
        sig.extend_from_slice(&wots_chain(&chains[i], nibbles[i]));
    }
    sig
}

/// Verify a W-OTS raw signature against a public key and hash.
///
/// Returns `true` only if `signature` was produced by the private key
/// corresponding to `pub_key` over `hash`.
pub fn wots_verify_raw(pub_key: &[u8], hash: &[u8; WOTS_N], signature: &[u8]) -> bool {
    if signature.len() != WOTS_CHAINS * WOTS_N || pub_key.len() != WOTS_CHAINS * WOTS_N {
        return false;
    }
    let pub_chains = bytes_to_chains(pub_key);
    let sig_chains = bytes_to_chains(signature);
    let nibbles = wots_message_nibbles(hash);
    for i in 0..WOTS_CHAINS {
        let steps = WOTS_W - 1 - nibbles[i];
        if wots_chain(&sig_chains[i], steps) != pub_chains[i] {
            return false;
        }
    }
    true
}

/// Sign an arbitrary message (SHA-256 is computed internally).
pub fn sign_message(priv_key: &[u8], message: &[u8]) -> Vec<u8> {
    let hash_vec = sha256(message);
    let hash: [u8; WOTS_N] = hash_vec.try_into().expect("sha256 returns 32 bytes");
    wots_sign_raw(priv_key, &hash)
}

/// Verify a message signature produced by `sign_message`.
pub fn verify_signature(pub_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let hash_vec = sha256(message);
    match hash_vec.try_into() {
        Ok(hash) => wots_verify_raw(pub_key, &hash, signature),
        Err(_) => false,
    }
}

/// Get current Unix timestamp.
pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ===========================================================================
// Subkey derivation
// ===========================================================================

/// Derive a one-time W-OTS subkey from a master private key and a sequence number.
///
/// Produces a 2048-byte private key (WOTS_CHAINS × WOTS_N) that can be used
/// with `wots_sign_raw` exactly once. Each `seq` value yields an independent
/// subkey; knowing one subkey does not reveal the master or other subkeys.
///
/// Algorithm: `seed = sha256(master_priv || seq.to_be_bytes())`; then
/// `subkey[i*32..(i+1)*32] = sha256(seed || i.to_le_bytes())` for i in 0..WOTS_CHAINS.
pub fn derive_subkey(master_priv: &[u8], seq: u64) -> Vec<u8> {
    // 32-byte seed unique to this seq
    let mut seed_input = Vec::with_capacity(master_priv.len() + 8);
    seed_input.extend_from_slice(master_priv);
    seed_input.extend_from_slice(&seq.to_be_bytes());
    let seed = sha256(&seed_input);

    // Expand seed to WOTS_CHAINS chains of WOTS_N bytes each
    let mut subkey = Vec::with_capacity(WOTS_CHAINS * WOTS_N);
    for i in 0u32..WOTS_CHAINS as u32 {
        let mut chain_input = Vec::with_capacity(WOTS_N + 4);
        chain_input.extend_from_slice(&seed);
        chain_input.extend_from_slice(&i.to_le_bytes());
        subkey.extend_from_slice(&sha256(&chain_input));
    }
    subkey
}

// ===========================================================================
// Key persistence
// ===========================================================================

/// Return the path to the crux keys directory: `$HOME/.crux-keys/`.
pub fn crux_keys_dir() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".crux-keys"))
}

/// Write a W-OTS private key for `mesh_id` to `~/.crux-keys/<mesh_id>.priv`.
///
/// The file is hex-encoded. Directory is created with mode 0o700, file
/// with mode 0o600 (Unix). Returns `Ok(())` on success; silently no-ops if
/// the home directory cannot be determined.
pub fn write_crux_key(mesh_id: &str, private_key_bytes: &[u8]) -> Result<(), String> {
    use std::fs;
    use std::io::Write;

    let dir = match crux_keys_dir() {
        Some(d) => d,
        None => return Ok(()),   // no home dir — skip silently
    };
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Cannot create keys dir {}: {e}", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot chmod keys dir: {e}"))?;
    }

    let safe_id = mesh_id.replace('/', "-").replace(':', "_");
    let key_path = dir.join(format!("{safe_id}.priv"));
    let hex = sha256_hex(private_key_bytes); // use hex encoding via bytes_to_hex
    // sha256_hex only returns 64 chars; we need the full private key hex
    let mut full_hex = String::with_capacity(private_key_bytes.len() * 2);
    for b in private_key_bytes {
        full_hex.push_str(&format!("{b:02x}"));
    }

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&key_path)
        .map_err(|e| format!("Cannot open key file {}: {e}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Cannot chmod key file: {e}"))?;
    }

    f.write_all(full_hex.as_bytes())
        .map_err(|e| format!("Cannot write key file: {e}"))?;

    let _ = hex; // suppress unused warning
    Ok(())
}

/// Read and hex-decode the private key for `mesh_id` from `~/.crux-keys/<mesh_id>.priv`.
pub fn read_crux_key(mesh_id: &str) -> Result<Vec<u8>, String> {
    let dir = crux_keys_dir()
        .ok_or_else(|| "Cannot determine home directory for key lookup".to_string())?;
    let safe_id = mesh_id.replace('/', "-").replace(':', "_");
    let key_path = dir.join(format!("{safe_id}.priv"));
    let hex = std::fs::read_to_string(&key_path)
        .map_err(|e| format!("Cannot read key file {}: {e}", key_path.display()))?;
    let trimmed = hex.trim();
    (0..trimmed.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&trimmed[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex in key file: {e}"))
        })
        .collect()
}

/// Derive the W-OTS public key from a private key by running each chain WOTS_W-1 steps.
pub fn wots_pubkey_from_privkey(priv_key: &[u8]) -> Vec<u8> {
    let chains = bytes_to_chains(priv_key);
    let mut pub_key = Vec::with_capacity(WOTS_CHAINS * WOTS_N);
    for i in 0..WOTS_CHAINS {
        pub_key.extend_from_slice(&wots_chain(&chains[i], WOTS_W - 1));
    }
    pub_key
}

/// Encode a byte slice as a lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode a hex string into bytes. Returns Err on invalid input.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at {i}: {e}")))
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256_hex(b"abc");
        assert_eq!(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_sha256_long() {
        let hash = sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hash, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn test_secure_random_bytes_length() {
        let r = secure_random_bytes(64);
        assert_eq!(r.len(), 64);
    }

    #[test]
    fn test_secure_random_bytes_uniqueness() {
        let a = secure_random_bytes(32);
        let b = secure_random_bytes(32);
        assert_ne!(a, b, "two random draws should not be equal");
    }

    #[test]
    fn test_wots_chain_deterministic() {
        let val = [0xabu8; WOTS_N];
        let c1 = wots_chain(&val, 3);
        let c2 = wots_chain(&val, 3);
        assert_eq!(c1, c2);
        assert_ne!(c1, val);
    }

    #[test]
    fn test_generate_keypair_sizes() {
        let kp = generate_keypair();
        assert_eq!(kp.private_key.len(), WOTS_CHAINS * WOTS_N);
        assert_eq!(kp.public_key.len(), WOTS_CHAINS * WOTS_N);
    }

    #[test]
    fn test_wots_sign_verify_roundtrip() {
        let kp = generate_keypair();
        let msg = b"hello, crux mesh";
        let sig = sign_message(&kp.private_key, msg);
        assert_eq!(sig.len(), WOTS_CHAINS * WOTS_N);
        assert!(verify_signature(&kp.public_key, msg, &sig));
    }

    #[test]
    fn test_wots_verify_wrong_message() {
        let kp = generate_keypair();
        let sig = sign_message(&kp.private_key, b"correct");
        assert!(!verify_signature(&kp.public_key, b"wrong", &sig));
    }

    #[test]
    fn test_wots_verify_wrong_key() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let sig = sign_message(&kp1.private_key, b"message");
        assert!(!verify_signature(&kp2.public_key, b"message", &sig));
    }

    #[test]
    fn test_wots_message_nibbles_checksum() {
        let hash = [0u8; WOTS_N];
        let nibbles = wots_message_nibbles(&hash);
        // All data nibbles are 0 → checksum = 64 * 15 = 960
        let cs = nibbles[64] * 256 + nibbles[65] * 16 + nibbles[66];
        assert_eq!(cs, 960);
    }

    #[test]
    fn test_sign_message_deterministic_for_same_key() {
        let kp = generate_keypair();
        let sig1 = sign_message(&kp.private_key, b"test");
        let sig2 = sign_message(&kp.private_key, b"test");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn derive_subkey_deterministic() {
        let master = secure_random_bytes(WOTS_CHAINS * WOTS_N);
        let sk1 = derive_subkey(&master, 42);
        let sk2 = derive_subkey(&master, 42);
        assert_eq!(sk1, sk2);
        assert_eq!(sk1.len(), WOTS_CHAINS * WOTS_N);

        // Different seq → different subkey
        let sk3 = derive_subkey(&master, 43);
        assert_ne!(sk1, sk3);

        // Derived subkey signs+verifies via standard WOTS path
        let sub_kp = KeyPair {
            private_key: sk1.clone(),
            public_key: {
                let mut pub_key = Vec::with_capacity(WOTS_CHAINS * WOTS_N);
                for chunk in sk1.chunks(WOTS_N) {
                    let c: [u8; WOTS_N] = chunk.try_into().unwrap();
                    pub_key.extend_from_slice(&wots_chain(&c, 15));
                }
                pub_key
            },
        };
        let sig = sign_message(&sub_kp.private_key, b"test");
        assert!(verify_signature(&sub_kp.public_key, b"test", &sig));
    }

    #[test]
    #[cfg(unix)]
    fn write_and_read_crux_key_roundtrip() {
        use std::os::unix::fs::PermissionsExt;
        let key = secure_random_bytes(WOTS_CHAINS * WOTS_N);
        let mesh_id = format!("sha256:test_{}", sha256_hex(b"key_test"));
        write_crux_key(&mesh_id, &key).unwrap();
        let recovered = read_crux_key(&mesh_id).unwrap();
        assert_eq!(key, recovered);

        // Verify file mode is 0o600
        if let Some(dir) = crux_keys_dir() {
            let safe_id = mesh_id.replace('/', "-").replace(':', "_");
            let key_path = dir.join(format!("{safe_id}.priv"));
            let meta = std::fs::metadata(&key_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file should have mode 0o600, got {:o}", mode);
        }
    }
}
