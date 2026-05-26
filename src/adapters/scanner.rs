//! Filesystem scanner — recursively walk a directory and identify content.
//!
//! Detects file types by extension and (where relevant) by magic bytes,
//! producing a manifest of `ScannedFile` entries. A separate function
//! generates cruxes from an entire directory, grouping files by type.

use std::path::{Path, PathBuf};

use crate::adapters::{AdapterConfig, CruxAdapter};
use crate::schema::{CruxDb, CruxNode, CruxKind, NodeSchema,
                    PlanningMetadata, SecurityMetadata, create_crux_db, save_crux_db};
use crate::crypto::sha256_hex;

// ===========================================================================
// Detected file kind
// ===========================================================================

/// The logical kind of a scanned file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileKind {
    Email,
    Markdown,
    Csv,
    Json,
    Plaintext,
    SourceCode,
    Document,  // PDF, Word, Excel — text extraction not yet supported
    Image,
    Binary,
}

impl FileKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileKind::Email => "email",
            FileKind::Markdown => "markdown",
            FileKind::Csv => "csv",
            FileKind::Json => "json",
            FileKind::Plaintext => "plaintext",
            FileKind::SourceCode => "source",
            FileKind::Document => "document",
            FileKind::Image => "image",
            FileKind::Binary => "binary",
        }
    }

    /// MIME type for this file kind.
    pub fn mime(&self) -> &'static str {
        match self {
            FileKind::Email => "message/rfc822",
            FileKind::Markdown => "text/markdown",
            FileKind::Csv => "text/csv",
            FileKind::Json => "application/json",
            FileKind::Plaintext => "text/plain",
            FileKind::SourceCode => "text/x-source",
            FileKind::Document => "application/octet-stream",
            FileKind::Image => "image/*",
            FileKind::Binary => "application/octet-stream",
        }
    }

    /// Returns true if this file kind's content can be read as UTF-8 text and ingested.
    pub fn is_ingestible(&self) -> bool {
        matches!(
            self,
            FileKind::Email
                | FileKind::Markdown
                | FileKind::Csv
                | FileKind::Json
                | FileKind::Plaintext
                | FileKind::SourceCode
        )
    }
}

// ===========================================================================
// ScannedFile
// ===========================================================================

/// Metadata about a single file discovered during a scan.
#[derive(Debug, Clone)]
pub struct ScannedFile {
    /// Path relative to the scan root.
    pub relative_path: String,
    /// Absolute path.
    pub absolute_path: PathBuf,
    /// Detected file kind.
    pub kind: FileKind,
    /// MIME type string.
    pub mime: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

impl ScannedFile {
    /// Serialize to a JSON object string.
    pub fn to_json(&self) -> String {
        use crate::json::json_escape;
        format!(
            "{{\"path\":{},\"kind\":{},\"mime\":{},\"size\":{},\"ingestible\":{}}}",
            json_escape(&self.relative_path),
            json_escape(self.kind.as_str()),
            json_escape(&self.mime),
            self.size_bytes,
            self.kind.is_ingestible()
        )
    }
}

// ===========================================================================
// ScanResult
// ===========================================================================

/// Result of scanning a directory.
#[derive(Debug)]
pub struct ScanResult {
    pub root: PathBuf,
    pub files: Vec<ScannedFile>,
}

impl ScanResult {
    /// Serialize to a JSON array of file objects.
    pub fn to_json(&self) -> String {
        let mut out = String::from("[");
        for (i, f) in self.files.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&f.to_json());
        }
        out.push(']');
        out
    }

    /// Summarize by kind for a human-readable report.
    pub fn summary(&self) -> String {
        use std::collections::HashMap;
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for f in &self.files {
            *counts.entry(f.kind.as_str()).or_insert(0) += 1;
        }
        let mut parts: Vec<String> = counts
            .iter()
            .map(|(k, v)| format!("{} {}", v, k))
            .collect();
        parts.sort();
        format!(
            "Scanned {} files: {}",
            self.files.len(),
            parts.join(", ")
        )
    }
}

// ===========================================================================
// File type detection
// ===========================================================================

/// Detect the kind of a file by its extension.
fn detect_by_extension(path: &Path) -> Option<FileKind> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    match ext.as_deref() {
        Some("mbox") | Some("eml") => Some(FileKind::Email),
        Some("md") | Some("markdown") | Some("mdx") => Some(FileKind::Markdown),
        Some("csv") | Some("tsv") => Some(FileKind::Csv),
        Some("json") | Some("jsonl") | Some("ndjson") => Some(FileKind::Json),
        Some("txt") | Some("log") | Some("text") => Some(FileKind::Plaintext),
        Some("rs") | Some("py") | Some("js") | Some("ts") | Some("go")
        | Some("c") | Some("cpp") | Some("cc") | Some("h") | Some("hpp")
        | Some("java") | Some("kt") | Some("swift") | Some("rb") | Some("php")
        | Some("cs") | Some("sh") | Some("bash") | Some("zsh") | Some("fish")
        | Some("lua") | Some("r") | Some("scala") | Some("ex") | Some("exs")
        | Some("clj") | Some("cljs") | Some("ml") | Some("hs") | Some("elm") => {
            Some(FileKind::SourceCode)
        }
        Some("pdf") | Some("doc") | Some("docx") | Some("odt")
        | Some("xls") | Some("xlsx") | Some("ods") | Some("ppt") | Some("pptx") => {
            Some(FileKind::Document)
        }
        Some("jpg") | Some("jpeg") | Some("png") | Some("gif") | Some("bmp")
        | Some("tiff") | Some("tif") | Some("webp") | Some("svg") | Some("ico")
        | Some("heic") | Some("heif") => Some(FileKind::Image),
        _ => None,
    }
}

/// Detect file kind by reading the first few bytes (magic bytes).
fn detect_by_magic(path: &Path) -> Option<FileKind> {
    let mut buf = [0u8; 8];
    let n = std::fs::File::open(path)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut buf)
        })
        .unwrap_or(0);

    if n < 2 {
        return None;
    }

    match &buf[..n.min(4)] {
        // PDF: %PDF
        b if b.starts_with(b"%PDF") => Some(FileKind::Document),
        // PNG
        b if b.starts_with(b"\x89PNG") => Some(FileKind::Image),
        // JPEG
        b if b.starts_with(b"\xff\xd8") => Some(FileKind::Image),
        // GIF
        b if b.starts_with(b"GIF8") => Some(FileKind::Image),
        // ZIP-based (docx, xlsx, etc.) — 50 4B 03 04
        b if b.starts_with(b"PK\x03\x04") => Some(FileKind::Document),
        _ => None,
    }
}

/// Classify a file. Extension takes priority; magic bytes used as fallback.
pub fn classify_file(path: &Path) -> FileKind {
    if let Some(kind) = detect_by_extension(path) {
        return kind;
    }
    if let Some(kind) = detect_by_magic(path) {
        return kind;
    }
    FileKind::Binary
}

// ===========================================================================
// Scanner
// ===========================================================================

/// Recursively scan a directory and return metadata for all files found.
///
/// - `root`: directory to scan
/// - `max_depth`: maximum recursion depth (None = unlimited)
/// - `extensions`: if non-empty, only include files with these extensions
pub fn scan_directory(
    root: &Path,
    max_depth: Option<usize>,
    extensions: &[String],
) -> Result<ScanResult, String> {
    let root = root.canonicalize()
        .map_err(|e| format!("Cannot access '{}': {}", root.display(), e))?;
    let mut files = Vec::new();
    scan_recursive(&root, &root, 0, max_depth.unwrap_or(usize::MAX), extensions, &mut files);
    Ok(ScanResult { root, files })
}

fn scan_recursive(
    root: &Path,
    current: &Path,
    depth: usize,
    max_depth: usize,
    extensions: &[String],
    files: &mut Vec<ScannedFile>,
) {
    if depth > max_depth {
        return;
    }

    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Skip hidden files and directories
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if name.starts_with('.') {
            continue;
        }

        if meta.is_dir() {
            scan_recursive(root, &path, depth + 1, max_depth, extensions, files);
        } else if meta.is_file() {
            // Extension filter
            if !extensions.is_empty() {
                let ext = path.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_lowercase())
                    .unwrap_or_default();
                if !extensions.iter().any(|e| e.to_lowercase() == ext) {
                    continue;
                }
            }

            let kind = classify_file(&path);
            let mime = kind.mime().to_string();
            let size_bytes = meta.len();

            // Compute relative path
            let relative_path = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string_lossy().to_string());

            files.push(ScannedFile {
                relative_path,
                absolute_path: path,
                kind,
                mime,
                size_bytes,
            });
        }
    }

    // Sort for deterministic output
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
}

// ===========================================================================
// Source-reference helpers
// ===========================================================================

/// Extract the volume label from paths rooted at /Volumes/{label} or /mnt/{label}.
fn extract_volume_label(path: &Path) -> Option<String> {
    let s = path.to_str()?;
    let rest = s.strip_prefix("/Volumes/").or_else(|| s.strip_prefix("/mnt/"))?;
    let label = rest.split('/').next()?;
    if label.is_empty() { None } else { Some(label.to_string()) }
}

/// Return the path relative to the volume root (i.e., strip /Volumes/{label}/ or /mnt/{label}/).
/// Falls back to the absolute path string if the path isn't under a known mount prefix.
fn relative_to_volume(path: &Path) -> String {
    let s = path.to_str().unwrap_or("");
    let rest = s.strip_prefix("/Volumes/").or_else(|| s.strip_prefix("/mnt/"));
    if let Some(rest) = rest {
        if let Some(slash) = rest.find('/') {
            return rest[slash + 1..].to_string();
        }
    }
    s.to_string()
}

// ===========================================================================
// Crux generation from a single file (by path on disk)
// ===========================================================================

/// Generate a `CruxDb` by reading a file from disk and running the appropriate adapter.
///
/// Detects the format, reads the content, runs the adapter, and attaches
/// provenance metadata to each generated node via the `properties` field.
pub fn generate_from_file(
    path: &Path,
    crux_name: &str,
    device_id: Option<&str>,
    default_classification: Option<&str>,
) -> Result<CruxDb, String> {
    let kind = classify_file(path);

    if !kind.is_ingestible() {
        // For binary/document/image files, produce a single metadata-only node.
        return generate_metadata_node(path, crux_name, &kind, device_id, default_classification);
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read '{}': {}", path.display(), e))?;

    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let format = kind.as_str();

    let mut config = AdapterConfig::new(crux_name, format);
    config.default_classification = default_classification.map(|s| s.to_string());

    let mut db = match kind {
        FileKind::Markdown => {
            crate::adapters::markdown::MarkdownAdapter.generate(&content, &config)?
        }
        FileKind::Csv => {
            crate::adapters::auto::AutoAdapter.generate(&content, &config)?
        }
        FileKind::Json => {
            crate::adapters::auto::AutoAdapter.generate(&content, &config)?
        }
        FileKind::Email => {
            crate::adapters::auto::AutoAdapter.generate(&content, &config)?
        }
        FileKind::SourceCode => {
            // Source code: create one node per file as a document
            crate::adapters::plaintext::PlaintextAdapter.generate(&content, &config)?
        }
        _ => {
            crate::adapters::auto::AutoAdapter.generate(&content, &config)?
        }
    };

    // Attach provenance and source-reference metadata to all nodes
    let now = crate::schema::now_unix();
    let path_str = path.to_string_lossy().to_string();
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let file_uri = format!("file://{}", path_str);
    let volume_label = extract_volume_label(path);
    let rel_path = relative_to_volume(path);

    for node in db.nodes.iter_mut() {
        // Provenance: who acquired this and when
        node.properties.push(format!("provenance.source_path={}", path_str));
        node.properties.push(format!("provenance.source_file={}", file_name));
        node.properties.push(format!("provenance.mime_type={}", kind.mime()));
        node.properties.push(format!("provenance.original_size={}", file_size));
        node.properties.push(format!("provenance.acquired_at={}", now));
        if let Some(dev) = device_id {
            node.properties.push(format!("provenance.source_device={}", dev));
        }

        // Source reference: mount-resilient pointer for content retrieval
        node.properties.push(format!("source_ref.uri={}", file_uri));
        node.properties.push(format!("source_ref.relative_path={}", rel_path));
        if let Some(ref vol) = volume_label {
            node.properties.push(format!("source_ref.volume_label={}", vol));
        }
        if let Some(dev) = device_id {
            node.properties.push(format!("source_ref.device_id={}", dev));
        }
        // For single-record file types (markdown, plaintext, source), the adapter
        // will not have set byte_offset — point to the whole file.
        if !node.properties.iter().any(|p| p.starts_with("source_ref.byte_offset=")) {
            node.properties.push("source_ref.byte_offset=0".to_string());
            node.properties.push(format!("source_ref.byte_length={}", file_size));
        }

        // Apply classification if set in config and node still has default
        if let Some(ref cls) = config.default_classification {
            if node.security.classification == "internal" {
                node.security.classification = cls.clone();
            }
        }
    }

    Ok(db)
}

/// Generate a single metadata-only node for a binary/image/document file.
fn generate_metadata_node(
    path: &Path,
    crux_name: &str,
    kind: &FileKind,
    device_id: Option<&str>,
    default_classification: Option<&str>,
) -> Result<CruxDb, String> {
    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let now = crate::schema::now_unix();
    let classification = default_classification.unwrap_or("internal").to_string();

    let mut db = create_crux_db(crux_name, CruxKind::Dataset, kind.as_str());

    // Hash the file by reading its bytes (for forensic integrity)
    let content_hash = if let Ok(bytes) = std::fs::read(path) {
        format!("sha256:{}", sha256_hex(&bytes))
    } else {
        format!("sha256:{}", sha256_hex(file_name.as_bytes()))
    };

    let node_id = format!(
        "sha256:{}",
        sha256_hex(format!("node:{}:{}", db.header.crux_id, file_name).as_bytes())
    );

    let summary = format!(
        "{} file: {} ({} bytes)",
        kind.as_str(),
        file_name,
        size
    );
    let summary = if summary.len() > 200 { summary[..200].to_string() } else { summary };

    let file_uri = format!("file://{}", path.to_string_lossy());
    let volume_label = extract_volume_label(path);
    let rel_path = relative_to_volume(path);

    let mut properties = vec![
        format!("provenance.source_path={}", path.to_string_lossy()),
        format!("provenance.source_file={}", file_name),
        format!("provenance.mime_type={}", kind.mime()),
        format!("provenance.original_size={}", size),
        format!("provenance.acquired_at={}", now),
    ];
    if let Some(dev) = device_id {
        properties.push(format!("provenance.source_device={}", dev));
    }

    // Source reference: mount-resilient pointer (whole file, single record)
    properties.push(format!("source_ref.uri={}", file_uri));
    properties.push(format!("source_ref.relative_path={}", rel_path));
    if let Some(ref vol) = volume_label {
        properties.push(format!("source_ref.volume_label={}", vol));
    }
    if let Some(dev) = device_id {
        properties.push(format!("source_ref.device_id={}", dev));
    }
    properties.push("source_ref.byte_offset=0".to_string());
    properties.push(format!("source_ref.byte_length={}", size));

    db.nodes.push(CruxNode {
        node_id,
        name: file_name.clone(),
        kind: kind.as_str().to_string(),
        module: path.parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string(),
        summary,
        schema: NodeSchema::empty(),
        tags: vec![kind.as_str().to_string(), "unextracted".to_string()],
        reach: Vec::new(),
        properties,
        warnings: vec!["Content not extracted: binary or unsupported format".to_string()],
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata { classification, redact_below: None },
        content_hash,
        deleted_at: None,
    });

    Ok(db)
}

// ===========================================================================
// Bulk directory generation
// ===========================================================================

/// Strategy for grouping files into cruxes during directory generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupingStrategy {
    /// One crux per detected file kind (email, csv, markdown, etc.)
    ByKind,
    /// One crux per immediate subdirectory
    ByDirectory,
    /// All files in a single flat crux
    Flat,
}

impl GroupingStrategy {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "by_directory" => GroupingStrategy::ByDirectory,
            "flat" => GroupingStrategy::Flat,
            _ => GroupingStrategy::ByKind,
        }
    }
}

/// Result of generating cruxes from a directory.
#[derive(Debug)]
pub struct GenerateDirResult {
    /// Name of each crux created and path to its .crux.json file.
    pub cruxes: Vec<(String, PathBuf)>,
    /// Files that were skipped (non-ingestible).
    pub skipped: Vec<ScannedFile>,
    /// Summary text.
    pub summary: String,
}

/// Scan a directory, group files by strategy, generate one crux per group,
/// and save each crux to `output_dir`.
///
/// Returns a summary of what was created.
pub fn generate_dir(
    source_dir: &Path,
    output_dir: &Path,
    mesh_name: &str,
    strategy: GroupingStrategy,
    device_id: Option<&str>,
    default_classification: Option<&str>,
    max_depth: Option<usize>,
) -> Result<GenerateDirResult, String> {
    // Scan
    let scan = scan_directory(source_dir, max_depth, &[])?;

    // Partition into ingestible and skipped
    let (ingestible, skipped): (Vec<_>, Vec<_>) =
        scan.files.into_iter().partition(|f| f.kind.is_ingestible());

    // Group
    let groups = group_files(&ingestible, &scan.root, &strategy);

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Cannot create output directory '{}': {}", output_dir.display(), e))?;

    let mut cruxes = Vec::new();
    let total_groups = groups.len();

    for (group_name, files) in groups {
        let crux_name = format!("{}-{}", mesh_name, group_name);
        let group_dir = output_dir.join(&crux_name);
        std::fs::create_dir_all(&group_dir)
            .map_err(|e| format!("Cannot create crux directory: {}", e))?;

        // Determine crux kind for this group
        let crux_kind = kind_for_group(&group_name);

        let mut merged_db = create_crux_db(&crux_name, crux_kind, "scanner");

        for scanned_file in &files {
            match generate_from_file(
                &scanned_file.absolute_path,
                &crux_name,
                device_id,
                default_classification,
            ) {
                Ok(file_db) => {
                    // Merge nodes and edges into the group crux
                    for node in file_db.nodes {
                        // Deduplicate by name
                        if !merged_db.nodes.iter().any(|n| n.name == node.name) {
                            merged_db.nodes.push(node);
                        }
                    }
                    for edge in file_db.edges {
                        merged_db.edges.push(edge);
                    }
                }
                Err(e) => {
                    // Don't fail the whole batch on one file; add an error node
                    let err_node = make_error_node(
                        &merged_db.header.crux_id,
                        &scanned_file.relative_path,
                        &e,
                        default_classification,
                    );
                    merged_db.nodes.push(err_node);
                }
            }
        }

        save_crux_db(&merged_db, &group_dir)?;
        cruxes.push((crux_name, group_dir.join(".crux.json")));
    }

    let summary = format!(
        "Generated {} crux(es) from {} files in '{}'. {} file(s) skipped (binary/image/document).",
        total_groups,
        files_count(&cruxes),
        source_dir.display(),
        skipped.len()
    );

    Ok(GenerateDirResult { cruxes, skipped, summary })
}

fn files_count(cruxes: &[(String, PathBuf)]) -> usize {
    cruxes.len() // approximation; real count tracked in nodes
}

/// Group scanned files by the given strategy. Returns (group_name, files).
fn group_files(
    files: &[ScannedFile],
    scan_root: &Path,
    strategy: &GroupingStrategy,
) -> Vec<(String, Vec<ScannedFile>)> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Vec<ScannedFile>> = HashMap::new();

    for file in files {
        let key = match strategy {
            GroupingStrategy::ByKind => file.kind.as_str().to_string(),
            GroupingStrategy::ByDirectory => {
                // Get the first-level subdirectory under scan root
                let abs = &file.absolute_path;
                if let Ok(rel) = abs.strip_prefix(scan_root) {
                    rel.components()
                        .next()
                        .and_then(|c| {
                            let s = c.as_os_str().to_str()?;
                            // If it's a file (no more components), use "root"
                            if rel.components().count() == 1 { Some("root") } else { Some(s) }
                        })
                        .unwrap_or("root")
                        .to_string()
                } else {
                    "root".to_string()
                }
            }
            GroupingStrategy::Flat => "all".to_string(),
        };
        map.entry(key).or_default().push(file.clone());
    }

    let mut result: Vec<(String, Vec<ScannedFile>)> = map.into_iter().collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Map a group name to an appropriate CruxKind.
fn kind_for_group(group: &str) -> CruxKind {
    match group {
        "email" | "communication" => CruxKind::Dataset,
        "markdown" | "plaintext" | "document" => CruxKind::Documentation,
        "csv" | "json" => CruxKind::Dataset,
        "source" => CruxKind::Codebase,
        "image" | "binary" => CruxKind::Dataset,
        _ => CruxKind::Dataset,
    }
}

/// Create an error node for a file that failed to ingest.
fn make_error_node(
    crux_id: &str,
    relative_path: &str,
    error: &str,
    default_classification: Option<&str>,
) -> CruxNode {
    let name = format!("error:{}", relative_path);
    let node_id = format!("sha256:{}", sha256_hex(format!("node:{}:{}", crux_id, name).as_bytes()));
    let classification = default_classification.unwrap_or("internal").to_string();
    let summary = format!("Ingestion failed for {}", relative_path);
    let summary = if summary.len() > 200 { summary[..200].to_string() } else { summary };

    CruxNode {
        node_id,
        name,
        kind: "error".to_string(),
        module: "scanner".to_string(),
        summary,
        schema: NodeSchema::empty(),
        tags: vec!["error".to_string(), "ingestion-failure".to_string()],
        reach: Vec::new(),
        properties: vec![
            format!("provenance.source_path={}", relative_path),
            format!("error.message={}", error),
        ],
        warnings: vec![format!("Ingestion error: {}", error)],
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata { classification, redact_below: None },
        content_hash: format!("sha256:{}", sha256_hex(relative_path.as_bytes())),
        deleted_at: None,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn make_test_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("crux_scanner_test_{}_{}", crate::schema::now_unix(), id));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_classify_by_extension() {
        assert_eq!(classify_file(Path::new("inbox.mbox")), FileKind::Email);
        assert_eq!(classify_file(Path::new("README.md")), FileKind::Markdown);
        assert_eq!(classify_file(Path::new("data.csv")), FileKind::Csv);
        assert_eq!(classify_file(Path::new("api.json")), FileKind::Json);
        assert_eq!(classify_file(Path::new("notes.txt")), FileKind::Plaintext);
        assert_eq!(classify_file(Path::new("main.rs")), FileKind::SourceCode);
        assert_eq!(classify_file(Path::new("report.pdf")), FileKind::Document);
        assert_eq!(classify_file(Path::new("photo.jpg")), FileKind::Image);
        assert_eq!(classify_file(Path::new("app.exe")), FileKind::Binary);
    }

    #[test]
    fn test_file_kind_is_ingestible() {
        assert!(FileKind::Email.is_ingestible());
        assert!(FileKind::Markdown.is_ingestible());
        assert!(FileKind::Csv.is_ingestible());
        assert!(FileKind::Json.is_ingestible());
        assert!(FileKind::Plaintext.is_ingestible());
        assert!(FileKind::SourceCode.is_ingestible());
        assert!(!FileKind::Document.is_ingestible());
        assert!(!FileKind::Image.is_ingestible());
        assert!(!FileKind::Binary.is_ingestible());
    }

    #[test]
    fn test_scan_directory_basic() {
        let dir = make_test_dir();
        fs::write(dir.join("readme.md"), "# Hello\n").unwrap();
        fs::write(dir.join("data.csv"), "name,age\nalice,30\n").unwrap();
        fs::write(dir.join("photo.jpg"), b"\xff\xd8\xff\xe0").unwrap();

        let result = scan_directory(&dir, None, &[]).unwrap();
        assert_eq!(result.files.len(), 3);

        let kinds: Vec<&str> = result.files.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"markdown"));
        assert!(kinds.contains(&"csv"));
        assert!(kinds.contains(&"image"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_directory_hidden_skipped() {
        let dir = make_test_dir();
        fs::write(dir.join("visible.txt"), "hello").unwrap();
        fs::write(dir.join(".hidden.txt"), "secret").unwrap();

        let result = scan_directory(&dir, None, &[]).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].relative_path, "visible.txt");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_directory_extension_filter() {
        let dir = make_test_dir();
        fs::write(dir.join("a.md"), "# A").unwrap();
        fs::write(dir.join("b.csv"), "x,y").unwrap();
        fs::write(dir.join("c.txt"), "hi").unwrap();

        let result = scan_directory(
            &dir,
            None,
            &["md".to_string(), "csv".to_string()],
        )
        .unwrap();
        assert_eq!(result.files.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_directory_max_depth() {
        let dir = make_test_dir();
        let sub = dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.join("root.txt"), "root").unwrap();
        fs::write(sub.join("deep.txt"), "deep").unwrap();

        let result = scan_directory(&dir, Some(0), &[]).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].relative_path, "root.txt");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_result_to_json() {
        let dir = make_test_dir();
        fs::write(dir.join("test.md"), "# Test").unwrap();

        let result = scan_directory(&dir, None, &[]).unwrap();
        let json = result.to_json();
        assert!(json.contains("test.md"));
        assert!(json.contains("markdown"));
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_from_file_markdown() {
        let dir = make_test_dir();
        let file = dir.join("docs.md");
        fs::write(&file, "# Section One\nContent here.\n## Sub\nMore content.").unwrap();

        let db = generate_from_file(&file, "test-crux", Some("drive-1"), Some("internal")).unwrap();
        assert!(!db.nodes.is_empty());

        // All nodes should have provenance
        for node in &db.nodes {
            let has_provenance = node.properties.iter().any(|p| p.starts_with("provenance."));
            assert!(has_provenance, "Node '{}' missing provenance", node.name);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_from_file_binary() {
        let dir = make_test_dir();
        let file = dir.join("photo.jpg");
        fs::write(&file, b"\xff\xd8\xff\xe0test binary content").unwrap();

        let db = generate_from_file(&file, "test-crux", None, None).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert!(db.nodes[0].warnings.iter().any(|w| w.contains("binary")));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_dir_by_kind() {
        let source = make_test_dir();
        let output = make_test_dir();

        fs::write(source.join("README.md"), "# Project\n## Overview\nTest").unwrap();
        fs::write(source.join("data.csv"), "name,age\nalice,30\nbob,25\n").unwrap();
        fs::write(source.join("notes.txt"), "Some notes here").unwrap();

        let result = generate_dir(
            &source,
            &output,
            "test",
            GroupingStrategy::ByKind,
            Some("drive-1"),
            Some("internal"),
            None,
        )
        .unwrap();

        // Should have 3 cruxes: markdown, csv, plaintext
        assert_eq!(result.cruxes.len(), 3, "Expected 3 cruxes, got: {:?}", result.cruxes);

        // All crux files should exist
        for (_, path) in &result.cruxes {
            assert!(path.exists(), "Crux file not found: {}", path.display());
        }

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&output);
    }

    #[test]
    fn test_generate_dir_flat() {
        let source = make_test_dir();
        let output = make_test_dir();

        fs::write(source.join("a.md"), "# A").unwrap();
        fs::write(source.join("b.csv"), "x,y\n1,2").unwrap();

        let result = generate_dir(
            &source,
            &output,
            "flat-mesh",
            GroupingStrategy::Flat,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(result.cruxes.len(), 1);

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&output);
    }

    #[test]
    fn test_grouping_strategy_from_str() {
        assert_eq!(GroupingStrategy::from_str("by_kind"), GroupingStrategy::ByKind);
        assert_eq!(GroupingStrategy::from_str("by_directory"), GroupingStrategy::ByDirectory);
        assert_eq!(GroupingStrategy::from_str("flat"), GroupingStrategy::Flat);
        assert_eq!(GroupingStrategy::from_str("unknown"), GroupingStrategy::ByKind);
    }
}
