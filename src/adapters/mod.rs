//! Universal crux adapters — generate CruxDb from various data sources.
//!
//! Each adapter reads a specific input format (LML, Markdown, plaintext, etc.)
//! and produces a standard v2 `CruxDb` with extracted nodes and edges.

pub mod auto;
pub mod csv;
pub mod lml;
pub mod manual;
pub mod markdown;
pub mod plaintext;
pub mod scanner;

use crate::schema::CruxDb;

/// Configuration for adapter invocations.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// Name for the generated crux.
    pub name: String,
    /// Origin identifier (e.g. "lml", "markdown").
    pub origin: String,
    /// Default security classification for generated nodes (e.g. "internal").
    pub default_classification: Option<String>,
    /// Default module name for generated nodes.
    pub default_module: Option<String>,
    /// Schema hints mapping field names to node kinds (e.g. "contact" → "person").
    pub schema_hints: Vec<(String, String)>,
}

impl AdapterConfig {
    /// Create a minimal config with just name and origin.
    pub fn new(name: &str, origin: &str) -> Self {
        AdapterConfig {
            name: name.to_string(),
            origin: origin.to_string(),
            default_classification: None,
            default_module: None,
            schema_hints: Vec::new(),
        }
    }
}

/// Trait for crux adapters that generate a CruxDb from text input.
pub trait CruxAdapter {
    /// Generate a CruxDb from the given input text.
    fn generate(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String>;
}
