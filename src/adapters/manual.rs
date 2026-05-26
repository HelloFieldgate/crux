//! Manual adapter — hand-written JSON passthrough with validation.
//!
//! Accepts JSON in the universal v2 CruxDb format and validates it.

use crate::adapters::{AdapterConfig, CruxAdapter};
use crate::schema::{parse_crux_db, CruxDb};

pub struct ManualAdapter;

impl CruxAdapter for ManualAdapter {
    fn generate(&self, input: &str, _config: &AdapterConfig) -> Result<CruxDb, String> {
        // Basic validation: must look like JSON
        let trimmed = input.trim();
        if !trimmed.starts_with('{') {
            return Err("Input is not valid JSON (expected '{')".to_string());
        }
        let db = parse_crux_db(input)?;
        // Validate that we got a meaningful crux_id
        if db.header.crux_id.is_empty() {
            return Err("Missing required field 'crux_id'".to_string());
        }
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{create_crux_db, serialize_crux_db, CruxKind};

    #[test]
    fn test_manual_adapter_roundtrip() {
        let db = create_crux_db("test", CruxKind::Codebase, "manual");
        let json = serialize_crux_db(&db);

        let adapter = ManualAdapter;
        let config = AdapterConfig::new("test", "manual");

        let result = adapter.generate(&json, &config).unwrap();
        assert_eq!(result.header.crux_name, "test");
    }

    #[test]
    fn test_manual_adapter_invalid() {
        let adapter = ManualAdapter;
        let config = AdapterConfig::new("test", "manual");

        let result = adapter.generate("not json", &config);
        assert!(result.is_err());
    }
}
