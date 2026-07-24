use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::CompileError;

pub fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, CompileError> {
    let value = serde_json::to_value(value)
        .map_err(|error| CompileError::CanonicalSerialization(error.to_string()))?;
    let sorted = sort_value(value);
    serde_json::to_vec(&sorted)
        .map_err(|error| CompileError::CanonicalSerialization(error.to_string()))
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_value(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}
