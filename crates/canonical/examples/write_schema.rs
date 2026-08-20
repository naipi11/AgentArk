use std::{env, fs, path::PathBuf};

use agentark_canonical::CanonicalSession;
use schemars::schema_for;

fn main() {
    let output = env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("schema output path is required");
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("create schema parent");
    }
    let schema = schema_for!(CanonicalSession);
    let json = serde_json::to_vec_pretty(&schema).expect("serialize schema");
    fs::write(output, json).expect("write schema");
}
