#![no_main]

use agentark_security::{PathClass, classify_windows_path, validate_relative_lexical};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let class = classify_windows_path(&value);
    let accepted = validate_relative_lexical(value.as_ref()).is_ok();
    if matches!(
        class,
        PathClass::Unc | PathClass::Device | PathClass::AlternateDataStream | PathClass::Traversal
    ) {
        assert!(!accepted);
    }
});
