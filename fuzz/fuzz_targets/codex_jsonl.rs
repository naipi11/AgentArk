#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use agentark_adapter_codex::{normalize_thread_read_bytes, split_complete_jsonl_prefix};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = split_complete_jsonl_prefix(data);
            if let Ok(session) = normalize_thread_read_bytes(data) {
                assert!(!session.searchable_text().contains("HiddenReasoningCanary"));
            }
        }))
        .is_ok()
    );
});
