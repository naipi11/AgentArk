use std::{fs, path::Path};

use agentark_security::{
    AuthorizedRoot, PathClass, classify_windows_path, is_windows_reparse_point,
};
use tempfile::tempdir;

#[test]
fn rejects_windows_unc_device_ads_and_traversal_strings_on_every_platform() {
    assert_eq!(classify_windows_path(r"\\server\share\x"), PathClass::Unc);
    assert_eq!(classify_windows_path(r"\\?\C:\x"), PathClass::Device);
    assert_eq!(
        classify_windows_path(r"C:\safe\file.txt:secret"),
        PathClass::AlternateDataStream
    );
    assert_eq!(classify_windows_path(r"..\outside"), PathClass::Traversal);
    assert!(!is_windows_reparse_point(0));
    assert!(is_windows_reparse_point(0x400));
}

#[test]
fn opens_only_regular_files_beneath_the_authorized_root() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("ok.jsonl"), b"{}\n").unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    let root = AuthorizedRoot::new(dir.path().to_path_buf()).unwrap();
    assert!(root.open_regular_file(Path::new("ok.jsonl")).is_ok());
    assert!(root.open_regular_file(Path::new("nested")).is_err());
    assert!(root.open_regular_file(Path::new("../escape")).is_err());
}
