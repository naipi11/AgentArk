use std::{fs, path::Path};

use agentark_security::{
    AuthorizedRoot, PathClass, classify_windows_path, is_windows_reparse_point,
    validate_relative_lexical,
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
    assert_eq!(classify_windows_path(r"C:relative"), PathClass::Device);
    assert!(validate_relative_lexical(r"C:relative").is_err());
    assert!(!is_windows_reparse_point(0));
    assert!(is_windows_reparse_point(0x400));
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_to_an_outside_file_without_opening_the_target() {
    let root_dir = tempdir().unwrap();
    let outside_dir = tempdir().unwrap();
    fs::write(outside_dir.path().join("secret.jsonl"), b"secret").unwrap();
    std::os::unix::fs::symlink(
        outside_dir.path().join("secret.jsonl"),
        root_dir.path().join("link.jsonl"),
    )
    .unwrap();
    let root = AuthorizedRoot::new(root_dir.path().to_path_buf()).unwrap();
    assert!(root.open_regular_file(Path::new("link.jsonl")).is_err());
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
