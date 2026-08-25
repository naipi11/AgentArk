use std::{fs, path::Path};

#[cfg(windows)]
use std::process::Command;

use agentark_security::{
    AuthorizedRoot, PathClass, classify_windows_path, is_windows_reparse_point,
    open_directory_nofollow, validate_relative_lexical,
};
use tempfile::tempdir;

#[cfg(windows)]
fn link_directory(link: &Path, target: &Path) {
    let status = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            link.to_string_lossy().as_ref(),
            target.to_string_lossy().as_ref(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
fn link_directory(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

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

#[cfg(windows)]
#[test]
fn opens_a_canonical_windows_workspace_root() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("README.md"), b"workspace").unwrap();
    let canonical_root = std::fs::canonicalize(workspace.path()).unwrap();

    assert!(canonical_root.to_string_lossy().starts_with(r"\\?\"));
    let root = AuthorizedRoot::new(canonical_root).unwrap();
    assert!(root.open_regular_file(Path::new("README.md")).is_ok());
}

#[test]
fn nofollow_directory_open_rejects_linked_root() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let linked = root.path().join("linked");
    link_directory(&linked, outside.path());

    assert!(open_directory_nofollow(&linked).is_err());
    assert!(open_directory_nofollow(root.path()).is_ok());
}

#[test]
fn resolve_existing_rejects_a_linked_parent_directory() {
    let root_dir = tempdir().unwrap();
    let outside_dir = tempdir().unwrap();
    fs::write(outside_dir.path().join("secret.jsonl"), b"secret").unwrap();
    link_directory(&root_dir.path().join("linked"), outside_dir.path());
    let root = AuthorizedRoot::new(root_dir.path().to_path_buf()).unwrap();

    assert!(
        root.resolve_existing(Path::new("linked/secret.jsonl"))
            .is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn nofollow_directory_open_accepts_the_macos_system_temp_alias() {
    assert!(open_directory_nofollow(&std::env::temp_dir()).is_ok());
}
