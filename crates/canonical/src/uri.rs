use std::path::Path;

/// Return a canonical file URI for a local path on the current platform.
///
/// `Url::from_file_path` performs the required drive-letter, UNC, and percent
/// escaping rules. Relative paths are resolved against the current directory
/// without requiring the target to exist.
pub fn file_uri_for_path(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .expect("the process must have a current directory")
            .join(path)
    };
    url::Url::from_file_path(&absolute)
        .expect("an absolute filesystem path always converts to a file URI")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::file_uri_for_path;
    use std::path::Path;

    #[test]
    fn emits_a_standard_absolute_file_uri() {
        let uri = file_uri_for_path(if cfg!(windows) {
            Path::new(r"C:\AgentArk\workspace")
        } else {
            Path::new("/tmp/AgentArk/workspace")
        });
        assert!(uri.starts_with("file:///"));
        assert!(!uri.starts_with("file:////"));
        assert!(!uri.contains('\\'));
    }
}
