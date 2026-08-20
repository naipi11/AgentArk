use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

use crate::SecurityError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    Local,
    Unc,
    Device,
    AlternateDataStream,
    Traversal,
    ReparsePoint,
    Symlink,
}

pub fn classify_windows_path(value: &str) -> PathClass {
    let normalized = value.replace('/', r"\");
    if normalized.starts_with(r"\\?\") || normalized.starts_with(r"\\.\") {
        return PathClass::Device;
    }
    if normalized.starts_with(r"\\") {
        return PathClass::Unc;
    }
    if normalized.split('\\').any(|part| part == "..") {
        return PathClass::Traversal;
    }
    let bytes = normalized.as_bytes();
    let without_drive = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        &normalized[2..]
    } else {
        &normalized
    };
    if without_drive.contains(':') {
        return PathClass::AlternateDataStream;
    }
    PathClass::Local
}

pub fn is_windows_reparse_point(file_attributes: u32) -> bool {
    file_attributes & 0x400 != 0
}

pub fn validate_relative_lexical(value: &str) -> Result<(), SecurityError> {
    if value.is_empty() {
        return Err(SecurityError::ForbiddenPathClass("empty"));
    }
    let class = classify_windows_path(value);
    if class != PathClass::Local {
        return Err(SecurityError::ForbiddenPathClass(match class {
            PathClass::Unc => "unc",
            PathClass::Device => "device",
            PathClass::AlternateDataStream => "alternate-data-stream",
            PathClass::Traversal => "traversal",
            PathClass::ReparsePoint => "reparse-point",
            PathClass::Symlink => "symlink",
            PathClass::Local => unreachable!(),
        }));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || value.starts_with('/')
        || value.starts_with('\\')
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(SecurityError::ForbiddenPathClass(
            "absolute-or-dot-component",
        ));
    }
    Ok(())
}

pub struct AuthorizedRoot {
    root: PathBuf,
}

impl AuthorizedRoot {
    pub fn new(root: PathBuf) -> Result<Self, SecurityError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(SecurityError::RootNotAuthorized);
        }
        Ok(Self {
            root: dunce::canonicalize(root)?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve_existing(&self, relative: &Path) -> Result<PathBuf, SecurityError> {
        let value = relative.to_str().ok_or(SecurityError::NonUtf8Path)?;
        validate_relative_lexical(value)?;
        let mut candidate = self.root.clone();
        for component in relative.components() {
            let normal = match component {
                std::path::Component::Normal(value) => value,
                _ => return Err(SecurityError::PathEscape),
            };
            candidate.push(normal);
            let metadata = std::fs::symlink_metadata(&candidate)?;
            if metadata.file_type().is_symlink() {
                return Err(SecurityError::ForbiddenPathClass("symlink"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if is_windows_reparse_point(metadata.file_attributes()) {
                    return Err(SecurityError::ForbiddenPathClass("reparse-point"));
                }
            }
        }
        let canonical = dunce::canonicalize(&candidate)?;
        if !canonical.starts_with(&self.root) {
            return Err(SecurityError::PathEscape);
        }
        Ok(canonical)
    }

    pub fn open_regular_file(&self, relative: &Path) -> Result<File, SecurityError> {
        let path = self.resolve_existing(relative)?;
        if !std::fs::metadata(&path)?.is_file() {
            return Err(SecurityError::NotRegularFile);
        }
        Ok(OpenOptions::new().read(true).open(path)?)
    }
}
