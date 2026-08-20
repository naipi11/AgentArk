use std::path::{Path, PathBuf};

use cap_std::{
    ambient_authority,
    fs::{Dir, File},
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
    let has_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let without_drive = if has_drive {
        &normalized[2..]
    } else {
        &normalized
    };
    if without_drive.contains(':') {
        return PathClass::AlternateDataStream;
    }
    if has_drive {
        return PathClass::Device;
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
    dir: Dir,
}

impl AuthorizedRoot {
    pub fn new(root: PathBuf) -> Result<Self, SecurityError> {
        let metadata = std::fs::symlink_metadata(&root)?;
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
        if !root.is_absolute() || !metadata.is_dir() {
            return Err(SecurityError::RootNotAuthorized);
        }
        let canonical_root = dunce::canonicalize(root)?;
        let dir = Dir::open_ambient_dir(&canonical_root, ambient_authority())?;
        Ok(Self {
            root: canonical_root,
            dir,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve_existing(&self, relative: &Path) -> Result<PathBuf, SecurityError> {
        let value = relative.to_str().ok_or(SecurityError::NonUtf8Path)?;
        validate_relative_lexical(value)?;
        for component in relative.components() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err(SecurityError::PathEscape);
            }
        }
        let metadata = self.dir.symlink_metadata(relative)?;
        if metadata.file_type().is_symlink() {
            return Err(SecurityError::ForbiddenPathClass("symlink"));
        }
        #[cfg(windows)]
        {
            use cap_std::fs::MetadataExt;
            if is_windows_reparse_point(metadata.file_attributes()) {
                return Err(SecurityError::ForbiddenPathClass("reparse-point"));
            }
        }
        let canonical_relative = self.dir.canonicalize(relative)?;
        if canonical_relative.is_absolute()
            || canonical_relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(SecurityError::PathEscape);
        }
        Ok(self.root.join(canonical_relative))
    }

    pub fn open_regular_file(&self, relative: &Path) -> Result<File, SecurityError> {
        let value = relative.to_str().ok_or(SecurityError::NonUtf8Path)?;
        validate_relative_lexical(value)?;
        let metadata = self.dir.symlink_metadata(relative)?;
        if metadata.file_type().is_symlink() {
            return Err(SecurityError::ForbiddenPathClass("symlink"));
        }
        #[cfg(windows)]
        {
            use cap_std::fs::MetadataExt;
            if is_windows_reparse_point(metadata.file_attributes()) {
                return Err(SecurityError::ForbiddenPathClass("reparse-point"));
            }
        }
        if !metadata.is_file() {
            return Err(SecurityError::NotRegularFile);
        }
        let file = self.dir.open(relative)?;
        let after = self.dir.symlink_metadata(relative)?;
        if after.file_type().is_symlink() {
            return Err(SecurityError::ForbiddenPathClass("symlink"));
        }
        #[cfg(windows)]
        {
            use cap_std::fs::MetadataExt;
            if is_windows_reparse_point(after.file_attributes()) {
                return Err(SecurityError::ForbiddenPathClass("reparse-point"));
            }
        }
        if !file.metadata()?.is_file() {
            return Err(SecurityError::NotRegularFile);
        }
        Ok(file)
    }
}
