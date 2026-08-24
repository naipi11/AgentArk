use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

use cap_primitives::fs::open_dir_nofollow;
use cap_std::{
    ambient_authority,
    fs::{Dir, File},
};
use io_lifetimes::AsFilelike;

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

/// Opens an existing absolute directory through a stable filesystem root and
/// rejects every symlink or Windows reparse point encountered while traversing
/// it. The returned capability remains pinned to the opened directory even if
/// its path is renamed afterward.
pub fn open_directory_nofollow(path: &Path) -> Result<Dir, SecurityError> {
    let normalized_path = normalize_system_directory_alias(path);
    let (filesystem_root, components) = split_absolute_directory_path(&normalized_path)?;
    let mut directory = Dir::open_ambient_dir(&filesystem_root, ambient_authority())?;
    for component in components {
        directory = open_child_directory_nofollow(&directory, Path::new(&component))?;
    }
    Ok(directory)
}

fn normalize_system_directory_alias(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        for (alias, canonical) in [
            (Path::new("/var"), Path::new("/private/var")),
            (Path::new("/tmp"), Path::new("/private/tmp")),
            (Path::new("/etc"), Path::new("/private/etc")),
        ] {
            if let Ok(relative) = path.strip_prefix(alias) {
                return canonical.join(relative);
            }
        }
    }
    path.to_path_buf()
}

/// Opens an absolute directory, creating missing normal-path components from
/// the nearest existing parent while rejecting every symlink or Windows
/// reparse point encountered during traversal.
pub fn open_or_create_directory_nofollow(path: &Path) -> Result<Dir, SecurityError> {
    if !path.is_absolute() {
        return Err(SecurityError::RootNotAuthorized);
    }
    let mut missing_components = Vec::new();
    let mut anchor = path;
    loop {
        match std::fs::symlink_metadata(anchor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = anchor.file_name().ok_or(SecurityError::PathEscape)?;
                missing_components.push(component.to_owned());
                anchor = anchor.parent().ok_or(SecurityError::PathEscape)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut directory = open_directory_nofollow(anchor)?;
    for component in missing_components.iter().rev() {
        let component = Path::new(component);
        match directory.symlink_metadata(component) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(SecurityError::RootNotAuthorized),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match directory.create_dir(component) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
        directory = open_child_directory_nofollow(&directory, component)?;
    }
    Ok(directory)
}

/// Opens one child directory without following a symlink or Windows reparse
/// point. Callers retain the parent capability, so this is race-resistant for
/// child replacement between validation and use.
pub fn open_child_directory_nofollow(parent: &Dir, child: &Path) -> Result<Dir, SecurityError> {
    if !matches!(child.components().next(), Some(Component::Normal(_)))
        || child.components().count() != 1
    {
        return Err(SecurityError::PathEscape);
    }
    open_dir_nofollow(&parent.as_filelike_view::<std::fs::File>(), child)
        .map(Dir::from_std_file)
        .map_err(SecurityError::from)
}

fn split_absolute_directory_path(path: &Path) -> Result<(PathBuf, Vec<OsString>), SecurityError> {
    if !path.is_absolute() {
        return Err(SecurityError::RootNotAuthorized);
    }
    let mut filesystem_root = PathBuf::new();
    let mut components = Vec::new();
    let mut found_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => filesystem_root.push(prefix.as_os_str()),
            Component::RootDir => {
                filesystem_root.push(component.as_os_str());
                found_root = true;
            }
            Component::Normal(value) if found_root => components.push(value.to_owned()),
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                return Err(SecurityError::PathEscape);
            }
        }
    }
    if !found_root {
        return Err(SecurityError::RootNotAuthorized);
    }
    Ok((filesystem_root, components))
}

pub struct AuthorizedRoot {
    root: PathBuf,
    dir: Dir,
}

impl AuthorizedRoot {
    pub fn new(root: PathBuf) -> Result<Self, SecurityError> {
        let dir = open_directory_nofollow(&root)?;
        Ok(Self { root, dir })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve_existing(&self, relative: &Path) -> Result<PathBuf, SecurityError> {
        let value = relative.to_str().ok_or(SecurityError::NonUtf8Path)?;
        validate_relative_lexical(value)?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let filename = relative.file_name().ok_or(SecurityError::PathEscape)?;
        let parent_dir = self.open_relative_directory_nofollow(parent)?;
        let metadata = parent_dir.symlink_metadata(filename)?;
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
        Ok(self.root.join(relative))
    }

    pub fn open_regular_file(&self, relative: &Path) -> Result<File, SecurityError> {
        let value = relative.to_str().ok_or(SecurityError::NonUtf8Path)?;
        validate_relative_lexical(value)?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let filename = relative.file_name().ok_or(SecurityError::PathEscape)?;
        let parent_dir = self.open_relative_directory_nofollow(parent)?;
        let metadata = parent_dir.symlink_metadata(filename)?;
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
        let file = parent_dir.open(filename)?;
        let after = parent_dir.symlink_metadata(filename)?;
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

    fn open_relative_directory_nofollow(&self, relative: &Path) -> Result<Dir, SecurityError> {
        let mut directory = self.dir.try_clone()?;
        for component in relative.components() {
            let Component::Normal(value) = component else {
                return Err(SecurityError::PathEscape);
            };
            directory = open_child_directory_nofollow(&directory, Path::new(value))?;
        }
        Ok(directory)
    }
}
