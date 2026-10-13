//! A single project-file selector for all public operations. The loader still
//! owns interpretation of main.srx and the lock; the CLI only selects its root.
use std::path::{Path, PathBuf};

pub(crate) fn select(reference: Option<&str>, file: Option<&Path>) -> Result<String, String> {
    let Some(file) = file else {
        return Ok(reference.unwrap_or(".").to_owned());
    };
    if file
        .file_name()
        .is_none_or(|name| name != "main.srx")
    {
        return Err("-f/--file must name a project's main.srx".into());
    }
    let parent = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::path::absolute(parent).map_err(|error| error.to_string())?;
    let export = match reference {
        None | Some(".") => None,
        Some(name) if name.starts_with(".#") && name.len() > 2 => Some(&name[2..]),
        Some(name) => {
            return Err(format!(
                "-f/--file selects a project; use .#export instead of {name:?}"
            ));
        }
    };
    let mut selected = parent
        .into_os_string()
        .into_string()
        .map_err(|_| "project path must be UTF-8".to_owned())?;
    if selected.contains('#') {
        return Err("project path contains '#', which is reserved for export selection".into());
    }
    if let Some(export) = export {
        selected.push('#');
        selected.push_str(export);
    }
    Ok(selected)
}

pub(crate) fn project(file: Option<&Path>, path: Option<&Path>) -> Result<PathBuf, String> {
    if path.is_some() && file.is_some() {
        return Err("use either a project path or -f/--file".into());
    }
    let reference = select(None, file)?;
    Ok(path.map_or_else(|| PathBuf::from(reference), Path::to_path_buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_selects_exact_entrypoint_and_explicit_export() {
        let file = Path::new("project/main.srx");
        assert!(
            select(None, Some(file))
                .unwrap()
                .ends_with("/project")
        );
        assert!(
            select(Some(".#hello"), Some(file))
                .unwrap()
                .ends_with("/project#hello")
        );
        assert!(select(Some("hello"), Some(file)).is_err());
        assert!(select(None, Some(Path::new("other.srx"))).is_err());
        assert!(project(Some(file), Some(Path::new("project"))).is_err());
    }
}
