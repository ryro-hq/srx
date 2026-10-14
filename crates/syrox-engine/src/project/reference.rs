use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectReference<'a> {
    Project {
        path: &'a Path,
        export: Option<&'a str>,
    },
    Catalog {
        export: &'a str,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid project or catalog reference")]
pub struct InvalidProjectReference;

pub fn parse_project_reference(
    reference: &str,
) -> Result<ProjectReference<'_>, InvalidProjectReference> {
    if reference.is_empty() || reference.len() > 4096 {
        return Err(InvalidProjectReference);
    }
    if let Some((path, export)) = reference.split_once('#') {
        if !is_project_path(path) || !valid_export(export) {
            return Err(InvalidProjectReference);
        }
        return Ok(ProjectReference::Project {
            path: Path::new(path),
            export: Some(export),
        });
    }
    if is_project_path(reference) {
        return Ok(ProjectReference::Project {
            path: Path::new(reference),
            export: None,
        });
    }
    if valid_export(reference) {
        Ok(ProjectReference::Catalog {
            export: reference,
        })
    } else {
        Err(InvalidProjectReference)
    }
}

fn is_project_path(text: &str) -> bool {
    matches!(text, "." | "..") || text.contains('/')
}
// A module export key is a sequence of public identifiers, not one flat name.
// Keep the existing ASCII/length policy until the public Unicode CLI contract
// is settled; never accept empty segments or a single ':' as separators.
fn valid_export(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && text.split("::").all(|segment| {
            !segment.is_empty()
                && segment.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                })
        })
}

#[cfg(test)]
mod reference_tests {
    use super::{ProjectReference, parse_project_reference, valid_export};
    use std::path::Path;

    #[test]
    fn parent_project_and_selected_exports_share_one_classification() {
        for path in [
            ".",
            "..",
            "./project",
            "/tmp/project",
            "../main.srx",
        ] {
            assert_eq!(
                parse_project_reference(path).unwrap(),
                ProjectReference::Project {
                    path: Path::new(path),
                    export: None
                }
            );
            let selected = format!("{path}#group::hello");
            assert_eq!(
                parse_project_reference(&selected).unwrap(),
                ProjectReference::Project {
                    path: Path::new(path),
                    export: Some("group::hello")
                }
            );
        }
        assert_eq!(
            parse_project_reference("group::hello").unwrap(),
            ProjectReference::Catalog {
                export: "group::hello"
            }
        );
        for invalid in [
            "",
            "project#hello",
            ".#",
            "..#a#b",
            "a:b",
        ] {
            assert!(
                parse_project_reference(invalid).is_err(),
                "{invalid}"
            );
        }
        assert!(parse_project_reference(&format!("./{}", "a".repeat(4095))).is_err());
    }

    #[test]
    fn composite_catalog_keys_follow_module_export_spelling() {
        for valid in ["hello", "group::hello", "a0::b_2::C"] {
            assert!(valid_export(valid), "{valid}");
        }
        for invalid in [
            "",
            "::hello",
            "group::",
            "group:::hello",
            "group:hello",
            "a::::b",
            "a/b",
            "a#b",
            "a::1b",
            "a::ü",
        ] {
            assert!(!valid_export(invalid), "{invalid}");
        }
        assert!(!valid_export(&format!("a::{}", "b".repeat(253))));
    }
}
