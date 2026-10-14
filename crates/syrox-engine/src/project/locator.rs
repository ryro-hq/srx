use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use syrox_lang::{syntax::ItemKind, syntax::ParsedSources, syntax::StringPart};

use super::CheckFailure;

pub(super) struct InputLocator {
    pub(super) name: String,
    pub(super) relative: PathBuf,
    pub(super) modules: bool,
    pub(super) child: bool,
    pub(super) github: Option<crate::acquire::github::GithubLocator>,
}

pub(super) fn root_input_locators(
    parsed: &ParsedSources,
) -> Result<Vec<InputLocator>, CheckFailure> {
    let mut names = HashSet::new();
    let mut locators = Vec::new();
    let main = parsed
        .iter()
        .next()
        .expect("main source was parsed")
        .program();
    for item in &main.items {
        let ItemKind::Inputs(inputs) = &item.kind else {
            continue;
        };
        for input in &inputs.entries {
            if !names.insert(input.name.text.clone()) {
                return Err(CheckFailure::DuplicateInputName {
                    name: input.name.text.clone(),
                });
            }
            let locator = decode_plain_string(&input.value).ok_or_else(|| {
                CheckFailure::UnsupportedLocator {
                    name: input.name.text.clone(),
                    locator: input.value.source.clone(),
                }
            })?;
            if locator.starts_with("github:") {
                locators.push(InputLocator {
                    name: input.name.text.clone(),
                    relative: PathBuf::new(),
                    modules: false,
                    child: true,
                    github: Some(crate::acquire::github::GithubLocator::parse(
                        &locator,
                    )?),
                });
                continue;
            }
            let (relative, modules, child) =
                if let Some(relative) = locator.strip_prefix("path:../") {
                    (relative, false, true)
                } else if let Some(relative) = locator.strip_prefix("path:") {
                    (relative, false, false)
                } else if let Some(relative) = locator.strip_prefix("modules:") {
                    (relative, true, false)
                } else {
                    return Err(CheckFailure::UnsupportedLocator {
                        name: input.name.text.clone(),
                        locator,
                    });
                };
            let original = Path::new(relative);
            let relative = normalize_relative_input(&input.name.text, original)?;
            if child && original.as_os_str() != relative.as_os_str() {
                return Err(CheckFailure::UnsafeInputPath {
                    name: input.name.text.clone(),
                    path: original.to_path_buf(),
                });
            }
            if child && relative.as_os_str().is_empty() {
                return Err(CheckFailure::UnsafeInputPath {
                    name: input.name.text.clone(),
                    path: PathBuf::from(".."),
                });
            }
            locators.push(InputLocator {
                name: input.name.text.clone(),
                relative,
                modules,
                child,
                github: None,
            });
        }
    }
    Ok(locators)
}

fn decode_plain_string(value: &syrox_lang::syntax::StringLiteral) -> Option<String> {
    let mut decoded = String::new();
    for part in &value.parts {
        let StringPart::Text {
            source,
            ..
        } = part
        else {
            return None;
        };
        let mut chars = source.chars();
        while let Some(character) = chars.next() {
            if character != '\\' {
                decoded.push(character);
                continue;
            }
            decoded.push(match chars.next()? {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '$' => '$',
                _ => return None,
            });
        }
    }
    Some(decoded)
}

fn normalize_relative_input(name: &str, path: &Path) -> Result<PathBuf, CheckFailure> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CheckFailure::UnsafeInputPath {
                    name: name.to_owned(),
                    path: path.to_path_buf(),
                });
            }
        }
    }
    Ok(normalized)
}
