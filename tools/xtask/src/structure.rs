//! Checking where production modules live across the workspace crates.
//!
//! Crate entries must introduce the reading flow. Internal files may omit docs
//! when their names and code already explain their role. Directories with `mod.rs`
//! remain reserved for modules with production children.
//!
//! Versioned format tags (`"syrox-...-vN"`) are spelled only in
//! `syrox_encoding::formats`. Tests, test-gated items and examples may spell them
//! out, so fixtures double as golden checks of the registry bytes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn has_crate_docs(source: &str) -> bool {
    source
        .lines()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| line.starts_with("//!"))
        .any(|line| {
            line.strip_prefix("//!")
                .is_some_and(|text| !text.trim().is_empty())
        })
}

// Comments vanish and each string literal stays one token starting with its quote,
// so fixture source strings cannot invent modules or hide format tags.
fn tokens(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index..].starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        } else {
            let raw = [
                b"r".as_slice(),
                b"br".as_slice(),
                b"cr".as_slice(),
            ]
            .into_iter()
            .find_map(|prefix| {
                if !bytes[index..].starts_with(prefix) {
                    return None;
                }
                let start = index + prefix.len();
                let mut quote = start;
                while bytes.get(quote) == Some(&b'#') {
                    quote += 1;
                }
                (bytes.get(quote) == Some(&b'"')).then_some((quote, quote - start))
            });
            if let Some((quote, hashes)) = raw {
                index = quote + 1;
                while index < bytes.len() {
                    if bytes[index] == b'"'
                        && bytes
                            .get(index + 1..index + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|b| *b == b'#'))
                    {
                        index += 1 + hashes;
                        break;
                    }
                    index += 1;
                }
                result.push(source[quote..index].into());
            } else if bytes[index] == b'"' {
                let start = index;
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == b'"' {
                        index += 1;
                        break;
                    } else {
                        index += 1;
                    }
                }
                result.push(source[start..index].into());
            } else if bytes[index] == b'\'' && bytes.get(index + 2) == Some(&b'\'') {
                index += 3;
                result.push("literal".into());
            } else if bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_' {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                result.push(source[start..index].into());
            } else {
                result.push(char::from(bytes[index]).to_string());
                index += 1;
            }
        }
    }
    result
}

/// Parse the outer attribute starting at `index`, returning whether it gates on
/// `test` and the index after its closing bracket.
fn attribute(tokens: &[String], index: usize) -> Option<(bool, usize)> {
    if tokens[index] != "#" || tokens.get(index + 1).is_none_or(|t| t != "[") {
        return None;
    }
    let start = index + 2;
    let mut end = start;
    let mut brackets = 1;
    while end < tokens.len() && brackets > 0 {
        match tokens[end].as_str() {
            "[" => brackets += 1,
            "]" => brackets -= 1,
            _ => (),
        }
        end += 1;
    }
    let attribute = &tokens[start..end.saturating_sub(1)];
    let attr = attribute.join("");
    let mut parentheses = 0;
    let requires_test = attribute.iter().any(|token| {
        match token.as_str() {
            "(" => parentheses += 1,
            ")" => parentheses -= 1,
            "test" if parentheses == 2 => return true,
            _ => (),
        }
        false
    });
    Some((
        attr == "cfg(test)" || (attr.starts_with("cfg(all(") && requires_test),
        end,
    ))
}

fn production_modules(source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let mut modules = Vec::new();
    let mut index = 0;
    let mut depth = 0;
    let mut test_only = false;
    while index < tokens.len() {
        if depth == 0
            && let Some((test, end)) = attribute(&tokens, index)
        {
            test_only |= test;
            index = end;
            continue;
        }
        match tokens[index].as_str() {
            "mod"
                if depth == 0 && !test_only && tokens.get(index + 2).is_some_and(|t| t == ";") =>
            {
                modules.push(tokens[index + 1].clone());
            }
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth == 0 {
                    test_only = false;
                }
            }
            ";" if depth == 0 => test_only = false,
            _ => (),
        }
        index += 1;
    }
    modules
}

/// Versioned `syrox-...-vN` tag opening a string literal token.
fn format_tag(token: &str) -> Option<&str> {
    let body = token.strip_prefix('"')?;
    let end = body
        .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'))
        .unwrap_or(body.len());
    let tag = &body[..end];
    let (_, version) = tag.strip_prefix("syrox-")?.rsplit_once("-v")?;
    (!version.is_empty() && version.bytes().all(|b| b.is_ascii_digit())).then_some(tag)
}

/// Format tags spelled as literals outside items gated on `cfg(test)`.
fn format_literals(source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let mut found = Vec::new();
    let mut index = 0;
    let mut test_item = false;
    while index < tokens.len() {
        if let Some((test, end)) = attribute(&tokens, index) {
            test_item |= test;
            index = end;
            continue;
        }
        if test_item {
            // Skip the gated item, field, arm or statement: through its outer
            // `;` or `,`, or through the brace block that closes it.
            let mut depth = 0_usize;
            while index < tokens.len() {
                let token = tokens[index].as_str();
                index += 1;
                match token {
                    "{" | "(" | "[" => depth += 1,
                    "}" if depth <= 1 => break,
                    ")" | "]" | "}" => depth = depth.saturating_sub(1),
                    ";" | "," if depth == 0 => break,
                    _ => (),
                }
            }
            test_item = false;
            continue;
        }
        if let Some(tag) = format_tag(&tokens[index]) {
            found.push(tag.to_owned());
        }
        index += 1;
    }
    found
}

/// Tests, examples and the registry itself may spell tags out: tests and
/// fixtures keep literal tags as golden checks of the registry bytes.
fn may_spell_format_tags(path: &Path) -> bool {
    path.ends_with("crates/syrox-encoding/src/formats.rs")
        || path.components().any(|part| {
            matches!(
                part.as_os_str().to_str(),
                Some("tests" | "examples" | "benches")
            )
        })
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
}

fn production_child(directory: &Path) -> io::Result<bool> {
    let source = fs::read_to_string(directory.join("mod.rs"))?;
    Ok(production_modules(&source).iter().any(|name| {
        name != "tests"
            && !name.ends_with("_tests")
            && (directory.join(format!("{name}.rs")).is_file()
                || directory.join(name).join("mod.rs").is_file())
    }))
}

fn check(root: &Path) -> io::Result<Vec<String>> {
    let mut files = Vec::new();
    for name in [
        "syrox-lang",
        "syrox-encoding",
        "syrox-engine",
        "syrox-system",
        "syrox",
    ] {
        rust_files(&root.join("crates").join(name), &mut files)?;
    }
    files.sort();
    let mut errors = Vec::new();
    for entry in [
        "crates/syrox-lang/src/lib.rs",
        "crates/syrox-encoding/src/lib.rs",
        "crates/syrox-engine/src/lib.rs",
        "crates/syrox-system/src/lib.rs",
        "crates/syrox/src/main.rs",
        "crates/syrox/src/worker.rs",
    ] {
        let path = root.join(entry);
        if !has_crate_docs(&fs::read_to_string(&path)?) {
            errors.push(format!(
                "{}: explain the crate at its entry point",
                path.display()
            ));
        }
    }
    for path in &files {
        if path
            .file_name()
            .is_some_and(|name| name == "mod.rs")
            && !path
                .components()
                .any(|part| part.as_os_str() == "tests")
            && !production_child(
                path.parent()
                    .ok_or_else(|| io::Error::other("mod.rs path has no parent"))?,
            )?
        {
            errors.push(format!(
                "{}: leaf implementation must be a sibling .rs file; place large suites in domain tests",
                path.display()
            ));
        }
    }
    let tools = root.join("tools");
    if tools.is_dir() {
        rust_files(&tools, &mut files)?;
    }
    for path in &files {
        if may_spell_format_tags(path) {
            continue;
        }
        for tag in format_literals(&fs::read_to_string(path)?) {
            errors.push(format!(
                "{}: format tag {tag} is spelled as a literal; reference syrox_encoding::formats",
                path.display()
            ));
        }
    }
    println!(
        "Checked {} Rust files across five crates and tools",
        files.len()
    );
    Ok(errors)
}

pub(super) fn run(root: &Path) -> io::Result<()> {
    let errors = check(root)?;
    for error in &errors {
        eprintln!("{error}");
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other("module structure check failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_docs_start_at_the_entry_without_a_prescribed_template() {
        assert!(has_crate_docs(
            "//! Lê e checa os arquivos .srx.\n\npub mod syntax;"
        ));
        assert!(!has_crate_docs(
            "fn main() {}\n//! Uma explicação que veio depois."
        ));
        assert!(!has_crate_docs("//!\n\nfn main() {}"));
    }

    #[test]
    fn leaves_do_not_need_module_docs() {
        let root = std::env::temp_dir().join(format!("syrox-doc-layout-{}", std::process::id()));
        for entry in [
            "crates/syrox-lang/src/lib.rs",
            "crates/syrox-encoding/src/lib.rs",
            "crates/syrox-engine/src/lib.rs",
            "crates/syrox-system/src/lib.rs",
            "crates/syrox/src/main.rs",
            "crates/syrox/src/worker.rs",
        ] {
            let path = root.join(entry);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "//! Entrada da crate.\n").unwrap();
        }
        let leaf = root.join("crates/syrox-lang/src/helper.rs");
        fs::write(leaf, "fn helper() {}\n").unwrap();
        assert!(check(&root).unwrap().is_empty());
        fs::write(
            root.join("crates/syrox-lang/src/lib.rs"),
            "pub mod helper;\n",
        )
        .unwrap();
        let errors = check(&root).unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("explain the crate"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tests_do_not_justify_a_production_module_directory() {
        let directory =
            std::env::temp_dir().join(format!("syrox-structure-{}", std::process::id()));
        fs::create_dir_all(directory.join("tests")).unwrap();
        fs::write(directory.join("mod.rs"), "mod tests;").unwrap();
        fs::write(directory.join("tests/mod.rs"), "").unwrap();
        fs::write(directory.join("input_tests.rs"), "").unwrap();
        assert!(!production_child(&directory).unwrap());
        fs::write(directory.join("ownership.rs"), "").unwrap();
        fs::write(
            directory.join("mod.rs"),
            "mod tests; mod ownership;",
        )
        .unwrap();
        assert!(production_child(&directory).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_only_helpers_and_literal_modules_do_not_justify_a_directory() {
        assert_eq!(
            production_modules(
                r##"
            //! mod forged;
            /* nested /* mod fake; */ comment */
            const SOURCE: &str = r#"mod forged; { }"#;
            #[cfg(test)] mod arbitrary_fixture;
            #[cfg(all(test, target_os = "linux"))] mod host_fixture;
            #[cfg(all(target_os = "linux", test))] mod another_fixture;
            #[cfg(test)] mod tests { mod nested; }
            #[cfg(target_os = "linux")] pub(crate) mod retained;
        "##
            ),
            ["retained"]
        );
    }

    #[test]
    fn format_tags_are_rejected_outside_test_items() {
        let source = r##"
            // "syrox-comment-v1"
            const HEADER: &[u8] = b"syrox-header-v2\n";
            fn scope() -> String { format!("syrox-scope-v1:{}", 1) }
            const PROFILE: &str = r#"syrox-profile-x86_64-v3"#;
            const NAME: &str = "syrox-build-namespace";
            const UNIT: &str = "syrox-services-unit.service";
            const OTHER: &str = "prefix syrox-inline-v1";
            #[cfg(test)]
            const FIXTURE: &[u8] = b"syrox-fixture-v1\n";
            #[cfg(test)]
            #[allow(dead_code)]
            fn fixture() { let _ = "syrox-helper-v1"; }
            #[cfg(test)]
            mod tests { fn nested() { if true { "syrox-nested-v2"; } } }
            struct Record { #[cfg(test)] snapshot: Vec<u8>, name: String }
            impl Record { fn tag() -> &'static str { "syrox-record-v1" } }
            const AFTER: &str = "syrox-after-v4";
        "##;
        assert_eq!(
            format_literals(source),
            [
                "syrox-header-v2",
                "syrox-scope-v1",
                "syrox-profile-x86_64-v3",
                "syrox-record-v1",
                "syrox-after-v4"
            ]
        );
        for allowed in [
            "crates/syrox-encoding/src/formats.rs",
            "crates/syrox/tests/cli.rs",
            "crates/syrox-engine/src/store/tests.rs",
            "crates/syrox-engine/src/build/tests/cache/mod.rs",
            "crates/syrox-engine/src/build/bootstrap/linux/selected_input_tests.rs",
            "crates/syrox-engine/examples/verify_release.rs",
        ] {
            assert!(
                may_spell_format_tags(Path::new(allowed)),
                "{allowed}"
            );
        }
        assert!(!may_spell_format_tags(Path::new(
            "crates/syrox-engine/src/store/mod.rs"
        )));
    }
}
