use std::{fs, path::Path, process::Command};

#[test]
fn language_reference_examples_are_formatted_and_checked() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let reference = fs::read_to_string(root.join("docs/language.md")).unwrap();
    let mut examples = fs::read_dir(root.join("examples/language"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    examples.sort();
    assert!(!examples.is_empty());
    for path in examples {
        let source = fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        let marker = format!("<!-- example: {name} -->\n\n```srx\n{source}```");
        assert!(
            reference.contains(&marker),
            "reference drifted from {name}"
        );
        for arguments in [["fmt", "--check"], ["project", "check"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_srx"))
                .args(arguments)
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
