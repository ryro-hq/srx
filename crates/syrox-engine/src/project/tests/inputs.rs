use super::*;

fn run_with_low_descriptor_limit(test_name: &str, marker: &str) {
    let executable = crate::reexec_test_executable(test_name, false);
    let output = Command::new("sh")
        .args([
            "-c",
            "ulimit -n 32 && exec \"$1\" --exact \"$2\" --nocapture",
            "sh",
        ])
        .arg(executable)
        .arg(test_name)
        .env(marker, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "low-descriptor child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    crate::assert_reexec_result(&output.stdout, test_name);
}

#[test]
fn source_is_rejected_after_reading_one_byte_beyond_the_limit() {
    let input = vec![b'x'; MAX_SOURCE_BYTES + 1];
    let error = read_source(Cursor::new(input), Path::new("large.srx")).unwrap_err();
    assert!(matches!(error, CheckFailure::TooLarge { .. }));
}

#[test]
fn project_merges_input_files_in_deterministic_relative_order() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write(
        "dep/z.srx",
        "mod shared { struct Item { name: Name; } }",
    );
    project.write("dep/a.srx", "mod shared { value Name(str); }");

    let report = check_project(&project.0).unwrap();
    assert_eq!(report.declarations, 3);

    project.write("dep/z.srx", "mod shared { value Name(str); }");
    let CheckFailure::Diagnostics {
        input,
        errors,
    } = check_project(&project.0).unwrap_err()
    else {
        panic!("expected duplicate declaration diagnostic");
    };
    let duplicate = errors
        .iter()
        .find(|error| error.message == "duplicate item declaration in module")
        .unwrap();
    assert_eq!(
        input
            .get(duplicate.span.source_id())
            .unwrap()
            .name(),
        "dep/z.srx"
    );
}

#[test]
fn syntax_errors_do_not_cross_file_boundaries() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("dep/a.srx", "mod shared {");
    project.write("dep/b.srx", "}");

    let CheckFailure::Diagnostics {
        errors,
        ..
    } = check_project(&project.0).unwrap_err()
    else {
        panic!("expected syntax diagnostics");
    };
    assert!(errors.len() >= 2);
}

#[test]
fn project_rejects_unsafe_and_unsupported_locators() {
    for (locator, expected) in [
        ("path:../../outside", "relative"),
        ("https:example.invalid", "unsupported locator"),
    ] {
        let project = TempProject::new();
        project.write(
            "main.srx",
            &format!("inputs {{ dep = \"{locator}\"; }}"),
        );
        assert!(
            check_project(&project.0)
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
    }
}

#[test]
fn locator_overlap_is_rejected_before_input_roots_are_opened() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "inputs { missing = \"path:missing\"; nested = \"path:missing/nested\"; }",
    );

    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::AliasedInputPaths { .. }
    ));
}

#[cfg(unix)]
#[test]
fn project_rejects_symlinked_inputs_and_files() {
    use std::os::unix::fs::symlink;

    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("real/source.srx", "value V(str);");
    symlink(project.0.join("real"), project.0.join("dep")).unwrap();
    let error = check_project(&project.0).unwrap_err();
    assert!(
        matches!(error, CheckFailure::SymbolicLink { .. }),
        "{error:?}"
    );

    fs::remove_file(project.0.join("dep")).unwrap();
    fs::create_dir(project.0.join("dep")).unwrap();
    symlink(
        project.0.join("real/source.srx"),
        project.0.join("dep/source.srx"),
    )
    .unwrap();
    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::SymbolicLink { .. }
    ));

    fs::remove_file(project.0.join("dep/source.srx")).unwrap();
    fs::remove_file(project.0.join("main.srx")).unwrap();
    symlink(
        project.0.join("real/source.srx"),
        project.0.join("main.srx"),
    )
    .unwrap();
    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::SymbolicLink { .. }
    ));
}

#[test]
fn traversal_keeps_using_the_opened_directory_after_a_path_swap() {
    use std::os::unix::fs::symlink;

    let project = TempProject::new();
    project.write("main.srx", "value Main(str);");
    project.write("dep/source.srx", "value Original(str);");
    project.write(
        "replacement/source.srx",
        "value Replacement(str);",
    );

    let mut budget = LoadBudget::new(ProjectLimits::default());
    let project_handle = open_top(&project.0, &mut budget).unwrap();
    let dep_path = project.0.join("dep");
    let dep = open_beneath(
        project_handle.fd(),
        Path::new("dep"),
        &dep_path,
        true,
        &mut budget,
    )
    .unwrap();
    let root = InputRoot {
        name: "dep".to_owned(),
        relative: PathBuf::from("dep"),
        opened: dep,
    };
    let mut directories = HashMap::new();
    directories.insert(identity(&project_handle), project.0.clone());
    directories.insert(identity(&root.opened), dep_path.clone());

    fs::rename(&dep_path, project.0.join("original-dep")).unwrap();
    symlink(project.0.join("replacement"), &dep_path).unwrap();
    let files = walk_input(
        &project.0,
        root,
        &mut directories,
        &mut HashMap::new(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].1.contains("Original"));

    fs::remove_file(&dep_path).unwrap();
    fs::rename(project.0.join("original-dep"), dep_path).unwrap();
}

#[test]
fn reopened_descendant_must_match_its_discovered_identity() {
    let project = TempProject::new();
    fs::create_dir_all(project.0.join("dep/child")).unwrap();
    fs::create_dir_all(project.0.join("replacement")).unwrap();

    let mut budget = LoadBudget::new(ProjectLimits::default());
    let project_handle = open_top(&project.0, &mut budget).unwrap();
    let dep_path = project.0.join("dep");
    let dep = open_beneath(
        project_handle.fd(),
        Path::new("dep"),
        &dep_path,
        true,
        &mut budget,
    )
    .unwrap();
    let child = open_beneath(
        dep.fd(),
        Path::new("child"),
        &dep_path.join("child"),
        true,
        &mut budget,
    )
    .unwrap();
    let expected = identity(&child);
    drop(child);

    fs::rename(
        dep_path.join("child"),
        project.0.join("original-child"),
    )
    .unwrap();
    fs::rename(
        project.0.join("replacement"),
        dep_path.join("child"),
    )
    .unwrap();

    assert!(matches!(
        reopen_directory(
            dep.fd(),
            Path::new("child"),
            &dep_path.join("child"),
            expected,
            &mut budget,
        ),
        Err(CheckFailure::Inspect { .. })
    ));
}

#[test]
fn traversal_does_not_retain_sibling_directory_descriptors() {
    const MARKER: &str = "SYROX_TEST_LOW_FD_SIBLINGS";
    if std::env::var_os(MARKER).is_none() {
        run_with_low_descriptor_limit(
            "project::tests::inputs::traversal_does_not_retain_sibling_directory_descriptors",
            MARKER,
        );
        return;
    }

    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    for index in 0..64 {
        fs::create_dir_all(project.0.join(format!("dep/child-{index:02}"))).unwrap();
    }
    check_project(&project.0).unwrap();
}

#[test]
fn project_does_not_retain_all_input_root_descriptors() {
    const MARKER: &str = "SYROX_TEST_LOW_FD_ROOTS";
    if std::env::var_os(MARKER).is_none() {
        run_with_low_descriptor_limit(
            "project::tests::inputs::project_does_not_retain_all_input_root_descriptors",
            MARKER,
        );
        return;
    }

    let project = TempProject::new();
    let mut main = String::from("inputs {");
    for index in 0..64 {
        write!(main, " dep{index} = \"path:dep{index}\";").unwrap();
        fs::create_dir(project.0.join(format!("dep{index}"))).unwrap();
    }
    main.push_str(" }");
    project.write("main.srx", &main);
    check_project(&project.0).unwrap();
}

#[test]
fn hard_linked_sources_cannot_receive_distinct_domain_authority() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "inputs { first = \"path:first\"; second = \"path:second\"; }",
    );
    project.write("first/source.srx", "value V(str);");
    fs::create_dir(project.0.join("second")).unwrap();
    fs::hard_link(
        project.0.join("first/source.srx"),
        project.0.join("second/source.srx"),
    )
    .unwrap();

    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::AliasedSourceFiles { .. }
    ));
}

#[test]
fn unavailable_openat2_is_never_mapped_to_a_path_fallback() {
    assert!(matches!(
        open_error(
            Path::new("project"),
            OpenError::Unsupported(io::Error::other("openat2 unavailable")),
        ),
        CheckFailure::UnsupportedKernel { .. }
    ));
}
