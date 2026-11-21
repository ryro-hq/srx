use super::*;

#[test]
fn elf_inspection_reads_only_bounded_file_ranges() {
    let mut bytes = elf(
        3,
        None,
        &["libc.so.6"],
        Some("libsample.so"),
        None,
    );
    bytes.resize(8 * 1024 * 1024, 0);
    let expected = inspect(&bytes).unwrap();
    let mut read_bytes = 0;
    let actual = inspect_ranges(bytes.len(), |start, length| {
        read_bytes += length;
        Ok(checked(&bytes, start, length)?.to_vec())
    })
    .unwrap();
    assert_eq!(actual.needed, expected.needed);
    assert_eq!(actual.soname, expected.soname);
    assert!(read_bytes < 16 * 1024);
}

#[test]
fn static_elf_closure_is_retained_and_non_elf_is_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let app = retained(
        &store,
        "static",
        &elf(2, None, &[], None, None),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&app),
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    assert_eq!(
        closure.entry(),
        format!("/syrox/store/{}/out/bin/hello", app.action)
    );
    assert_eq!(
        crate::result::clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    drop(closure);
    assert!(store.maintenance().is_ok());
    let text = retained(&store, "text", b"hello", None);
    assert!(
        verify_runtime(
            &store,
            &RuntimeRequest {
                application: runtime_file(&text),
                loader: None,
                libraries: vec![]
            }
        )
        .is_err()
    );
}

#[test]
fn dynamic_elf_requires_exact_loader_and_transitive_libraries() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let loader = retained(
        &store,
        "loader",
        &elf(3, None, &[], None, None),
        None,
    );
    let path = format!("/syrox/store/{}/out/bin/hello", loader.action);
    let lib2 = retained(
        &store,
        "second",
        &elf(3, None, &[], None, None),
        Some((
            "libsecond.so.1",
            &elf(3, None, &[], Some("libsecond.so.1"), None),
        )),
    );
    let lib2_path = format!("/syrox/store/{}/out/usr/lib", lib2.action);
    let lib1 = retained(
        &store,
        "first",
        &elf(3, None, &[], None, None),
        Some((
            "libfirst.so.1",
            &elf(
                3,
                None,
                &["libsecond.so.1"],
                Some("libfirst.so.1"),
                Some(&lib2_path),
            ),
        )),
    );
    let lib1_path = format!("/syrox/store/{}/out/usr/lib", lib1.action);
    let app = retained(
        &store,
        "dynamic",
        &elf(
            3,
            Some(&path),
            &["libfirst.so.1"],
            None,
            Some(&lib1_path),
        ),
        None,
    );
    let mut request = RuntimeRequest {
        application: runtime_file(&app),
        loader: Some(runtime_file(&loader)),
        libraries: vec![output(&lib1)],
    };
    assert!(verify_runtime(&store, &request).is_err());
    request.libraries.push(output(&lib2));
    assert_eq!(
        verify_runtime(&store, &request)
            .unwrap()
            .libraries()
            .len(),
        2
    );
    request.loader = None;
    assert!(verify_runtime(&store, &request).is_err());
    request.loader = Some(runtime_file(&loader));
    let no_path = retained(
        &store,
        "no_path",
        &elf(3, Some(&path), &["libfirst.so.1"], None, None),
        None,
    );
    request.application = runtime_file(&no_path);
    assert!(verify_runtime(&store, &request).is_err());
    let host = retained(
        &store,
        "host",
        &elf(
            3,
            Some("/lib64/ld-linux-x86-64.so.2"),
            &["libc.so.6"],
            None,
            None,
        ),
        None,
    );
    request.application = runtime_file(&host);
    assert!(verify_runtime(&store, &request).is_err());
}

#[test]
fn identical_loader_and_library_roles_share_one_verified_view() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let provider = retained(
        &store,
        "shared_provider",
        &elf(3, None, &[], None, None),
        Some((
            "libshared.so.1",
            &elf(3, None, &[], Some("libshared.so.1"), None),
        )),
    );
    let prefix = format!("/syrox/store/{}/out", provider.action);
    let application = retained(
        &store,
        "shared_consumer",
        &elf(
            2,
            Some(&format!("{prefix}/bin/hello")),
            &["libshared.so.1"],
            None,
            Some(&format!("{prefix}/usr/lib")),
        ),
        None,
    );
    let request = RuntimeRequest {
        application: runtime_file(&application),
        loader: Some(runtime_file(&provider)),
        libraries: vec![output(&provider)],
    };
    let closure = verify_runtime(&store, &request).unwrap();
    assert!(
        closure
            .loader()
            .unwrap()
            .output
            .shares_directory(&closure.libraries()[0])
    );
    assert_eq!(closure.mounts().unwrap().len(), 2);
    drop(closure);

    let alias = RootName::new("shared_provider_alias").unwrap();
    let lease = store.operation().unwrap();
    let references = lease
        .build_references(&provider.root)
        .unwrap()
        .unwrap();
    lease.publish_root(&alias, &references).unwrap();
    drop(lease);
    let mut separately_authorized = request.clone();
    separately_authorized.libraries[0].root = alias;
    let closure = verify_runtime(&store, &separately_authorized).unwrap();
    assert!(
        !closure
            .loader()
            .unwrap()
            .output
            .shares_directory(&closure.libraries()[0])
    );
    drop(closure);

    crate::store::take_verified_read_bytes();
    verify_runtime(&store, &request).unwrap();
    let shared_bytes = crate::store::take_verified_read_bytes();
    verify_runtime(&store, &separately_authorized).unwrap();
    let separate_bytes = crate::store::take_verified_read_bytes();
    eprintln!("runtime_verified_bytes shared={shared_bytes} separate_roots={separate_bytes}");
    assert!(
        shared_bytes < separate_bytes,
        "shared={shared_bytes} separately_authorized={separate_bytes}"
    );
}

#[test]
fn installed_but_unreachable_module_needs_no_runpath_but_still_needs_a_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let loader = retained(
        &store,
        "module-loader",
        &elf(3, None, &[], None, None),
        None,
    );
    let loader_path = format!("/syrox/store/{}/out/bin/hello", loader.action);
    let libc = retained(
        &store,
        "module-libc",
        &elf(3, None, &[], None, None),
        Some((
            "libc.so.6",
            &elf(3, None, &[], Some("libc.so.6"), None),
        )),
    );
    let module = retained(
        &store,
        "unused-module",
        &elf(3, None, &[], None, None),
        Some((
            "liboptional.so.1",
            &elf(
                3,
                None,
                &["libc.so.6"],
                Some("liboptional.so.1"),
                None,
            ),
        )),
    );
    let path = format!("/syrox/store/{}/out/usr/lib", libc.action);
    let app = retained(
        &store,
        "module-app",
        &elf(
            3,
            Some(&loader_path),
            &["libc.so.6"],
            None,
            Some(&path),
        ),
        None,
    );
    let request = RuntimeRequest {
        application: runtime_file(&app),
        loader: Some(runtime_file(&loader)),
        libraries: vec![output(&libc), output(&module)],
    };
    assert!(verify_runtime(&store, &request).is_ok());
    let broken = retained(
        &store,
        "broken-module",
        &elf(3, None, &[], None, None),
        Some((
            "libbroken.so.1",
            &elf(
                3,
                None,
                &["libmissing.so.1"],
                Some("libbroken.so.1"),
                None,
            ),
        )),
    );
    let mut request = request;
    request.libraries.push(output(&broken));
    assert!(verify_runtime(&store, &request).is_err());
}

#[test]
fn soname_alias_is_resolved_without_duplicate_elf_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let loader = retained(
        &store,
        "loader-alias",
        &elf(3, None, &[], None, None),
        None,
    );
    let interpreter = format!("/syrox/store/{}/out/bin/hello", loader.action);
    let mut action = build::cache::tests::action();
    action.directory = "aliased-library".into();
    let library = build::cache::tests::retained_with_library_alias(
        &store.operation().unwrap(),
        &action,
        &elf(3, None, &[], None, None),
        "libanswer.so.1",
        "libanswer.so.1.2",
        &elf(3, None, &[], Some("libanswer.so.1"), None),
    );
    let runpath = format!("/syrox/store/{}/out/usr/lib", library.action);
    let app = retained(
        &store,
        "app-alias",
        &elf(
            3,
            Some(&interpreter),
            &["libanswer.so.1"],
            None,
            Some(&runpath),
        ),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&app),
            loader: Some(runtime_file(&loader)),
            libraries: vec![output(&library)],
        },
    )
    .unwrap();
    assert_eq!(closure.mounts().unwrap().len(), 3);
    let alias = closure.libraries()[0]
        .directory()
        .unwrap()
        .join("usr/lib/libanswer.so.1");
    assert!(fs::symlink_metadata(&alias).unwrap().is_file());
}

#[test]
fn library_direct_invocation_interpreter_and_extra_declared_provider_are_allowed() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let loader = retained(
        &store,
        "loader-independent",
        &elf(3, None, &[], None, None),
        None,
    );
    let loader_path = format!("/syrox/store/{}/out/bin/hello", loader.action);
    let library = retained(
        &store,
        "libc-like",
        &elf(3, None, &[], None, None),
        Some((
            "libordinary.so.1",
            &elf(
                3,
                Some("/lib64/ld-linux-x86-64.so.2"),
                &[],
                Some("libordinary.so.1"),
                None,
            ),
        )),
    );
    let extra = retained(
        &store,
        "extra-declared",
        &elf(3, None, &[], None, None),
        Some((
            "libextra.so.1",
            &elf(3, None, &[], Some("libextra.so.1"), None),
        )),
    );
    let app = retained(
        &store,
        "program",
        &elf(
            3,
            Some(&loader_path),
            &["libordinary.so.1"],
            None,
            Some(&format!(
                "/syrox/store/{}/out/usr/lib:/syrox/store/{}/out/usr/lib",
                library.action, extra.action
            )),
        ),
        None,
    );
    let request = RuntimeRequest {
        application: runtime_file(&app),
        loader: Some(runtime_file(&loader)),
        libraries: vec![output(&library), output(&extra)],
    };
    assert!(verify_runtime(&store, &request).is_ok());
    let missing = RuntimeRequest {
        libraries: vec![output(&extra)],
        ..request
    };
    assert!(verify_runtime(&store, &missing).is_err());
}

#[test]
fn loader_soname_may_be_supplied_by_its_separate_output() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut action = build::cache::tests::action();
    action.directory = "standalone-loader".into();
    let loader = build::cache::tests::retained_at(
        &store.operation().unwrap(),
        &action,
        "usr/lib/ld-linux-x86-64.so.2",
        &elf(3, None, &[], Some("ld-linux-x86-64.so.2"), None),
    );
    let interpreter = format!(
        "/syrox/store/{}/out/usr/lib/ld-linux-x86-64.so.2",
        loader.action
    );
    let libc = retained(
        &store,
        "separate-libc",
        &elf(3, None, &[], None, None),
        Some((
            "libc.so.6",
            &elf(
                3,
                Some(&interpreter),
                &["ld-linux-x86-64.so.2"],
                Some("libc.so.6"),
                None,
            ),
        )),
    );
    let runpath = format!("/syrox/store/{}/out/usr/lib", libc.action);
    let app = retained(
        &store,
        "separate-app",
        &elf(
            3,
            Some(&interpreter),
            &["libc.so.6"],
            None,
            Some(&runpath),
        ),
        None,
    );
    let request = RuntimeRequest {
        application: runtime_file(&app),
        loader: Some(RuntimeFile {
            output: output(&loader),
            path: "usr/lib/ld-linux-x86-64.so.2".into(),
        }),
        libraries: vec![output(&libc)],
    };
    let cancellation = crate::cancellation::Cancellation::default();
    let closure = verify_runtime(&store, &request).unwrap();
    let retained = RetainedRuntime {
        application: RuntimeFile {
            output: closure
                .application()
                .output
                .retain(
                    &RootName::new("generation_app").unwrap(),
                    &cancellation,
                )
                .unwrap(),
            path: closure.application().path.as_str().to_owned(),
        },
        loader: Some(RuntimeFile {
            output: closure
                .loader()
                .unwrap()
                .output
                .retain(
                    &RootName::new("generation_loader").unwrap(),
                    &cancellation,
                )
                .unwrap(),
            path: closure
                .loader()
                .map(|file| file.path.as_str())
                .unwrap()
                .to_owned(),
        }),
        libraries: vec![
            closure.libraries()[0]
                .retain(
                    &RootName::new("generation_libc").unwrap(),
                    &cancellation,
                )
                .unwrap(),
        ],
    };
    drop(closure);
    {
        let mut maintenance = store.maintenance().unwrap();
        crate::result::clear_materializations(&mut maintenance).unwrap();
        let report = maintenance
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                remove_roots: vec![app.root, loader.root, libc.root],
                limits: crate::store::GcLimits::default(),
            })
            .unwrap();
        assert!(report.removed_objects.is_empty());
    }
    let closure = retained.open(&store, &cancellation).unwrap();
    assert_eq!(closure.mounts().unwrap().len(), 3);
    assert_eq!(
        crate::result::clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    let mut invalid = retained.clone();
    invalid.libraries[0].identity.action = ContentDigest::sha256(b"wrong");
    assert!(invalid.open(&store, &cancellation).is_err());
    let mut invalid = retained.clone();
    invalid.loader.as_mut().unwrap().output.root = RootName::new("not_retained").unwrap();
    assert!(invalid.open(&store, &cancellation).is_err());
    let mut invalid = retained.clone();
    invalid.libraries.clear();
    assert!(invalid.open(&store, &cancellation).is_err());
}

#[test]
fn elf_inspection_refuses_truncated_and_unsafe_metadata_without_execution() {
    let good = elf(
        3,
        Some("/syrox/store/placeholder/out/bin/ld"),
        &["liba.so"],
        None,
        Some("/syrox/store/placeholder/out/usr/lib"),
    );
    assert_eq!(inspect(&good).unwrap().needed, vec!["liba.so"]);
    for end in [0, 48, 120, 0x310] {
        assert!(inspect(&good[..end]).is_err());
    }
    assert!(inspect(&elf(3, None, &["../host.so"], None, None)).is_err());
    assert_eq!(
        inspect(&elf(3, Some("/lib/ld-linux.so"), &[], None, None))
            .unwrap()
            .interpreter
            .as_deref(),
        Some("/lib/ld-linux.so")
    );
}

#[test]
fn elf_large_dynstr_is_bounded_by_file_and_each_name_not_64_kib() {
    let mut bytes = elf(3, None, &["libanswer.so.1"], None, None);
    bytes.resize(0x20300, 0);
    let length = bytes.len() as u64;
    bytes[64 + 32..64 + 40].copy_from_slice(&length.to_le_bytes());
    bytes[64 + 40..64 + 48].copy_from_slice(&length.to_le_bytes());
    // Dynamic entries: NEEDED, STRTAB, STRSZ, NULL.
    bytes[0x228..0x230].copy_from_slice(&(0x20000_u64).to_le_bytes());
    assert_eq!(
        inspect(&bytes).unwrap().needed,
        ["libanswer.so.1"]
    );
    bytes[0x228..0x230].copy_from_slice(&(length + 1).to_le_bytes());
    assert!(inspect(&bytes).is_err());
}
