use super::*;
use crate::build::{self, BuildResult};
use std::fs;
use std::process::{Command, Stdio};

mod managed_terminal;

pub(crate) fn elf(
    kind: u16,
    interpreter: Option<&str>,
    needed: &[&str],
    soname: Option<&str>,
    runpath: Option<&str>,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&kind.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(
        &(if interpreter.is_some() {
            3_u16
        } else {
            2_u16
        })
        .to_le_bytes(),
    );
    let ph = 64;
    bytes[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x400_u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x400_u64.to_le_bytes());
    let ph = ph + 56;
    bytes[ph..ph + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0x200_u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(
        &((needed.len() + usize::from(soname.is_some()) + usize::from(runpath.is_some()) + 3)
            as u64
            * 16)
            .to_le_bytes(),
    );
    if let Some(path) = interpreter {
        let ph = ph + 56;
        bytes[ph..ph + 4].copy_from_slice(&3_u32.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&0x180_u64.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&((path.len() + 1) as u64).to_le_bytes());
        bytes[0x180..0x180 + path.len()].copy_from_slice(path.as_bytes());
    }
    let mut cursor = 0x300;
    let mut tags = Vec::new();
    for name in needed {
        tags.push((1_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len() + 1;
    }
    if let Some(name) = soname {
        tags.push((14_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len() + 1;
    }
    if let Some(path) = runpath {
        tags.push((29_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + path.len()].copy_from_slice(path.as_bytes());
        cursor += path.len() + 1;
    }
    tags.push((5, 0x0040_0300));
    tags.push((10, (cursor - 0x300) as u64));
    for (n, (tag, value)) in tags.into_iter().enumerate() {
        let at = 0x200 + n * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn retained(
    store: &Store,
    name: &str,
    bytes: &[u8],
    library: Option<(&str, &[u8])>,
) -> BuildResult {
    let lease = store.operation().unwrap();
    let mut action = build::cache::tests::action();
    action.directory = name.to_owned();
    if let Some((soname, content)) = library {
        build::cache::tests::retained_with_library(&lease, &action, bytes, soname, content)
    } else {
        build::cache::tests::retained(&lease, &action, bytes)
    }
}

fn output(result: &BuildResult) -> RuntimeOutput {
    RuntimeOutput {
        root: result.root.clone(),
        receipt: result.receipt,
        output: "out".into(),
    }
}

fn runtime_file(result: &BuildResult) -> RuntimeFile {
    RuntimeFile {
        output: output(result),
        path: "bin/hello".into(),
    }
}
fn materialized_file(
    output: MaterializedArtifact,
    path: &str,
) -> RuntimeFile<MaterializedArtifact> {
    RuntimeFile {
        output,
        path: path.to_owned(),
    }
}

#[test]
fn cancellation_before_runtime_launch_has_a_distinct_error() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let app = retained(
        &store,
        "prelaunch",
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
    let cancellation = crate::cancellation::Cancellation::default();
    cancellation.cancel();
    assert!(matches!(
        verify_runtime_with_cancellation(
            &store,
            &RuntimeRequest {
                application: runtime_file(&app),
                loader: None,
                libraries: vec![]
            },
            &cancellation,
        ),
        Err(RuntimeError::Cancelled)
    ));
    assert!(matches!(
        run_runtime_with_cancellation(&closure, &[], temporary.path(), &cancellation),
        Err(RuntimeError::Cancelled)
    ));
}

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

/// A real kernel/namespace proof, deliberately separate from synthetic ELF
/// metadata tests. Run on a configured Linux `x86_64` host with GCC and the worker.
#[test]
#[ignore = "requires syrox-worker beside the test profile directory, user namespaces and static GCC"]
fn host_static_runtime_mounts_only_the_verified_output_and_preserves_cwd() {
    let temporary = tempfile::tempdir().unwrap();
    let source = r#"
        #include <unistd.h>
        #include <string.h>
        #include <limits.h>
        #include <errno.h>
        #include <linux/capability.h>
        #include <sys/prctl.h>
        #include <sys/syscall.h>
        int main(int argc, char **argv) {
            char cwd[PATH_MAX];
            if (argc != 4 || access(argv[1], R_OK) != 0) return 10;
            if (getcwd(cwd, sizeof(cwd)) == 0 || strcmp(cwd, argv[2]) != 0) return 13;
            if (access("input", R_OK) != 0) return 11;
            if (access("/usr", F_OK) == 0) return 12;
            if (access(argv[3], F_OK) == 0) return 14;
            struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
            struct __user_cap_data_struct caps[2] = {0};
            if (syscall(SYS_capget, &header, caps)) return 15;
            for (int n = 0; n < 2; ++n)
                if (caps[n].effective || caps[n].permitted || caps[n].inheritable) return 16;
            if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 17;
            for (int cap = 0; cap < 1024; ++cap) {
                int bit = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
                if (bit < 0) return errno == EINVAL && cap > 0 ? 37 : 18;
                if (bit != 0) return 19;
            }
            return 20;
        }
    "#;
    let binary = temporary.path().join("static-program");
    let mut compiler = Command::new("gcc")
        .args(["-static", "-x", "c", "-o"])
        .arg(&binary)
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    assert!(compiler.wait().unwrap().success());
    let store_path = temporary.path().join("store");
    fs::create_dir(&store_path).unwrap();
    let store = Store::open(&store_path).unwrap();
    let app = retained(
        &store,
        "static-host",
        &fs::read(binary).unwrap(),
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
    let cancellation = crate::cancellation::Cancellation::default();
    let retained = RetainedRuntime {
        application: RuntimeFile {
            output: closure
                .application()
                .output
                .retain(
                    &RootName::new("service_generation_1").unwrap(),
                    &cancellation,
                )
                .unwrap(),
            path: closure.application().path.as_str().to_owned(),
        },
        loader: None,
        libraries: vec![],
    };
    drop(closure);
    {
        let mut maintenance = store.maintenance().unwrap();
        crate::result::clear_materializations(&mut maintenance).unwrap();
        maintenance
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                remove_roots: vec![app.root],
                limits: crate::store::GcLimits::default(),
            })
            .unwrap();
    }
    let closure = retained.open(&store, &cancellation).unwrap();
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    fs::write(cwd.join("input"), b"cwd remains visible").unwrap();
    let entry = closure.entry();
    assert_eq!(closure.mounts().unwrap().len(), 1);
    let result = run_runtime(
        &closure,
        &[
            entry.into(),
            cwd.as_os_str().to_owned(),
            store_path.join("roots").into_os_string(),
        ],
        &cwd,
    )
    .unwrap();
    assert_eq!(result.code(), Some(37));
    fs::write(
        temporary.path().join("input"),
        b"parent is writable",
    )
    .unwrap();
    let parent_status = run_runtime(
        &closure,
        &[
            temporary.path().join("input").into_os_string(),
            temporary.path().as_os_str().to_owned(),
            store_path.join("roots").into_os_string(),
        ],
        temporary.path(),
    )
    .unwrap();
    assert_eq!(
        parent_status.code(),
        Some(37),
        "Store must be masked from a parent cwd"
    );
    assert!(run_runtime(&closure, &[], &store_path).is_err());
    assert_eq!(
        crate::result::clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    drop(closure);
    assert!(store.maintenance().is_ok());
    assert!(!temporary.path().join("syrox").exists());
}

fn compile(source: &str, output: &std::path::Path, options: &[&str]) {
    let mut compiler = Command::new("gcc")
        .args(["-x", "c", "-"])
        .args(options)
        .arg("-o")
        .arg(output)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    assert!(compiler.wait().unwrap().success());
}

#[test]
#[ignore = "requires syrox-worker, user namespaces, GCC and a Linux x86_64 bootstrap loader"]
fn host_dynamic_runtime_uses_only_declared_loader_and_library() {
    let temporary = tempfile::tempdir().unwrap();
    let store_path = temporary.path().join("store");
    fs::create_dir(&store_path).unwrap();
    let store = Store::open(&store_path).unwrap();
    // Explicitly copy a host loader into a retained fixture output: this is
    // bootstrap provenance for a host proof, not a portable toolchain claim.
    let loader = fs::read("/lib64/ld-linux-x86-64.so.2").unwrap();
    let loader = retained(&store, "bootstrap-loader", &loader, None);
    let shared = temporary.path().join("libanswer.so.1");
    compile(
        "int answer(void) { return 37; }",
        &shared,
        &[
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-Wl,-soname,libanswer.so.1",
        ],
    );
    let library = retained(
        &store,
        "bootstrap-library",
        &elf(3, None, &[], None, None),
        Some(("libanswer.so.1", &fs::read(&shared).unwrap())),
    );
    let interpreter = format!("/syrox/store/{}/out/bin/hello", loader.action);
    let runpath = format!("/syrox/store/{}/out/usr/lib", library.action);
    let binary = temporary.path().join("dynamic-program");
    let source = r#"
        extern int answer(void);
        __attribute__((noreturn)) void _start(void) {
            long code = answer();
            __asm__ volatile("mov $60, %%rax; mov %0, %%rdi; syscall"
                : : "r"(code) : "rax", "rdi", "rcx", "r11", "memory");
            __builtin_unreachable();
        }
    "#;
    compile(
        source,
        &binary,
        &[
            "-nostdlib",
            "-no-pie",
            "-Wl,-e,_start",
            &format!("-Wl,--dynamic-linker={interpreter}"),
            &format!("-Wl,-rpath={runpath}"),
            &format!("-L{}", temporary.path().display()),
            "-l:libanswer.so.1",
        ],
    );
    let app = retained(
        &store,
        "dynamic-host",
        &fs::read(binary).unwrap(),
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
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    assert_eq!(
        run_runtime(&closure, &[], temporary.path())
            .unwrap()
            .code(),
        Some(37)
    );
    let status = run_runtime(&closure, &[], &cwd).unwrap();
    assert_eq!(status.code(), Some(37));
    assert_eq!(
        crate::result::clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
}

#[test]
#[ignore = "requires SYROX_SOURCE_BUILT_GLIBC_OUTPUT pointing to a source-built x86_64 glibc install, GCC and rootless Bubblewrap"]
fn source_built_glibc_loader_and_libc_run_from_separate_retained_outputs() {
    let installed = std::env::var_os("SYROX_SOURCE_BUILT_GLIBC_OUTPUT")
        .expect("set SYROX_SOURCE_BUILT_GLIBC_OUTPUT to the glibc install's out directory");
    let installed = PathBuf::from(installed);
    let library = fs::read(installed.join("usr/lib/libc.so.6")).unwrap();
    let loader_bytes = fs::read(installed.join("usr/lib/ld-linux-x86-64.so.2")).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let store_path = temporary.path().join("store");
    fs::create_dir(&store_path).unwrap();
    let store = Store::open(&store_path).unwrap();
    let mut action = build::cache::tests::action();
    action.directory = "loader-from-source".into();
    let loader = build::cache::tests::retained_at(
        &store.operation().unwrap(),
        &action,
        "usr/lib/ld-linux-x86-64.so.2",
        &loader_bytes,
    );
    let libc = retained(
        &store,
        "libc-from-source",
        &elf(3, None, &[], None, None),
        Some(("libc.so.6", &library)),
    );
    let interpreter = format!(
        "/syrox/store/{}/out/usr/lib/ld-linux-x86-64.so.2",
        loader.action
    );
    let runpath = format!("/syrox/store/{}/out/usr/lib", libc.action);
    let binary = temporary.path().join("application");
    compile(
        "int main(void) { return 37; }",
        &binary,
        &[
            &format!("-Wl,--dynamic-linker={interpreter}"),
            &format!("-Wl,-rpath={runpath}"),
        ],
    );
    let app = retained(
        &store,
        "source-runtime-app",
        &fs::read(binary).unwrap(),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&app),
            loader: Some(RuntimeFile {
                output: output(&loader),
                path: "usr/lib/ld-linux-x86-64.so.2".into(),
            }),
            libraries: vec![output(&libc)],
        },
    )
    .unwrap();
    assert_eq!(closure.mounts().unwrap().len(), 3);
    assert_eq!(
        run_runtime(&closure, &[], temporary.path())
            .unwrap()
            .code(),
        Some(37)
    );
}

#[test]
#[ignore = "requires syrox-worker, user namespaces and a host static compiler"]
fn host_session_ends_descendants_before_the_store_lease_can_be_released() {
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("fork-program");
    compile(
        r#"
        #include <unistd.h>
        #include <fcntl.h>
        int main(void) {
            int ready[2];
            if (pipe(ready)) return 10;
            int child = fork();
            if (child < 0) return 11;
            if (child == 0) {
                close(ready[0]);
                if (write(ready[1], "x", 1) != 1) return 12;
                close(ready[1]);
                sleep(1);
                int fd = open("late", O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (fd >= 0) close(fd);
                return 0;
            }
            close(ready[1]);
            char signal;
            if (read(ready[0], &signal, 1) != 1) return 13;
            return 37;
        }
    "#,
        &binary,
        &["-static"],
    );
    let store_path = temporary.path().join("store");
    fs::create_dir(&store_path).unwrap();
    let store = Store::open(&store_path).unwrap();
    let app = retained(
        &store,
        "descendants-host",
        &fs::read(binary).unwrap(),
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
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    assert_eq!(
        run_runtime(&closure, &[], &cwd).unwrap().code(),
        Some(37)
    );
    assert_eq!(
        crate::result::clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    drop(closure);
    assert!(store.maintenance().is_ok());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        !cwd.join("late").exists(),
        "a descendant survived the PID-namespace session"
    );
}

#[test]
fn namespace_info_wait_observes_cancellation_without_message() {
    let (info, _writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(60));
            cancellation.cancel();
        });
        assert!(matches!(
            receive_namespace(info.as_fd(), &cancellation),
            Err(RuntimeError::Cancelled)
        ));
    });
}

/// Keep test subprocesses bounded even when an assertion or IPC operation fails.
struct ReapedTestChild(Child);
impl Drop for ReapedTestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn native_namespace_rejects_regular_file_descriptor() {
    let (info, writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    crate::platform::linux::fd::send_fd(writer.as_fd(), file.as_fd()).unwrap();
    assert!(matches!(
        receive_namespace(
            info.as_fd(),
            &crate::cancellation::Cancellation::default()
        ),
        Err(RuntimeError::Io(_))
    ));
}

#[test]
fn failed_gate_release_leaves_pinned_process_available_for_settlement() {
    let (info, writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
    let (mut gate, reader) = UnixStream::pair().unwrap();
    drop(reader);
    let child = ReapedTestChild(
        Command::new("/usr/bin/sleep")
            .arg("10")
            .spawn()
            .unwrap(),
    );
    let pinned = crate::platform::linux::fd::pidfd_open(child.0.id()).unwrap();
    crate::platform::linux::fd::send_fd(writer.as_fd(), pinned.as_fd()).unwrap();
    let mut namespace = None;
    let error = prepare_namespace(
        info.as_fd(),
        &mut gate,
        &crate::cancellation::Cancellation::default(),
        &mut namespace,
        || {},
    )
    .unwrap_err();
    assert!(matches!(error, RuntimeError::Io(_)));
    let pinned = namespace.unwrap();
    crate::platform::linux::fd::kill_pidfd(pinned.as_fd()).unwrap();
    crate::platform::linux::fd::wait_pidfd(pinned.as_fd()).unwrap();
}

#[test]
#[ignore = "requires the release syrox-worker binary, Linux user namespaces and static GCC"]
fn native_runtime_refuses_eof_invalid_authorization_and_coordinator_loss() {
    for case in 0..6 {
        native_gate_case(case);
    }
}

#[test]
#[ignore = "requires syrox-worker, Linux user namespaces and static GCC"]
fn native_cancellation_before_pin_prevents_payload() {
    native_gate_case(6);
}

#[test]
#[ignore = "requires syrox-worker, Linux user namespaces and static GCC"]
fn native_cancellation_after_pin_prevents_payload_and_settles() {
    native_gate_case(7);
}

#[allow(unsafe_code)] // Keep native gate case assertions and their retained fixtures in one cleanup scope.
fn native_gate_case(case: u8) {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("retention-store")).unwrap();
    let output_directory = temporary.path().join("payload");
    fs::create_dir(&output_directory).unwrap();
    let binary = output_directory.join("gated-native");
    let output_prefix = format!("/syrox/store/{}/out", "a".repeat(64));
    compile(
        r#"#include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            int fd = open("ran", O_WRONLY | O_CREAT, 0600);
            if (fd >= 0) close(fd);
            return 0;
        }"#,
        &binary,
        &["-static"],
    );
    let helper = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("syrox-worker");
    {
        let (control, monitor_control) = UnixStream::pair().unwrap();
        let (info, info_writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
        let (mut gate, gate_reader) = UnixStream::pair().unwrap();
        let mut command = Command::new(&helper);
        let retention = empty_process_interest(&store);
        crate::platform::linux::fd::pass_fd_to_child(&mut command, retention.as_raw_fd());
        command.args(["__runtime", "monitor"]);
        for fd in [
            monitor_control.as_raw_fd(),
            info_writer.as_raw_fd(),
            gate_reader.as_raw_fd(),
        ] {
            command.arg(fd.to_string());
            crate::platform::linux::fd::pass_fd_to_child(&mut command, fd);
        }
        let working_fd = fs::File::open(temporary.path()).unwrap();
        let output_fd = fs::File::open(&output_directory).unwrap();
        for file in [&working_fd, &output_fd] {
            crate::platform::linux::fd::pass_fd_to_child(&mut command, file.as_raw_fd());
        }
        command
            .arg("--ro")
            .arg(format!("/proc/self/fd/{}", output_fd.as_raw_fd()))
            .arg(&output_prefix);
        command
            .arg("--rw")
            .arg(format!(
                "/proc/self/fd/{}",
                working_fd.as_raw_fd()
            ))
            .arg(temporary.path());
        if case == 5 {
            command.args(["--mask", "relative-invalid-target"]);
        }
        command
            .arg("--cwd")
            .arg(temporary.path())
            .arg("--")
            .arg(format!("{output_prefix}/gated-native"));
        let mut monitor = ReapedTestChild(command.spawn().unwrap());
        drop(retention);
        drop((monitor_control, info_writer, gate_reader));
        if case == 4 {
            // Lose the coordinator before consuming the kernel-pinned message.
            control
                .shutdown(std::net::Shutdown::Both)
                .unwrap();
        }
        if case >= 6 {
            let cancellation = crate::cancellation::Cancellation::default();
            if case == 6 {
                // A message is waiting, but the coordinator has not received it.
                let mut event = libc::pollfd {
                    fd: info.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one initialized poll entry borrows the live info socket.
                assert_eq!(
                    unsafe { libc::poll(&raw mut event, 1, 10_000) },
                    1
                );
                assert_ne!(event.revents & libc::POLLIN, 0);
                cancellation.cancel();
            }
            let mut namespace = None;
            let error = prepare_namespace(
                info.as_fd(),
                &mut gate,
                &cancellation,
                &mut namespace,
                || {
                    if case == 7 {
                        cancellation.cancel();
                    }
                },
            )
            .unwrap_err();
            assert_eq!(namespace.is_some(), case == 7);
            assert!(matches!(
                abort_launch(
                    || monitor.0.wait(),
                    namespace.as_ref(),
                    control,
                    gate,
                    error
                ),
                RuntimeError::Cancelled
            ));
            assert!(monitor.0.try_wait().unwrap().is_some());
            assert_eq!(collected_process_interests(&store), 1);
            assert!(!temporary.path().join("ran").exists());
            return;
        }
        let pinned = receive_namespace(
            info.as_fd(),
            &crate::cancellation::Cancellation::default(),
        )
        .unwrap();
        if case < 4 {
            assert_eq!(collected_process_interests(&store), 0);
        }
        match case {
            0 => drop(gate), // EOF must never authorize a payload.
            1 => {
                gate.write_all(b"!").unwrap();
                drop(gate);
            }
            2 | 4 => {
                control
                    .shutdown(std::net::Shutdown::Both)
                    .unwrap();
                drop(gate);
            }
            3 => {
                monitor.0.kill().unwrap();
                drop(gate);
            }
            5 => {
                drop(gate);
            }
            _ => unreachable!(),
        }
        assert!(!monitor.0.wait().unwrap().success());
        crate::platform::linux::fd::wait_pidfd(pinned.as_fd()).unwrap();
        assert_eq!(collected_process_interests(&store), 1);
        assert!(
            !temporary.path().join("ran").exists(),
            "unauthorized payload in case {case}"
        );
    }
}

#[test]
#[ignore = "requires syrox-worker, user namespaces and host static GCC"]
fn host_runtime_cancellation_settles_before_releasing_retention() {
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("sleeper");
    compile(
        r#"#include <unistd.h>
        #include <fcntl.h>
        int main(void) {
            int ready = open("ready", O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (ready < 0) return 1;
            close(ready);
            sleep(1);
            int late = open("late", O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (late >= 0) close(late);
            return 0;
        }"#,
        &binary,
        &["-static"],
    );
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let result = retained(
        &store,
        "cancelled-host",
        &fs::read(&binary).unwrap(),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&result),
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let start = Instant::now();
            while !cwd.join("ready").exists() && start.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                cwd.join("ready").exists(),
                "runtime never reached the payload"
            );
            cancellation.cancel();
        });
        assert!(
            !run_runtime_with_cancellation(&closure, &[], &cwd, &cancellation)
                .unwrap()
                .success()
        );
    });
    assert_eq!(
        crate::result::clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    drop(closure);
    assert!(store.maintenance().is_ok());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!cwd.join("late").exists());
}

#[test]
#[ignore = "requires syrox-worker, user namespaces and a host static compiler"]
fn namespace_descendants_are_exited_at_return_not_merely_eventually() {
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("fork-many");
    compile(
        r#"#include <stdio.h>
        #include <unistd.h>
        #include <sys/types.h>
        #include <sys/file.h>
        #include <fcntl.h>
        int main(int argc, char **argv) {
            (void)argv;
            int witness = open("witness", O_RDONLY);
            if (witness < 0 || flock(witness, LOCK_EX)) return 11;
            int ready[2];
            if (pipe(ready)) return 12;
            for (int n = 0; n < 16; ++n) {
                pid_t child = fork();
                if (child < 0) return 13;
                if (child == 0) {
                    close(ready[0]);
                    if (write(ready[1], "x", 1) != 1) _exit(14);
                    sleep(3);
                    _exit(0);
                }
            }
            close(ready[1]);
            char signal;
            for (int n = 0; n < 16; ++n) {
                if (read(ready[0], &signal, 1) != 1) return 15;
            }
            if (argc > 1) {
                FILE *marker = fopen("ready", "w");
                if (!marker) return 16;
                fclose(marker);
                sleep(3);
            }
            return 37;
        }"#,
        &binary,
        &["-static"],
    );
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let result = retained(
        &store,
        "fork-many",
        &fs::read(&binary).unwrap(),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&result),
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    fs::write(cwd.join("witness"), b"retention witness").unwrap();
    for _ in 0..10 {
        assert_eq!(
            run_runtime(&closure, &[], &cwd).unwrap().code(),
            Some(37)
        );
        let witness = fs::File::open(cwd.join("witness")).unwrap();
        assert!(
            crate::platform::linux::fd::flock(
                witness.as_fd(),
                crate::platform::linux::fd::FlockMode::ExclusiveNonblocking
            )
            .unwrap(),
            "payload still holds a descriptor when run_runtime returned"
        );
    }
    for _ in 0..10 {
        let cancellation = crate::cancellation::Cancellation::default();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !cwd.join("ready").exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(2));
                }
                assert!(cwd.join("ready").exists());
                cancellation.cancel();
            });
            let status =
                run_runtime_with_cancellation(&closure, &["hold".into()], &cwd, &cancellation)
                    .unwrap();
            assert!(!status.success());
        });
        fs::remove_file(cwd.join("ready")).unwrap();
        let witness = fs::File::open(cwd.join("witness")).unwrap();
        assert!(
            crate::platform::linux::fd::flock(
                witness.as_fd(),
                crate::platform::linux::fd::FlockMode::ExclusiveNonblocking
            )
            .unwrap(),
            "cancelled payload still holds a descriptor when run_runtime returned"
        );
    }
}

#[test]
fn materialized_runtime_keeps_distinct_outputs_of_one_action() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    let (root, receipt, action) = build::cache::tests::retained_split_runtime(
        &store,
        &elf(3, None, &[], None, None),
        &elf(3, None, &[], Some("libsplit.so.1"), None),
    );
    let interpreter = format!("/syrox/store/{action}/out/bin/hello");
    let runpath = format!("/syrox/store/{action}/lib/usr/lib");
    let app = retained(
        &store,
        "split-consumer",
        &elf(
            2,
            Some(&interpreter),
            &["libsplit.so.1"],
            None,
            Some(&runpath),
        ),
        None,
    );
    let application = crate::result::materialize_artifact(&store, &app.root, app.receipt).unwrap();
    let loader = crate::result::materialize_artifact(&store, &root, receipt).unwrap();
    let library = crate::result::materialize_named_artifact(&store, &root, receipt, "lib").unwrap();
    let closure = verify_materialized_runtime(
        materialized_file(application, "bin/hello"),
        Some(materialized_file(loader, "bin/hello")),
        vec![library],
        &cancellation,
    )
    .unwrap();
    let targets = closure
        .mounts()
        .unwrap()
        .into_iter()
        .map(|mount| mount.target)
        .collect::<BTreeSet<_>>();
    assert_eq!(targets.len(), 3);
    assert!(targets.contains(&format!("/syrox/store/{action}/out")));
    assert!(targets.contains(&format!("/syrox/store/{action}/lib")));
    assert!(matches!(
        verify_materialized_runtime(
            materialized_file(
                closure.application.output.share(),
                closure.application().path.as_str()
            ),
            closure
                .loader
                .as_ref()
                .map(|file| materialized_file(file.output.share(), &file.path)),
            vec![],
            &cancellation
        ),
        Err(RuntimeError::Invalid(_))
    ));
    imported_runtime_roundtrip(&store, &closure);
    cancellation.cancel();
    assert!(matches!(
        verify_materialized_runtime(
            materialized_file(
                closure.application.output.share(),
                closure.application().path.as_str()
            ),
            closure
                .loader
                .as_ref()
                .map(|file| materialized_file(file.output.share(), &file.path)),
            closure
                .libraries
                .iter()
                .map(MaterializedArtifact::share)
                .collect(),
            &cancellation
        ),
        Err(RuntimeError::Cancelled)
    ));
}

#[test]
fn materialized_runtime_rejects_two_artifacts_for_the_same_prefix() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let first = retained(
        &store,
        "conflicting",
        &elf(2, None, &[], None, None),
        None,
    );
    let second = retained(
        &store,
        "conflicting",
        &elf(3, None, &[], None, None),
        None,
    );
    assert_eq!(first.action, second.action);
    assert_ne!(first.artifact, second.artifact);
    let application =
        crate::result::materialize_artifact(&store, &first.root, first.receipt).unwrap();
    let loader = crate::result::materialize_artifact(&store, &second.root, second.receipt).unwrap();
    let error = verify_materialized_runtime(
        materialized_file(application, "bin/hello"),
        Some(materialized_file(loader, "bin/hello")),
        vec![],
        &crate::cancellation::Cancellation::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, RuntimeError::Invalid(message) if message.contains("conflicting identities"))
    );
}

fn imported_runtime_roundtrip(source: &Store, closure: &RuntimeClosure) {
    let cancellation = crate::cancellation::Cancellation::default();
    let manifest = crate::result::ResultManifest::from_views(
        BTreeMap::from([
            ("app".into(), &closure.application().output),
            ("loader".into(), &closure.loader().unwrap().output),
            ("library".into(), &closure.libraries()[0]),
        ]),
        BTreeMap::from([(
            "run".into(),
            crate::result::ResultCommand {
                application: "app".into(),
                application_path: closure.application().path.as_str().to_owned(),
                loader: Some("loader".into()),
                loader_path: closure
                    .loader()
                    .map(|file| file.path.as_str())
                    .map(str::to_owned),
                libraries: vec!["library".into()],
            },
        )]),
    )
    .unwrap();
    let receiver = tempfile::tempdir().unwrap();
    let destination = Store::open(receiver.path()).unwrap();
    for output in manifest.outputs().values() {
        let input = source
            .operation()
            .unwrap()
            .open_verified(output.artifact, build::MAX_OUTPUT_BYTES)
            .unwrap()
            .unwrap();
        destination
            .operation()
            .unwrap()
            .ingest(input, output.artifact, build::MAX_OUTPUT_BYTES)
            .unwrap();
    }
    let admitted = crate::result::admit_result(
        &destination,
        &RootName::new("portable_runtime").unwrap(),
        &manifest,
        manifest.digest().unwrap(),
        &cancellation,
    )
    .unwrap();
    let runtime = admitted.command("run").unwrap();
    assert!(matches!(
        runtime.application.output.identity.origin,
        crate::result::OutputOrigin::Imported { .. }
    ));
    drop(admitted);
    let imported = runtime.open(&destination, &cancellation).unwrap();
    assert_eq!(imported.entry(), closure.entry());
    assert_eq!(imported.mounts().unwrap().len(), 3);
    crate::store::take_verified_read_bytes();
    runtime.open(&destination, &cancellation).unwrap();
    let shared_admission_bytes = crate::store::take_verified_read_bytes();
    verify_materialized_runtime(
        materialized_file(
            runtime
                .application
                .output
                .open(&destination, &cancellation)
                .unwrap(),
            &runtime.application.path,
        ),
        Some(materialized_file(
            runtime
                .loader
                .as_ref()
                .unwrap()
                .output
                .open(&destination, &cancellation)
                .unwrap(),
            &runtime.loader.as_ref().unwrap().path,
        )),
        vec![
            runtime.libraries[0]
                .open(&destination, &cancellation)
                .unwrap(),
        ],
        &cancellation,
    )
    .unwrap();
    let independent_admission_bytes = crate::store::take_verified_read_bytes();
    assert!(
        shared_admission_bytes < independent_admission_bytes,
        "shared={shared_admission_bytes}, independent={independent_admission_bytes}"
    );
    let crate::result::OutputOrigin::Built {
        receipt,
    } = closure.application().output.identity().origin
    else {
        panic!("source fixture was not built");
    };
    assert!(
        destination
            .operation()
            .unwrap()
            .read_verified(receipt, 1024 * 1024)
            .unwrap()
            .is_none()
    );
    drop(imported);
    crate::result::clear_materializations(&mut destination.maintenance().unwrap()).unwrap();
    assert_eq!(
        runtime
            .open(&destination, &cancellation)
            .unwrap()
            .entry(),
        closure.entry()
    );
}

#[test]
#[ignore = "requires syrox-worker, Linux user namespaces and a host static compiler"]
fn host_runtime_consumes_private_configuration_outside_cwd() {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("configured-program");
    let source = r#"
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <unistd.h>
        #include <sys/statvfs.h>
        int main(int argc, char **argv) {
            if (argc != 3 || !getenv("APP_CONFIG") || strcmp(argv[1], getenv("APP_CONFIG"))) return 10;
            FILE *f = fopen(argv[1], "r"); char bytes[32] = {0};
            if (!f || fread(bytes, 1, 10, f) != 10 || strcmp(bytes, "configured")) return 11;
            if (access(argv[2], F_OK) == 0 || access("app.conf", F_OK) == 0) return 12;
            struct statvfs info;
            if (statvfs(argv[1], &info) || !(info.f_flag & ST_RDONLY)) return 13;
            if (getenv("LD_PRELOAD") || getenv("PATH")) return 14;
            return 37;
        }
    "#;
    let mut compiler = Command::new("gcc")
        .args(["-static", "-x", "c", "-o"])
        .arg(&binary)
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    assert!(compiler.wait().unwrap().success());
    let store_path = temporary.path().join("store");
    fs::create_dir(&store_path).unwrap();
    let store = Store::open(&store_path).unwrap();
    let app = retained(
        &store,
        "configured-host",
        &fs::read(binary).unwrap(),
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
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    let directory = temporary.path().join("configuration");
    fs::create_dir(&directory).unwrap();
    let file = directory.join("app.conf");
    fs::write(&file, "configured").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    let logical = "/syrox/config/service/app.conf";
    let configuration = RuntimeConfiguration::new(
        "service",
        fs::File::open(&directory).unwrap(),
        BTreeMap::from([("APP_CONFIG".into(), logical.into())]),
    )
    .unwrap();
    let outcome = run_runtime_configured_with_cancellation(
        &closure,
        &[logical.into(), file.into_os_string()],
        &cwd,
        &configuration,
        &crate::cancellation::Cancellation::default(),
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.unwrap().code(), Some(37));
}

#[test]
#[ignore = "requires syrox-worker, Linux user/PID namespaces and a host static compiler"]
fn host_namespace_init_reaps_orphan_before_main_exit_and_preserves_main_status() {
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("orphan-reaping");
    compile(
        r"
        #include <unistd.h>
        #include <signal.h>
        #include <sys/wait.h>
        #include <errno.h>
        int main(void) {
            int channel[2];
            if (pipe(channel)) return 10;
            pid_t intermediate = fork();
            if (intermediate < 0) return 11;
            if (intermediate == 0) {
                close(channel[0]);
                pid_t orphan = fork();
                if (orphan < 0) _exit(12);
                if (orphan == 0) {
                    close(channel[1]);
                    usleep(100000);
                    _exit(99);
                }
                if (write(channel[1], &orphan, sizeof(orphan)) != sizeof(orphan)) _exit(13);
                close(channel[1]);
                _exit(23);
            }
            close(channel[1]);
            pid_t orphan;
            if (read(channel[0], &orphan, sizeof(orphan)) != sizeof(orphan)) return 14;
            close(channel[0]);
            int status;
            if (waitpid(intermediate, &status, 0) != intermediate ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 23) return 15;
            /* kill(pid, 0) still succeeds for an unreaped zombie. The principal
               deliberately stays alive until PID 1 has collected the orphan. */
            for (int n = 0; n < 500; ++n) {
                if (kill(orphan, 0) < 0) return errno == ESRCH ? 37 : 16;
                usleep(10000);
            }
            return 17;
        }
        ",
        &binary,
        &["-static"],
    );
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let application = retained(
        &store,
        "orphan-reaping",
        &fs::read(binary).unwrap(),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&application),
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    assert_eq!(
        run_runtime(&closure, &[], &cwd).unwrap().code(),
        Some(37)
    );
}

#[test]
#[ignore = "requires syrox-worker, Linux user/PID namespaces, devpts and a host static compiler"]
fn host_runtime_payload_owns_terminal_foreground_and_observes_resize() {
    use crate::platform::linux::fd::terminal::{Pty, WindowSize};
    use std::sync::atomic::{AtomicBool, Ordering};
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("session-payload");
    compile(
        include_str!("../../../../../tests/fixtures/session-payload.c"),
        &binary,
        &[
            "-std=c11", "-static", "-no-pie", "-O2", "-Wall", "-Wextra", "-Werror",
        ],
    );
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let app = retained(
        &store,
        "terminal-host",
        &fs::read(binary).unwrap(),
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
    let cwd = temporary.path().join("cwd");
    fs::create_dir(&cwd).unwrap();
    let (master, slave) = Pty::open(
        WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        },
        None,
    )
    .unwrap()
    .into_parts();
    let mut master = fs::File::from(master);
    let flag = Arc::new(AtomicBool::new(false));
    let cancellation = crate::cancellation::Cancellation::from_flag(Arc::clone(&flag));
    let expired = Arc::new(AtomicBool::new(false));
    let timer_expired = Arc::clone(&expired);
    let timer_flag = Arc::clone(&flag);
    let (done, completion) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if let Err(error) = completion.recv_timeout(Duration::from_secs(30)) {
            timer_expired.store(
                matches!(error, std::sync::mpsc::RecvTimeoutError::Timeout),
                Ordering::Release,
            );
            timer_flag.store(true, Ordering::Release);
        }
    });
    let (terminal_io, status) = std::thread::scope(|scope| {
        let payload = scope.spawn(move || {
            run_runtime_with_terminal(
                &closure,
                &[
                    "terminal".into(),
                    "$HOME;echo literal".into(),
                    "40".into(),
                    "100".into(),
                ],
                &cwd,
                &RuntimeConfiguration::default(),
                slave.as_fd(),
                &cancellation,
            )
        });
        let terminal_io = (|| -> std::io::Result<()> {
            read_terminal_marker(
                &mut master,
                b"SYROX_SESSION_V1 READY terminal 24 80",
                Duration::from_secs(10),
            )?;
            WindowSize {
                rows: 40,
                columns: 100,
                x_pixels: 0,
                y_pixels: 0,
            }
            .apply(master.as_fd())?;
            master.write_all(b"$HOME;echo literal\n")?;
            read_terminal_marker(
                &mut master,
                b"SYROX_SESSION_V1 TERMINAL OK",
                Duration::from_secs(10),
            )
        })();
        if terminal_io.is_err() {
            flag.store(true, Ordering::Release);
        }
        (terminal_io, payload.join().unwrap())
    });
    let _ = done.send(());
    watchdog.join().unwrap();
    assert!(
        !expired.load(Ordering::Acquire),
        "runtime terminal settlement exceeded deadline"
    );
    terminal_io.unwrap();
    assert_eq!(status.unwrap().code(), Some(0));
}

fn read_terminal_marker(
    master: &mut fs::File,
    marker: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut received = Vec::new();
    loop {
        if received
            .windows(marker.len())
            .any(|bytes| bytes == marker)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "terminal marker deadline",
            ));
        }
        if !crate::execution::native::ready(master.as_fd(), 20)? {
            continue;
        }
        let mut bytes = [0; 1024];
        match master.read(&mut bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "terminal ended before marker",
                ));
            }
            Ok(n) => received.extend_from_slice(&bytes[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        if received.len() > 16 * 1024 {
            return Err(std::io::Error::other(
                "terminal output limit exceeded",
            ));
        }
    }
}

#[test]
fn managed_foreground_uses_explicit_snapshot_and_distinct_worker_entry() {
    let snapshot = std::path::Path::new("/controlled/release/worker-snapshot");
    assert_eq!(
        runtime_worker(RuntimeProfile {
            worker: Some(snapshot)
        })
        .unwrap(),
        snapshot
    );
    assert!(
        runtime_worker(RuntimeProfile {
            worker: Some(std::path::Path::new("relative-worker"))
        })
        .is_err()
    );
    assert_eq!(
        RuntimeProfile {
            worker: Some(snapshot)
        }
        .worker_mode(),
        "__runtime-managed"
    );
    assert_eq!(
        RuntimeProfile {
            worker: None
        }
        .worker_mode(),
        "__runtime"
    );
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER and SYROX_SESSION_PAYLOAD candidates, nonroot UID and Linux user/PID/mount namespaces"]
fn host_managed_foreground_preserves_identity_minimal_environment_and_exit_status() {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let worker = PathBuf::from(
        std::env::var_os("SYROX_OWNER_WORKER").expect("explicit worker candidate required"),
    );
    let payload = PathBuf::from(
        std::env::var_os("SYROX_SESSION_PAYLOAD")
            .expect("explicit static session payload required"),
    );
    assert!(worker.is_absolute() && payload.is_absolute());
    let mut candidates = Vec::new();
    for path in [&worker, &payload] {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        assert!(file.metadata().unwrap().is_file());
        let mut bytes = Vec::new();
        file.take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 128 * 1024 * 1024);
        eprintln!(
            "candidate {} sha256 {}",
            path.display(),
            ContentDigest::sha256(&bytes)
        );
        candidates.push(bytes);
    }
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let app = retained(
        &store,
        "managed-foreground-host",
        &candidates[1],
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
    let cwd = temporary.path().join("work");
    fs::create_dir(&cwd).unwrap();
    let peer = crate::execution::transport::Peer::current();
    assert_ne!(peer.uid, 0);
    let cancellation = crate::cancellation::Cancellation::default();
    let watch_token = cancellation.clone();
    let (done, completion) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if completion
            .recv_timeout(Duration::from_secs(30))
            .is_err()
        {
            watch_token.cancel();
            true
        } else {
            false
        }
    });
    let result = run_runtime_managed_with_cancellation(
        &worker,
        &closure,
        &[
            "managed".into(),
            peer.uid.to_string().into(),
            peer.gid.to_string().into(),
        ],
        &cwd,
        &RuntimeConfiguration::default(),
        None,
        &cancellation,
    );
    let _ = done.send(());
    assert!(
        !watchdog.join().unwrap(),
        "managed foreground exceeded deadline"
    );
    assert_eq!(result.unwrap().code(), Some(37));
}

fn empty_process_interest(store: &Store) -> fs::File {
    store
        .operation()
        .unwrap()
        .retain_objects(&[], &[])
        .unwrap()
        .process_retention()
        .unwrap()
}

fn collected_process_interests(store: &Store) -> usize {
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap()
        .removed_interests
}

#[test]
fn managed_terminal_refuses_non_tty_before_worker_or_cwd_access() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let app = retained(
        &store,
        "terminal-preflight",
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
    let invalid = tempfile::tempfile().unwrap();
    let worker = temporary.path().join("absent-worker");
    let cwd = temporary.path().join("absent-cwd");
    let cancelled = crate::cancellation::Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        run_runtime_managed_with_cancellation(
            &worker,
            &closure,
            &[],
            &cwd,
            &RuntimeConfiguration::default(),
            Some(invalid.as_fd()),
            &cancelled,
        ),
        Err(RuntimeError::Cancelled)
    ));
    assert!(matches!(
        run_runtime_managed_with_cancellation(
            &worker,
            &closure,
            &[],
            &cwd,
            &RuntimeConfiguration::default(),
            Some(invalid.as_fd()),
            &crate::cancellation::Cancellation::default(),
        ),
        Err(RuntimeError::Io(_))
    ));
    assert!(!worker.exists());
    assert!(!cwd.exists());
}
