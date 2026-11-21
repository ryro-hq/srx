use super::*;

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
        #include <fcntl.h>
        #include <sys/stat.h>
        #include <sys/sysmacros.h>
        #include <dirent.h>
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
            int null = open("/dev/null", O_RDWR);
            if (null < 0) return 21;
            struct stat device;
            if (fstat(null, &device) || !S_ISCHR(device.st_mode)
                || major(device.st_rdev) != 1 || minor(device.st_rdev) != 3) return 22;
            char buffer[16];
            if (read(null, buffer, sizeof(buffer)) != 0
                || write(null, "discarded", 9) != 9) return 23;
            close(null);
            DIR *devices = opendir("/dev");
            if (!devices) return 24;
            struct dirent *entry;
            int null_count = 0;
            while ((entry = readdir(devices))) {
                if (!strcmp(entry->d_name, "null")) ++null_count;
                else if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) return 25;
            }
            closedir(devices);
            if (null_count != 1) return 26;
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
