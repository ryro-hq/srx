//! From a `.srx` project to builds, running programs and installations.
//!
//! Start with [`project`] for loading and evaluation, then follow the topic your
//! change affects. Each operation owns the resources it opens through settlement.
//!
//! # From projects to builds
//!
//! [`project`] loads sources, checks the lock and prepares a [`project::PreparedPlan`].
//! [`plan`] describes acquisition, builds and consumers before host effects begin.
//! [`realize`] resolves a selection and realizes its dependencies using [`acquire`]
//! and [`build`]. A prepared plan carries input origins so realization uses the
//! same project preparation.
//!
//! # Keeping outputs alive
//!
//! [`store`] keeps objects by digest and provides leases for access and retention.
//! [`result`] groups admitted outputs and their references. [`runtime`] checks the
//! application, loader and libraries before execution. Its handles keep those
//! files alive until the processes that can use them have settled.
//!
//! # Shell sessions and Os generations
//!
//! [`deployment::shell`] owns temporary sessions and their commands, configuration
//! and secrets. [`deployment::os`] owns persistent generations and records the
//! effects of applying them. Both use [`execution`] for admission and process
//! observations, [`systemd`] for manager communication and [`platform`] for Linux
//! handles. Follow these modules for the contracts behind each handoff.
//!
//! # Cancellation and recovery
//!
//! [`cancellation`] provides cooperative cancellation; each transport also needs
//! its own way to bound a blocked read. [Build cancellation] tracks interest in
//! shared producers, so cancelling one consumer need not cancel another's build.
//!
//! Recovery reconciles durable records with observed execution before releasing
//! resources. Start with the [build journal] for interrupted builds or
//! [Os recovery] for installations. A missing reply can leave
//! an effect unresolved; neither cancellation nor reading a journal proves that
//! execution has ended.
//!
//! [Build cancellation]: ../src/syrox_engine/build/cancellation/mod.rs.html
//! [build journal]: ../src/syrox_engine/build/journal/mod.rs.html
//! [Os recovery]: ../src/syrox_engine/deployment/os/apply/recovery/mod.rs.html

#[cfg(not(target_os = "linux"))]
compile_error!("syrox-engine supports Linux only");
pub mod acquire;
pub mod build;
pub mod bundle;
pub mod cancellation;
#[cfg(target_os = "linux")]
pub mod catalog;
#[cfg(all(test, target_os = "linux"))]
mod catalog_tests;
pub mod config;
pub mod deployment;
pub mod execution;
pub mod plan;
pub mod platform;
pub mod project;
pub mod realize;
pub mod result;
pub mod runtime;
pub mod store;
pub mod systemd;
pub mod worker;

#[cfg(test)]
pub(crate) fn reexec_test_executable(test: &str, ignored: bool) -> std::path::PathBuf {
    let executable = std::env::current_exe().unwrap();
    let expected = format!("{test}: test");
    let list = |only_ignored: bool| {
        let mut command = std::process::Command::new(&executable);
        command.args(["--list", "--exact", test]);
        if only_ignored {
            command.arg("--ignored");
        }
        let output = command.output().expect("list reexec fixture");
        assert!(
            output.status.success(),
            "cannot list reexec fixture {test}"
        );
        String::from_utf8(output.stdout).expect("UTF-8 harness listing")
    };
    assert_eq!(
        list(false)
            .lines()
            .filter(|line| *line == expected)
            .count(),
        1,
        "reexec fixture must exist exactly once: {test}"
    );
    let is_ignored = list(true).lines().any(|line| line == expected);
    assert!(
        !is_ignored || ignored,
        "reexec fixture is ignored but was not selected: {test}"
    );
    executable
}

#[cfg(test)]
pub(crate) fn assert_reexec_result(stdout: &[u8], test: &str) {
    let output = String::from_utf8_lossy(stdout);
    assert!(
        output.contains("running 1 test") && output.contains("1 passed; 0 failed"),
        "reexec must report one executed fixture: {test}\n{output}"
    );
}

#[cfg(test)]
mod reexec_tests {
    //! Reject stale harness filters before child setup can produce a false pass.
    #[test]
    #[should_panic(expected = "reexec fixture must exist exactly once")]
    fn missing_fixture_is_rejected_before_reexec() {
        super::reexec_test_executable("missing::stale::fixture", false);
    }
    #[test]
    #[should_panic(expected = "reexec must report one executed fixture")]
    fn zero_test_success_is_rejected() {
        super::assert_reexec_result(
            b"running 0 tests\ntest result: ok. 0 passed; 0 failed",
            "stale",
        );
    }
}
