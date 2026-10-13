//! Do projeto `.srx` ao build, ao programa em execução e à instalação.
//!
//! Comece por [`project`]: ele carrega as fontes, confere o lock e prepara o
//! [`plan::Plan`]. [`plan`] descreve o que será feito. [`realize`] usa esse plano
//! para adquirir fontes e realizar os outputs escolhidos.
//!
//! [`store`] guarda os objetos; [`result`] reúne os outputs e suas referências.
//! [`runtime`] verifica a aplicação, o loader e as bibliotecas antes de executar.
//! Os handles ficam vivos enquanto o processo ainda pode usar esses arquivos.
//!
//! [`deployment::shell`] cuida das sessões temporárias. [`deployment::os`] cuida
//! das gerações persistentes e da recuperação. Os protocolos de execução ficam
//! em [`execution`], a comunicação com o manager em [`systemd`] e os detalhes de
//! Linux em [`platform`]. Cada operação cuida dos recursos que abriu até encerrar.

#[cfg(not(target_os = "linux"))]
compile_error!("syrox-engine supports Linux only");
pub mod acquire;
pub mod build;
pub mod bundle;
pub mod cancellation;
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
