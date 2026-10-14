use super::GuardianIo;
use crate::runtime::command_proxy::request::{AdmittedProxyRequest, ProxyRequest};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::fs::OpenOptions;
use std::os::fd::AsFd as _;
use std::path::PathBuf;

#[test]
fn redirected_stdio_creates_no_terminal_custody_or_second_reader() {
    let root = tempfile::tempdir().unwrap();
    let directory = linux_fd::open_top_directory(root.path()).unwrap();
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let request = ProxyRequest::new("tool".into(), Vec::new(), PathBuf::from(".")).unwrap();
    let fds = [
        directory.fd(),
        null.as_fd(),
        null.as_fd(),
        null.as_fd(),
    ]
    .into_iter()
    .map(|fd| fd.try_clone_to_owned().unwrap())
    .collect();
    let admitted = AdmittedProxyRequest::validate(
        request,
        fds,
        directory.fd(),
        &Cancellation::default(),
    )
    .unwrap();
    let (custody, relay) = GuardianIo::prepare(&admitted)
        .unwrap()
        .into_parts();
    assert!(custody.is_none());
    assert!(relay.is_none());
}
