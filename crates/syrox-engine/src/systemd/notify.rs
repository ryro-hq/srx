//! Messages and descriptors sent to the manager's notification socket.
//!
//! The endpoint comes from context verified by the launcher. Connecting to the
//! socket does not authenticate the manager, and cancelling a request does not
//! withdraw a message already sent.
//!
//! Reference: <https://raw.githubusercontent.com/systemd/systemd/v250/man/sd_notify.xml>.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

use super::{Budget, SystemdError};
use crate::cancellation::Cancellation;

#[derive(Clone, Debug)]
pub struct SystemdNotifyEndpoint(SocketAddr);
impl SystemdNotifyEndpoint {
    /// Explicit endpoint supplied by the launcher, never implicitly read from env.
    pub fn new(value: &str) -> Result<Self, SystemdError> {
        if value.as_bytes().contains(&0) {
            return Err(SystemdError::Invalid(
                "NUL in notification endpoint",
            ));
        }
        let address = if let Some(name) = value.strip_prefix('@') {
            if name.is_empty() {
                return Err(SystemdError::Invalid("empty abstract endpoint"));
            }
            SocketAddr::from_abstract_name(name.as_bytes())?
        } else {
            super::absolute(std::path::Path::new(value))?;
            SocketAddr::from_pathname(value)?
        };
        Ok(Self(address))
    }
}

/// Previous datagrams were processed, not necessarily accepted or retained.
#[derive(Debug)]
pub struct SystemdNotificationsProcessed(());

#[derive(Debug)]
pub struct SystemdNotifier {
    socket: UnixDatagram,
}
impl SystemdNotifier {
    pub fn connect(
        endpoint: &SystemdNotifyEndpoint,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Self, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        loop {
            budget.check()?;
            match socket.connect_addr(&endpoint.0) {
                Ok(()) => {
                    return Ok(Self {
                        socket,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(socket.as_fd(), libc::POLLOUT, &budget)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Enqueues one descriptor. Neither this nor a barrier proves FD store admission.
    /// The caller must retain its own lease until independently proven settlement.
    pub fn store_fd(
        &self,
        name: &str,
        descriptor: BorrowedFd<'_>,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        let packet = store_packet(name)?;
        self.send(
            packet.as_bytes(),
            Some(descriptor),
            &Budget::new(timeout, cancellation)?,
        )
    }
    pub fn ready(
        &self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        self.send(
            b"READY=1",
            None,
            &Budget::new(timeout, cancellation)?,
        )
    }
    pub fn stopping(
        &self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        self.send(
            b"STOPPING=1",
            None,
            &Budget::new(timeout, cancellation)?,
        )
    }
    pub fn barrier(
        &self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdNotificationsProcessed, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let (read, write) = pipe()?;
        self.send(b"BARRIER=1", Some(write.as_fd()), &budget)?;
        drop(write);
        let mut byte = 0_u8;
        loop {
            budget.check()?;
            // SAFETY: owned nonblocking pipe and one writable byte.
            let result = unsafe { libc::read(read.as_raw_fd(), (&raw mut byte).cast(), 1) };
            if result == 0 {
                return Ok(SystemdNotificationsProcessed(()));
            }
            if result > 0 {
                return Err(SystemdError::Protocol(
                    "unexpected barrier pipe data",
                ));
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => wait(read.as_fd(), libc::POLLIN, &budget)?,
                _ => return Err(error.into()),
            }
        }
    }
    fn send(
        &self,
        packet: &[u8],
        descriptor: Option<BorrowedFd<'_>>,
        budget: &Budget<'_>,
    ) -> Result<(), SystemdError> {
        // Storage aligned for cmsghdr, sufficient for one int on Linux ABIs.
        let mut control = [0_usize; 8];
        // SAFETY: zeroed msghdr has valid empty pointer/count pairs.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        if let Some(fd) = descriptor {
            message.msg_control = control.as_mut_ptr().cast();
            // SAFETY: control storage is aligned and exceeds CMSG_SPACE(one int).
            unsafe {
                message.msg_controllen =
                    libc::CMSG_SPACE(u32::try_from(size_of::<libc::c_int>()).expect("int size"))
                        .try_into()
                        .expect("bounded ancillary length");
                let header = libc::CMSG_FIRSTHDR(&raw const message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN(u32::try_from(size_of::<libc::c_int>()).expect("int size"))
                        .try_into()
                        .expect("bounded ancillary length");
                let raw = fd.as_raw_fd();
                std::ptr::copy_nonoverlapping(
                    (&raw const raw).cast::<u8>(),
                    libc::CMSG_DATA(header),
                    size_of::<libc::c_int>(),
                );
            }
        }
        loop {
            budget.check()?;
            // SAFETY: live packet/iovec/control buffers and borrowed descriptor.
            let result = unsafe {
                libc::sendmsg(
                    self.socket.as_raw_fd(),
                    &raw const message,
                    libc::MSG_NOSIGNAL,
                )
            };
            if result >= 0 {
                return if usize::try_from(result).ok() == Some(packet.len()) {
                    Ok(())
                } else {
                    Err(SystemdError::Protocol(
                        "partial notification datagram",
                    ))
                };
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => wait(self.socket.as_fd(), libc::POLLOUT, budget)?,
                _ => return Err(error.into()),
            }
        }
    }
}
fn store_packet(name: &str) -> Result<String, SystemdError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(SystemdError::Invalid("invalid FD store name"));
    }
    // Do not let HUP/ERR revoke a lifetime lease. Unit settlement clears its store.
    Ok(format!("FDSTORE=1\nFDNAME={name}\nFDPOLL=0"))
}
fn pipe() -> Result<(OwnedFd, OwnedFd), SystemdError> {
    let mut descriptors = [-1; 2];
    // SAFETY: two writable descriptor slots; success transfers ownership.
    if unsafe {
        libc::pipe2(
            descriptors.as_mut_ptr(),
            libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: pipe2 created two distinct live owned descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}
fn wait(
    fd: BorrowedFd<'_>,
    events: libc::c_short,
    budget: &Budget<'_>,
) -> Result<(), SystemdError> {
    budget.check()?;
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, borrowed descriptor, bounded timeout.
    let result = unsafe { libc::poll(&raw mut poll, 1, 20) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error().into());
    }
    budget.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::{SystemdService, SystemdServiceProfile, SystemdUnitName};

    #[test]
    fn endpoints_and_names_cannot_inject_fields() {
        for endpoint in [
            "",
            "relative",
            "@",
            "/tmp/../notify",
            "/tmp/a\0b",
        ] {
            assert!(SystemdNotifyEndpoint::new(endpoint).is_err());
        }
        assert!(SystemdNotifyEndpoint::new(&format!("@{}", "a".repeat(108))).is_err());
        assert!(SystemdNotifyEndpoint::new("@syrox-notify").is_ok());
        assert!(SystemdNotifyEndpoint::new("/run/systemd/notify").is_ok());
        for name in ["", "a:b", "a\nREADY=1", "a\0", "á"] {
            assert!(store_packet(name).is_err());
        }
        assert!(store_packet(&"a".repeat(129)).is_err());
        assert_eq!(
            store_packet("lease-1").unwrap(),
            "FDSTORE=1\nFDNAME=lease-1\nFDPOLL=0"
        );
    }

    #[test]
    fn notify_profile_is_bounded_and_uses_main_sender() {
        use crate::systemd::properties::{Value, service};
        let mut request = SystemdService::new(
            SystemdUnitName::new("syrox-notify.service").unwrap(),
            "/bin/true".into(),
        );
        request.profile = SystemdServiceProfile::Notify {
            fd_store_max: 1,
            start_timeout: Duration::from_secs(2),
        };
        let properties: std::collections::BTreeMap<_, _> =
            service(&request).unwrap().into_iter().collect();
        assert_eq!(properties["Type"], Value::String("notify".into()));
        assert_eq!(
            properties["NotifyAccess"],
            Value::String("main".into())
        );
        assert_eq!(
            properties["KillMode"],
            Value::String("mixed".into())
        );
        assert_eq!(
            properties["FileDescriptorStoreMax"],
            Value::U32(1)
        );
        assert_eq!(
            properties["TimeoutStartUSec"],
            Value::U64(2_000_000)
        );
        request.profile = SystemdServiceProfile::Notify {
            fd_store_max: 65,
            start_timeout: Duration::from_secs(2),
        };
        assert!(service(&request).is_err());
        request.profile = SystemdServiceProfile::Notify {
            fd_store_max: 1,
            start_timeout: Duration::ZERO,
        };
        assert!(service(&request).is_err());
    }

    #[test]
    fn cancelled_connect_does_not_touch_endpoint() {
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let endpoint = SystemdNotifyEndpoint::new("/nonexistent/syrox-notify").unwrap();
        assert!(matches!(
            SystemdNotifier::connect(&endpoint, Duration::from_secs(1), &cancellation),
            Err(SystemdError::Cancelled)
        ));
    }

    // IPC gate: a fake receiver intentionally keeps the barrier FD open. This is
    // transport verification only and says nothing about manager authorization.
    #[test]
    fn descriptor_transfer_and_barrier_deadline() {
        let (socket, receiver) = UnixDatagram::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let notifier = SystemdNotifier {
            socket,
        };
        let cancellation = Cancellation::default();
        let file = tempfile::tempfile().unwrap();
        notifier
            .store_fd(
                "lease",
                file.as_fd(),
                Duration::from_secs(1),
                &cancellation,
            )
            .unwrap();
        let (packet, lease) = receive(&receiver);
        assert_eq!(packet, b"FDSTORE=1\nFDNAME=lease\nFDPOLL=0");
        drop(lease);
        let worker = std::thread::spawn(move || {
            let (packet, fd) = receive(&receiver);
            assert_eq!(packet, b"BARRIER=1");
            std::thread::sleep(Duration::from_millis(100));
            drop(fd);
        });
        assert!(matches!(
            notifier.barrier(Duration::from_millis(30), &cancellation),
            Err(SystemdError::Deadline)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn barrier_completes_only_after_receiver_closes_descriptor() {
        let (socket, receiver) = UnixDatagram::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let notifier = SystemdNotifier {
            socket,
        };
        let worker = std::thread::spawn(move || {
            let (packet, fd) = receive(&receiver);
            assert_eq!(packet, b"BARRIER=1");
            drop(fd);
        });
        notifier
            .barrier(Duration::from_secs(1), &Cancellation::default())
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn elapsed_budget_is_a_deadline_without_io() {
        let cancellation = Cancellation::default();
        let budget = Budget {
            end: std::time::Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
            cancellation: &cancellation,
        };
        assert!(matches!(
            budget.check(),
            Err(SystemdError::Deadline)
        ));
    }

    #[allow(clippy::useless_conversion)] // libc ancillary lengths differ on GNU/musl.
    fn receive(socket: &UnixDatagram) -> (Vec<u8>, OwnedFd) {
        let mut data = [0_u8; 256];
        let mut control = [0_usize; 8];
        let mut vector = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: initialized pointers/counts and aligned ancillary buffer.
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &raw mut vector;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of_val(&control)
                .try_into()
                .expect("bounded control length");
            let length = libc::recvmsg(
                socket.as_raw_fd(),
                &raw mut message,
                libc::MSG_CMSG_CLOEXEC,
            );
            assert!(length > 0);
            assert_eq!(
                message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC),
                0
            );
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            assert!(!header.is_null());
            assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!(
                u64::try_from((*header).cmsg_len).expect("bounded header length"),
                u64::from(libc::CMSG_LEN(4))
            );
            let mut raw: libc::c_int = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(header),
                (&raw mut raw).cast::<u8>(),
                size_of::<libc::c_int>(),
            );
            let fd = OwnedFd::from_raw_fd(raw);
            assert!(libc::CMSG_NXTHDR(&raw const message, header).is_null());
            (
                data[..usize::try_from(length).unwrap()].to_vec(),
                fd,
            )
        }
    }

    #[test]
    #[ignore = "internal fixture invoked only by the authorized manager gate"]
    #[allow(clippy::zombie_processes)] // This fixture proves ownership after SIGKILL of the parent.
    fn manager_fixture() {
        let path =
            std::env::var_os("SYROX_NOTIFY_LEASE_FIXTURE").expect("manager fixture authorization");
        let endpoint =
            SystemdNotifyEndpoint::new(&std::env::var("NOTIFY_SOCKET").expect("manager endpoint"))
                .unwrap();
        let cancellation = Cancellation::default();
        let timeout = Duration::from_secs(5);
        let notifier = SystemdNotifier::connect(&endpoint, timeout, &cancellation).unwrap();
        let file = std::fs::File::open(path).unwrap();
        assert!(
            crate::platform::linux::fd::flock(
                file.as_fd(),
                crate::platform::linux::fd::FlockMode::Shared
            )
            .unwrap()
        );
        notifier
            .store_fd("lease", file.as_fd(), timeout, &cancellation)
            .unwrap();
        notifier.barrier(timeout, &cancellation).unwrap();
        drop(file);
        notifier.ready(timeout, &cancellation).unwrap();
        notifier.barrier(timeout, &cancellation).unwrap();
        if std::env::var_os("SYROX_NOTIFY_ABRUPT_FIXTURE").is_some() {
            // The parent's lease FD has been closed, and SCM_RIGHTS duplicated it
            // only into the manager. The descendant inherits no lease descriptor.
            let _child = std::process::Command::new(crate::reexec_test_executable(
                "systemd::notify::tests::descendant_fixture",
                true,
            ))
            .args([
                "--ignored",
                "--exact",
                "systemd::notify::tests::descendant_fixture",
            ])
            .spawn()
            .unwrap();
            // SAFETY: this opt-in manager fixture deliberately kills only itself.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            panic!("SIGKILL unexpectedly returned");
        }
        std::thread::sleep(Duration::from_secs(25));
    }

    /// Exercises both rejection (capacity zero) and actual manager retention. The
    /// fixture drops its descriptor before READY, so only the manager can keep flock.
    #[test]
    #[ignore = "requires authorized systemd >=250 user manager; set SYROX_SYSTEMD_USER_BUS"]
    fn manager_fd_store_retains_lease_until_stop_and_zero_capacity_rejects() {
        use crate::systemd::{
            SystemdJobCompletion, SystemdJobResult, SystemdManager, SystemdScope,
        };
        let bus_socket =
            std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit authorized bus");
        let cancellation = Cancellation::default();
        let timeout = Duration::from_secs(10);
        let mut manager = SystemdManager::connect(
            SystemdScope::User {
                bus_socket: bus_socket.into(),
            },
            timeout,
            &cancellation,
        )
        .unwrap();
        for (capacity, abrupt) in [(0, false), (1, false), (1, true)] {
            let lease = tempfile::NamedTempFile::new().unwrap();
            let mut service = SystemdService::new(
                SystemdUnitName::new(format!(
                    "syrox-notify-test-{}-{capacity}-{abrupt}.service",
                    std::process::id()
                ))
                .unwrap(),
                crate::reexec_test_executable("systemd::notify::tests::manager_fixture", true),
            );
            service.profile = SystemdServiceProfile::Notify {
                fd_store_max: capacity,
                start_timeout: timeout,
            };
            service.runtime_max = Some(Duration::from_secs(30));
            service.arguments = vec![
                "--ignored".into(),
                "--exact".into(),
                "systemd::notify::tests::manager_fixture".into(),
                "--nocapture".into(),
            ];
            service.environment.insert(
                "SYROX_NOTIFY_LEASE_FIXTURE".into(),
                lease.path().to_str().unwrap().into(),
            );
            if abrupt {
                service
                    .environment
                    .insert("SYROX_NOTIFY_ABRUPT_FIXTURE".into(), "1".into());
            }
            let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let job = manager
                    .start_transient(&service, timeout, &cancellation)
                    .unwrap();
                assert!(matches!(
                    manager
                        .wait_job(&job, timeout, &cancellation)
                        .unwrap(),
                    SystemdJobCompletion::Observed {
                        result: SystemdJobResult::Done
                    }
                ));
                if abrupt {
                    wait_abrupt_main(&mut manager, &service.unit, &cancellation);
                }
                let observed = manager
                    .query_fd_store(&service.unit, timeout, &cancellation)
                    .unwrap()
                    .unwrap();
                assert_eq!(observed.invocation.len(), 16);
                assert_eq!(observed.count, capacity);
                assert_eq!(observed.max, capacity);
                assert_eq!(observed.notify_access, "main");
                let acquired = crate::platform::linux::fd::flock(
                    lease.as_file().as_fd(),
                    crate::platform::linux::fd::FlockMode::ExclusiveNonblocking,
                )
                .unwrap();
                assert_eq!(
                    acquired,
                    capacity == 0,
                    "barrier did not imply descriptor acceptance"
                );
                if acquired {
                    assert!(
                        crate::platform::linux::fd::flock(
                            lease.as_file().as_fd(),
                            crate::platform::linux::fd::FlockMode::Unlock
                        )
                        .unwrap()
                    );
                }
            }));
            // Cleanup has independent cancellation/deadline even when the proof panics.
            let cleanup = Cancellation::default();
            let stopped = manager
                .stop(&service.unit, timeout, &cleanup)
                .and_then(|job| manager.wait_job(&job, timeout, &cleanup));
            if let Err(panic) = proof {
                std::panic::resume_unwind(panic);
            }
            assert!(matches!(
                stopped.unwrap(),
                SystemdJobCompletion::Observed {
                    result: SystemdJobResult::Done
                }
            ));
            assert!(
                crate::platform::linux::fd::flock(
                    lease.as_file().as_fd(),
                    crate::platform::linux::fd::FlockMode::ExclusiveNonblocking
                )
                .unwrap(),
                "manager still holds the lease after completed stop"
            );
        }
    }

    #[test]
    #[ignore = "internal bounded descendant for abrupt manager fixture"]
    fn descendant_fixture() {
        assert!(std::env::var_os("SYROX_NOTIFY_ABRUPT_FIXTURE").is_some());
        std::thread::sleep(Duration::from_secs(25));
    }

    fn wait_abrupt_main(
        manager: &mut crate::systemd::SystemdManager,
        unit: &SystemdUnitName,
        cancellation: &Cancellation,
    ) {
        let end = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                std::time::Instant::now() < end,
                "main process was not observed killed with a live descendant"
            );
            let status = manager
                .query(unit, Duration::from_secs(1), cancellation)
                .unwrap()
                .unwrap();
            if status.exec_main_code == libc::CLD_KILLED && status.exec_main_status == libc::SIGKILL
            {
                assert_eq!(
                    status.active_state, "active",
                    "ExitType=cgroup must keep the descendant owned"
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
