use super::*;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::process::{Command, Stdio};

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Child {
    fn start() -> Self {
        Self(
            Command::new(crate::reexec_test_executable(
                "systemd::quiescence::tests::retirement::gated_child",
                true,
            ))
            .args([
                "--exact",
                "systemd::quiescence::tests::retirement::gated_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SYROX_CGROUP_RETIREMENT_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
        )
    }
    fn release(&mut self) {
        self.0
            .stdin
            .take()
            .unwrap()
            .write_all(b"X")
            .unwrap();
        let limit = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < limit,
                "gated cgroup child timeout"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
struct Group {
    path: PathBuf,
    directory: OpenedPath,
}
impl Group {
    fn create(path: PathBuf) -> Self {
        std::fs::create_dir(&path).unwrap();
        let directory = linux_fd::open_top_directory(&path).unwrap();
        Self {
            path,
            directory,
        }
    }
    fn migrate(&self, child: &Child) {
        let file = linux_fd::open_beneath(
            self.directory.fd(),
            Path::new("cgroup.procs"),
            false,
        )
        .unwrap();
        // The read-only descriptor pins the kernel file before its explicit
        // write-only reopening. No existing group or unrelated PID is modified.
        let path = format!("/proc/self/fd/{}", file.fd().as_raw_fd());
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .write_all(child.0.id().to_string().as_bytes())
            .unwrap();
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        if let Ok(current) = linux_fd::open_top_directory(&self.path)
            && current.metadata().identity() == self.directory.metadata().identity()
        {
            // Never recurse or delete a replacement. A populated group remains
            // as evidence if kernel cleanup cannot remove our empty child.
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

#[test]
#[ignore = "subprocess fixture; invoked only by explicit delegated-cgroup gate"]
fn gated_child() {
    assert!(std::env::var_os("SYROX_CGROUP_RETIREMENT_CHILD").is_some());
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"X");
}

#[test]
#[ignore = "requires explicit SYROX_CGROUP_RETIREMENT_PARENT delegation; creates only a new child cgroup and migrates only its own gated child"]
fn pinned_core_events_observe_populated_empty_removed_and_refuse_replacement() {
    let path = PathBuf::from(
        std::env::var_os("SYROX_CGROUP_RETIREMENT_PARENT")
            .expect("explicit delegated parent required"),
    );
    assert!(path.is_absolute() && path != Path::new(CGROUP_ROOT) && path.starts_with(CGROUP_ROOT));
    assert!(
        !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    );
    let parent = linux_fd::open_top_directory(&path).unwrap();
    require_filesystem(&parent, CGROUP2_MAGIC).unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let group = Group::create(path.join(format!(
        "syrox-retirement-{}-{nonce}",
        std::process::id()
    )));
    let events = PinnedEvents::capture(group.directory.fd()).unwrap();
    let mut child = Child::start();
    group.migrate(&child);
    assert_eq!(
        events.observe().unwrap(),
        EventsObservation::Populated
    );
    child.release();
    assert_eq!(
        events.observe().unwrap(),
        EventsObservation::Empty
    );
    let original_directory = linux_fd::open_top_directory(&group.path).unwrap();
    std::fs::remove_dir(&group.path).unwrap();
    assert_eq!(
        events.observe().unwrap(),
        EventsObservation::Removed
    );
    assert_eq!(
        events.observe().unwrap(),
        EventsObservation::Removed
    );

    let pinned = PinnedUnitCgroup {
        marker: CgroupMarker {
            boot: BootId::current(
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap(),
            binding: binding(),
            control_group: format!(
                "/{}",
                group
                    .path
                    .strip_prefix(CGROUP_ROOT)
                    .unwrap()
                    .display()
            ),
            identity: group.directory.metadata().identity(),
        },
        root: linux_fd::open_top_directory(Path::new(CGROUP_ROOT)).unwrap(),
        directory: original_directory,
        events,
        manager: crate::systemd::SystemdManagerIdentity::new(
            crate::systemd::SystemdScope::System,
            "a".repeat(32),
            ":1.1".into(),
        )
        .unwrap(),
    };
    assert!(pinned.same_directory(true).unwrap());
    let replacement = Group::create(group.path.clone());
    let mut second = Child::start();
    replacement.migrate(&second);
    assert_eq!(
        PinnedEvents::capture(replacement.directory.fd())
            .unwrap()
            .observe()
            .unwrap(),
        EventsObservation::Populated
    );
    assert_eq!(
        pinned.events.observe().unwrap(),
        EventsObservation::Removed
    );
    assert!(!pinned.same_directory(true).unwrap());
    second.release();
}
