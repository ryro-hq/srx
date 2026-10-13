use super::*;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::time::Duration;

fn parent() -> tempfile::TempDir {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    parent
}
fn create(parent: &Path) -> SessionState {
    SessionState::create_names(
        BTreeSet::from(["database".into()]),
        parent,
        &Cancellation::default(),
    )
    .unwrap()
}
fn close(state: SessionState) -> io::Result<()> {
    state.close(
        &Cancellation::default(),
        Instant::now() + Duration::from_secs(5),
    )
}
#[test]
fn sessions_isolate_state_while_consumers_share_the_same_directory() {
    let parent = parent();
    let first = create(parent.path());
    let second = create(parent.path());
    let first_path = first.path().to_owned();
    assert_ne!(
        first.root.metadata().identity(),
        second.root.metadata().identity()
    );
    let a = first
        .configure("database", RuntimeConfiguration::default())
        .unwrap();
    let b = first
        .configure("database", RuntimeConfiguration::default())
        .unwrap();
    drop((a, b));
    let a = &first.services["database"];
    let b = &first.services["database"];
    fs::write(anchored(a, Path::new("value")), b"mutable bytes").unwrap();
    assert_eq!(
        fs::read(anchored(b, Path::new("value"))).unwrap(),
        b"mutable bytes"
    );
    assert!(!second.path().join("database/value").exists());
    assert!(
        !String::from_utf8(first.inventory.clone())
            .unwrap()
            .contains("mutable bytes")
    );
    close(first).unwrap();
    assert!(!first_path.exists());
    close(second).unwrap();
}
#[test]
fn drop_preserves_data_and_inventory_for_recovery() {
    let parent = parent();
    let state = create(parent.path());
    let path = state.path().to_owned();
    fs::write(path.join("database/value"), b"not Store content").unwrap();
    drop(state);
    assert!(path.join(INVENTORY).is_file());
    assert_eq!(
        fs::read(path.join("database/value")).unwrap(),
        b"not Store content"
    );
}
#[test]
fn replacement_is_not_removed_and_symlink_targets_are_never_traversed() {
    let parent = parent();
    let state = create(parent.path());
    let foreign = parent.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("keep"), b"foreign").unwrap();
    symlink(&foreign, state.path().join("database/link")).unwrap();
    close(state).unwrap();
    assert_eq!(
        fs::read(foreign.join("keep")).unwrap(),
        b"foreign"
    );
    let state = create(parent.path());
    fs::rename(
        state.path().join("database"),
        state.path().join("original"),
    )
    .unwrap();
    fs::create_dir(state.path().join("database")).unwrap();
    fs::write(state.path().join("database/foreign"), b"preserve").unwrap();
    let root = state.path().to_owned();
    assert!(close(state).is_err());
    assert!(root.join("database/foreign").is_file());
    assert!(root.join(INVENTORY).is_file());
}
#[test]
fn cancel_and_inventory_corruption_do_not_delete_data() {
    let parent = parent();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(
        SessionState::create_names(
            BTreeSet::from(["database".into()]),
            parent.path(),
            &cancel
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    let state = create(parent.path());
    let root = state.path().to_owned();
    fs::write(root.join("database/value"), b"retain").unwrap();
    assert!(
        state
            .close(&cancel, Instant::now() + Duration::from_secs(5))
            .is_err()
    );
    assert!(root.join("database/value").exists());
    let state = create(parent.path());
    let root = state.path().to_owned();
    let inventory = root.join(INVENTORY);
    fs::set_permissions(&inventory, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&inventory, b"{} ").unwrap();
    assert!(close(state).is_err());
    assert!(root.join("database").exists());
}
#[test]
fn state_root_is_private_and_no_mount_traversal_helper_rejects_proc() {
    let parent = parent();
    let state = create(parent.path());
    assert_eq!(
        fs::metadata(state.path().join("database"))
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
    let root = linux_fd::open_top_directory(Path::new("/")).unwrap();
    assert!(linux_fd::open_beneath_no_mounts(root.fd(), Path::new("proc"), true).is_err());
    close(state).unwrap();
}

#[test]
fn root_replacement_and_excessive_depth_preserve_inventory_and_data() {
    let parent = parent();
    let state = create(parent.path());
    let original = state.path().to_owned();
    let moved = parent.path().join("moved");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join("foreign"), b"keep").unwrap();
    assert!(close(state).is_err());
    assert!(original.join("foreign").is_file());
    assert!(moved.join(INVENTORY).is_file());

    let state = create(parent.path());
    let root = state.path().to_owned();
    let mut deep = root.join("database");
    for _ in 0..33 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }
    fs::write(deep.join("value"), b"preserve on refused cleanup").unwrap();
    assert!(close(state).is_err());
    assert!(deep.join("value").is_file());
    assert!(root.join(INVENTORY).is_file());
}

#[test]
fn inventory_is_a_legal_service_name_without_metadata_collision() {
    let parent = parent();
    let state = SessionState::create_names(
        BTreeSet::from(["inventory".into()]),
        parent.path(),
        &Cancellation::default(),
    )
    .unwrap();
    assert!(state.path().join("inventory").is_dir());
    assert!(state.path().join(INVENTORY).is_file());
    close(state).unwrap();
}
