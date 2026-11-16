use super::*;
use crate::system::budget::BuilderCapacity;
use std::time::{Duration, Instant};

fn capacity(inputs: &SystemBuildInputs) -> BuilderCapacity {
    let budget = inputs.action().budget().request();
    BuilderCapacity {
        memory_bytes: budget.memory_bytes,
        cpu_percent: budget.cpu_percent,
        processes: budget.processes,
        descriptors: budget.descriptors,
        files: budget.files,
        shared_storage_bytes: budget.storage_bytes().unwrap(),
    }
}

#[test]
fn scratch_invalid_identifiers_capacity_cancellation_and_deadlines_precede_helper_io() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    let cancel = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(2);
    for id in [
        "",
        "bad",
        "A123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef/extra",
    ] {
        assert!(matches!(
            inputs.prepare_scratch(id, capacity(&inputs), &cancel, deadline),
            Err(BuildError::InvalidRequest)
        ));
    }
    for index in 0..6 {
        let mut available = capacity(&inputs);
        match index {
            0 => available.memory_bytes -= 1,
            1 => available.cpu_percent -= 1,
            2 => available.processes -= 1,
            3 => available.descriptors -= 1,
            4 => available.files -= 1,
            5 => available.shared_storage_bytes -= 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            inputs.prepare_scratch(
                "0123456789abcdef0123456789abcdef",
                available,
                &cancel,
                deadline
            ),
            Err(BuildError::Budget(_))
        ));
    }
    assert!(matches!(
        inputs.prepare_scratch(
            "0123456789abcdef0123456789abcdef",
            capacity(&inputs),
            &cancel,
            Instant::now()
        ),
        Err(BuildError::Timeout)
    ));
    cancel.cancel();
    assert!(matches!(
        inputs.prepare_scratch(
            "0123456789abcdef0123456789abcdef",
            capacity(&inputs),
            &cancel,
            deadline
        ),
        Err(BuildError::Cancelled)
    ));
    assert_eq!(fixture.operations(), 0);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn workspace_preflight_refuses_invalid_authority_capacity_and_cancellation_before_helper_io() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    let cancel = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    for id in [
        "",
        "bad",
        "ABCDEF0123456789abcdef0123456789",
        "0123456789abcdef0123456789abcdef/extra",
    ] {
        assert!(matches!(
            inputs.prepare_workspace(id, capacity(&inputs), &cancel, deadline),
            Err(BuildError::InvalidRequest)
        ));
    }
    for index in 0..6 {
        let mut available = capacity(&inputs);
        match index {
            0 => available.memory_bytes -= 1,
            1 => available.cpu_percent -= 1,
            2 => available.processes -= 1,
            3 => available.descriptors -= 1,
            4 => available.files -= 1,
            5 => available.shared_storage_bytes -= 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            inputs.prepare_workspace(
                "0123456789abcdef0123456789abcdef",
                available,
                &cancel,
                deadline
            ),
            Err(BuildError::Budget(_))
        ));
    }
    assert!(matches!(
        inputs.prepare_workspace(
            "0123456789abcdef0123456789abcdef",
            capacity(&inputs),
            &cancel,
            Instant::now()
        ),
        Err(BuildError::Timeout)
    ));
    cancel.cancel();
    assert!(matches!(
        inputs.prepare_workspace(
            "0123456789abcdef0123456789abcdef",
            capacity(&inputs),
            &cancel,
            deadline
        ),
        Err(BuildError::Cancelled)
    ));
    assert_eq!(fixture.operations(), 0);
}

#[test]
fn changed_source_cannot_allocate_helper_scratch() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    let pin = inputs.action().source_digest().to_string();
    let source = fixture.directory.path().join(format!(
        "store/objects/sha256/{}/{pin}",
        &pin[..2]
    ));
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&source, [0x41; 12]).unwrap();
    assert!(matches!(
        inputs.prepare_scratch(
            "0123456789abcdef0123456789abcdef",
            capacity(&inputs),
            &Cancellation::default(),
            Instant::now() + Duration::from_secs(2)
        ),
        Err(BuildError::InputChanged)
    ));
    assert_eq!(fixture.operations(), 0);
    #[cfg(target_arch = "x86_64")]
    assert!(matches!(
        inputs.prepare_workspace(
            "0123456789abcdef0123456789abcdef",
            capacity(&inputs),
            &Cancellation::default(),
            Instant::now() + Duration::from_secs(2)
        ),
        Err(BuildError::InputChanged)
    ));
}

#[test]
#[ignore = "requires the marked disposable QEMU guest and explicitly activated private root scratch helper"]
fn disposable_vm_system_scratch_uses_prepared_action_and_private_helper() {
    use crate::platform::linux::fd as linux_fd;
    use std::os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    };
    // The root driver already verifies the content. Its 0600 marker must remain
    // unreadable to this non-root test; require the original root-owned shape.
    let marker = fs::symlink_metadata("/etc/srx-disposable-vm").unwrap();
    assert!(marker.is_file());
    assert_eq!(
        (marker.uid(), marker.mode() & 0o7777, marker.len()),
        (0, 0o600, 20)
    );
    assert_eq!(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .unwrap()
            .trim(),
        "QEMU"
    );
    assert_eq!(
        (
            linux_fd::real_uid(),
            linux_fd::effective_uid(),
            linux_fd::real_gid(),
            linux_fd::effective_gid()
        ),
        (1000, 1000, 1000, 1000)
    );
    let mut fixture = fixture(12);
    let source = fixture.directory.path().join("main.srx");
    let mut declaration = fs::read_to_string(&source).unwrap();
    for (old, new) in [
        (
            "memory_bytes = 1073741824;",
            "memory_bytes = 134217728;",
        ),
        ("processes = 256;", "processes = 16;"),
        ("descriptors = 1024;", "descriptors = 128;"),
        (
            "scratch_bytes = 1073741824;",
            "scratch_bytes = 67108864;",
        ),
        ("files = 100000;", "files = 512;"),
        (
            "output_bytes = 268435456;",
            "output_bytes = 1048576;",
        ),
        (
            "duration_seconds = 7200;",
            "duration_seconds = 180;",
        ),
    ] {
        assert!(declaration.contains(old));
        declaration = declaration.replace(old, new);
    }
    fs::write(source, declaration).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(fixture.directory.path(), &checks).unwrap_or_else(|e| panic!("VM lock: {e}"));
    fixture.plan = plan_project_with(fixture.directory.path(), &checks)
        .unwrap_or_else(|e| panic!("VM plan: {e}"));
    fixture.request = fixture
        .plan
        .builds()
        .find(|b| b.package().as_str() == "system-component")
        .unwrap()
        .request();
    fixture.configuration = configuration_at(
        ContentDigest::sha256(&fixture.worker),
        "/run/syrox-system-helper-probe.sock",
    );
    let cancel = Cancellation::default();
    let inputs = fixture.prepare().unwrap();
    let action = inputs.action().digest();
    let deadline = Instant::now() + Duration::from_secs(180);
    let scratch = inputs
        .prepare_scratch(
            "88888888888888888888888888888888",
            capacity(&inputs),
            &cancel,
            deadline,
        )
        .unwrap();
    assert_eq!(scratch.action_digest(), action);
    assert!(scratch.capacity().filesystem_bytes <= 67_108_864);
    assert!(scratch.capacity().inodes <= 512);
    let root = scratch
        .root_descriptor(&cancel, deadline)
        .unwrap();
    let path = format!(
        "/proc/self/fd/{}/system-component-proof",
        root.as_raw_fd()
    );
    let mut proof = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    proof
        .write_all(action.to_string().as_bytes())
        .unwrap();
    proof.sync_all().unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        action.to_string().as_bytes()
    );
    drop(proof);
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain);
    assert!(report.failures.is_empty());
    inputs.revalidate(&cancel).unwrap();
    drop(root);
    let receipt = scratch.release(&cancel, deadline).unwrap();
    assert_eq!(receipt["state"], "released");
    assert_eq!(receipt["details"]["image_retained"], true);
    assert_eq!(fixture.operations(), 0);
    println!("SRX_SYSTEM_COMPONENT_SCRATCH_OK {action}");
}

#[test]
#[cfg(target_arch = "x86_64")]
#[ignore = "requires the marked disposable QEMU guest and an explicitly selected two-volume root helper"]
fn disposable_vm_system_workspace_retains_prepared_inputs_through_gc_and_release() {
    use crate::platform::linux::fd as linux_fd;
    use std::os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    };
    let marker = fs::symlink_metadata("/etc/srx-disposable-vm").unwrap();
    assert!(marker.is_file());
    assert_eq!(
        (marker.uid(), marker.mode() & 0o7777, marker.len()),
        (0, 0o600, 20)
    );
    assert_eq!(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .unwrap()
            .trim(),
        "QEMU"
    );
    assert_eq!(
        (
            linux_fd::real_uid(),
            linux_fd::effective_uid(),
            linux_fd::real_gid(),
            linux_fd::effective_gid()
        ),
        (1000, 1000, 1000, 1000)
    );
    let endpoint = std::env::var("SRX_SYSTEM_WORKSPACE_VM_HELPER")
        .expect("explicit disposable helper endpoint");
    let mut fixture = fixture(12);
    let source = fixture.directory.path().join("main.srx");
    let mut declaration = fs::read_to_string(&source).unwrap();
    for (old, new) in [
        (
            "memory_bytes = 1073741824;",
            "memory_bytes = 134217728;",
        ),
        ("processes = 256;", "processes = 16;"),
        ("descriptors = 1024;", "descriptors = 128;"),
        (
            "scratch_bytes = 1073741824;",
            "scratch_bytes = 67108864;",
        ),
        ("files = 100000;", "files = 1024;"),
        (
            "output_bytes = 268435456;",
            "output_bytes = 134217728;",
        ),
        (
            "duration_seconds = 7200;",
            "duration_seconds = 180;",
        ),
    ] {
        assert!(declaration.contains(old));
        declaration = declaration.replace(old, new);
    }
    fs::write(source, declaration).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(fixture.directory.path(), &checks).unwrap();
    fixture.plan = plan_project_with(fixture.directory.path(), &checks).unwrap();
    fixture.request = fixture
        .plan
        .builds()
        .find(|b| b.package().as_str() == "system-component")
        .unwrap()
        .request();
    fixture.configuration = configuration_at(ContentDigest::sha256(&fixture.worker), &endpoint);
    let cancel = Cancellation::default();
    let inputs = fixture.prepare().unwrap();
    let action = inputs.action().digest();
    let deadline = Instant::now() + Duration::from_secs(180);
    let workspace = inputs
        .prepare_workspace(
            "99999999999999999999999999999999",
            capacity(&inputs),
            &cancel,
            deadline,
        )
        .unwrap();
    assert_eq!(workspace.action_digest(), action);
    assert_eq!(
        workspace.layout(),
        &inputs.action().workspace_layout().unwrap()
    );
    assert_eq!(
        (
            workspace.observation().scratch.inodes,
            workspace.observation().output.inodes
        ),
        (336, 672)
    );
    let (scratch, output) = workspace
        .root_descriptors(&cancel, deadline)
        .unwrap();
    for (role, root) in [
        ("scratch", &scratch),
        ("output", &output),
    ] {
        let path = format!(
            "/proc/self/fd/{}/component-{role}",
            root.as_raw_fd()
        );
        let mut proof = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        proof
            .write_all(action.to_string().as_bytes())
            .unwrap();
        proof.sync_all().unwrap();
        assert_eq!(
            fs::read(path).unwrap(),
            action.to_string().as_bytes()
        );
    }
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain);
    assert!(report.failures.is_empty());
    inputs.revalidate(&cancel).unwrap();
    assert_eq!(
        fs::read(format!(
            "/proc/self/fd/{}/component-output",
            output.as_raw_fd()
        ))
        .unwrap(),
        action.to_string().as_bytes()
    );
    drop(scratch);
    drop(output);
    let receipt = workspace.release(&cancel, deadline).unwrap();
    assert_eq!(receipt["state"], "released");
    assert_eq!(receipt["details"]["images"], 2);
    assert_eq!(receipt["details"]["image_retained"], true);
    assert_eq!(fixture.operations(), 0);
    println!("SRX_SYSTEM_COMPONENT_WORKSPACE_OK {action}");
}
