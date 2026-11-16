use super::*;
use crate::{
    build::{
        BuildPath, BuildProfile, BuildProgram, BuildResources, BuildSourceFormat, BuildStep,
        records::Action,
    },
    system::budget::{BuildBudget, BuilderLimits},
};

fn request() -> BuildBudget {
    BuildBudget {
        memory_bytes: 8 * 1024 * 1024 * 1024,
        cpu_percent: 350,
        processes: 2048,
        descriptors: 8192,
        scratch_bytes: 64 * 1024 * 1024 * 1024,
        files: 1_000_000,
        output_bytes: 16 * 1024 * 1024 * 1024,
        duration_seconds: 7200,
    }
}

fn action(request: BuildBudget) -> SystemBuildAction {
    SystemBuildAction::new(
        Action {
            program: BuildProgram {
                profile: BuildProfile::Managed,
                resources: BuildResources::Standard,
                source_format: BuildSourceFormat::Raw,
                outputs: vec!["out".into()],
                steps: vec![BuildStep::Directory(BuildPath::Work(
                    "build".into(),
                ))],
            },
            source: ContentDigest::sha256(b"source"),
            toolchain: None,
            worker: ContentDigest::sha256(b"worker"),
            directory: "source-1".into(),
            inputs: vec![],
        },
        1024,
        BuilderLimits::new(request)
            .unwrap()
            .admit(request)
            .unwrap(),
    )
    .unwrap()
}

fn capacity() -> BuilderCapacity {
    let request = request();
    BuilderCapacity {
        memory_bytes: request.memory_bytes,
        cpu_percent: request.cpu_percent,
        processes: request.processes,
        descriptors: request.descriptors,
        files: request.files,
        shared_storage_bytes: request.storage_bytes().unwrap(),
    }
}

fn service() -> SystemdService {
    let mut service = SystemdService::new(
        SystemdUnitName::new("syrox-system-test.service").unwrap(),
        "/explicit/worker".into(),
    );
    service.arguments = vec!["literal $value".into()];
    service
        .environment
        .insert("PATH".into(), String::new());
    service.working_directory = Some("/explicit/work".into());
    service.memory_max = Some(123);
    service.tasks_max = Some(2);
    service.runtime_max = Some(Duration::from_secs(120));
    service
}

#[test]
fn action_limits_replace_common_envelope_and_preserve_operational_selections() {
    let action = action(request());
    let limits = action.service_limits().unwrap();
    assert_eq!(limits.action_digest(), action.digest());
    assert_eq!(limits.budget(), action.budget());
    let mut target = service();
    let before = format!("{target:?}");
    assert!(limits.verify_service(&target).is_err());
    limits.apply(&mut target, capacity()).unwrap();
    limits.verify_service(&target).unwrap();
    assert_eq!(target.memory_max, Some(8 * 1024 * 1024 * 1024));
    assert_eq!(target.tasks_max, Some(2048));
    assert_eq!(
        target.runtime_max,
        Some(Duration::from_secs(7200))
    );
    assert_eq!(target.build_limits.unwrap().cpu_percent, 350);
    assert_eq!(target.build_limits.unwrap().nofile, 8192);
    assert_eq!(
        target.build_limits.unwrap().file_size,
        64 * 1024 * 1024 * 1024
    );
    // Restore only the resource fields. Every other selected property must be
    // identical, including arguments with characters a shell would expand.
    let original = service();
    target.memory_max = original.memory_max;
    target.tasks_max = original.tasks_max;
    target.runtime_max = original.runtime_max;
    target.build_limits = original.build_limits;
    assert_eq!(format!("{target:?}"), before);
    assert_eq!(
        action.program().resources,
        BuildResources::Standard
    );
    assert_eq!(
        BuildResources::Standard.envelope().memory,
        768 * 1024 * 1024
    );
}

#[test]
fn each_capacity_denial_precedes_any_service_mutation() {
    let limits = action(request()).service_limits().unwrap();
    for index in 0..6 {
        let mut capacity = capacity();
        match index {
            0 => capacity.memory_bytes -= 1,
            1 => capacity.cpu_percent -= 1,
            2 => capacity.processes -= 1,
            3 => capacity.descriptors -= 1,
            4 => capacity.files -= 1,
            5 => capacity.shared_storage_bytes -= 1,
            _ => unreachable!(),
        }
        let mut target = service();
        let before = format!("{target:?}");
        assert!(matches!(
            limits.apply(&mut target, capacity),
            Err(BuildError::Budget(_))
        ));
        assert_eq!(format!("{target:?}"), before);
    }
}

#[test]
fn individual_file_limit_covers_scratch_and_output_without_infinity() {
    let mut request = request();
    request.output_bytes = request.scratch_bytes * 2;
    let limits = action(request).service_limits().unwrap();
    assert_eq!(limits.process.file_size, request.output_bytes);
    // Scratch/output cannot reach UINT64_MAX individually because pure budget
    // validation also checks their sum. Memory can, and is refused here instead
    // of accidentally requesting the manager's infinity sentinel.
    request.memory_bytes = u64::MAX;
    assert!(matches!(
        action(request).service_limits(),
        Err(BuildError::InvalidRequest)
    ));
}

#[test]
fn every_changed_manager_limit_invalidates_the_expected_service() {
    let limits = action(request()).service_limits().unwrap();
    let mut target = service();
    limits.apply(&mut target, capacity()).unwrap();
    for index in 0..6 {
        let mut changed = target.clone();
        match index {
            0 => changed.memory_max = None,
            1 => changed.tasks_max = Some(2049),
            2 => changed.runtime_max = Some(Duration::from_secs(120)),
            3 => changed.build_limits.as_mut().unwrap().cpu_percent += 1,
            4 => changed.build_limits.as_mut().unwrap().nofile += 1,
            5 => changed.build_limits.as_mut().unwrap().file_size += 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            limits.verify_service(&changed),
            Err(BuildError::InputChanged)
        ));
    }
    let mut changed = target;
    changed.build_limits = None;
    assert!(limits.verify_service(&changed).is_err());
}
