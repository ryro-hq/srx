//! Core instruction tests; these do not bypass the guarded worker entry in use.

use super::*;
use crate::{
    build::{
        BuildPart, BuildPath, BuildProfile, BuildProgram, BuildResources, BuildSourceFormat,
        BuildStep, BuildText, records::Action,
    },
    system::{
        budget::{BuildBudget, BuilderLimits},
        workspace::{WorkspaceObservation, WorkspaceVolumeObservation},
    },
};
use std::{fs, io::Write as _, os::unix::fs::FileExt as _};

fn request() -> BuildBudget {
    BuildBudget {
        memory_bytes: 268_435_456,
        cpu_percent: 100,
        processes: 16,
        descriptors: 128,
        scratch_bytes: 2 * 1024 * 1024 * 1024,
        files: 100_000,
        output_bytes: 67_108_864,
        duration_seconds: 180,
    }
}
fn action(
    steps: Vec<BuildStep>,
    format: BuildSourceFormat,
    request: BuildBudget,
) -> SystemBuildAction {
    let budget = BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap();
    SystemBuildAction::new(
        Action {
            program: BuildProgram {
                profile: BuildProfile::Managed,
                resources: BuildResources::Standard,
                source_format: format,
                outputs: vec!["out".into()],
                steps,
            },
            source: ContentDigest::sha256(b"source"),
            worker: ContentDigest::sha256(b"worker"),
            directory: "source-1".into(),
            toolchain: None,
            inputs: vec![],
        },
        64 * 1024 * 1024,
        budget,
    )
    .unwrap()
}
fn paths(root: &Path, action: &SystemBuildAction) -> Paths {
    let paths = Paths {
        work: root.join("work"),
        source: root.join("source"),
        output: root.join("out").join(action.digest().to_string()),
        installed: format!("/syrox/store/{}", action.digest()).into(),
        inputs: vec![],
    };
    fs::create_dir(&paths.work).unwrap();
    paths
}
fn out(path: &str) -> BuildPath {
    BuildPath::Output {
        name: "out".into(),
        path: path.into(),
    }
}
fn gzip_source(path: &Path) {
    let mut header = [0_u8; 512];
    let name = b"pkg/source";
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000005\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut gzip = flate2::write::GzEncoder::new(
        File::create(path).unwrap(),
        flate2::Compression::fast(),
    );
    gzip.write_all(&header).unwrap();
    gzip.write_all(b"input").unwrap();
    gzip.write_all(&[0; 507]).unwrap();
    gzip.write_all(&[0; 1024]).unwrap();
    gzip.finish().unwrap();
}

#[test]
fn system_steps_extract_copy_move_and_write_with_one_settlement_per_step() {
    let steps = vec![
        BuildStep::Directory(BuildPath::Work("build".into())),
        BuildStep::Write {
            path: BuildPath::Work("build/generated".into()),
            text: BuildText(vec![BuildPart::Literal("generated".into())]),
            executable: false,
        },
        BuildStep::Copy {
            source: BuildPath::Work("build/generated".into()),
            destination: out("copy"),
        },
        BuildStep::Move {
            source: BuildPath::Work("build/generated".into()),
            destination: out("moved"),
        },
        BuildStep::Extract(BuildPath::Work("unpacked".into())),
        BuildStep::Copy {
            source: BuildPath::Work("unpacked/pkg/source".into()),
            destination: out("source"),
        },
        BuildStep::Extract(out("archive")),
    ];
    let count = steps.len();
    let selected = action(steps, BuildSourceFormat::Gzip, request());
    let directory = tempfile::tempdir().unwrap();
    let paths = paths(directory.path(), &selected);
    gzip_source(&paths.source);
    let mut settled = 0;
    execute_system_program(
        &selected,
        &paths,
        &Cancellation::default(),
        || {
            settled += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(settled, count);
    assert_eq!(
        fs::read(paths.output.join("out/copy")).unwrap(),
        b"generated"
    );
    assert_eq!(
        fs::read(paths.output.join("out/moved")).unwrap(),
        b"generated"
    );
    assert!(!paths.work.join("build/generated").exists());
    assert_eq!(
        fs::read(paths.output.join("out/source")).unwrap(),
        b"input"
    );
    assert_eq!(
        fs::read(paths.output.join("out/archive/pkg/source")).unwrap(),
        b"input"
    );
}

#[test]
fn output_role_ceiling_refuses_before_copying_a_file_that_fits_scratch() {
    let selected = action(
        vec![BuildStep::Copy {
            source: BuildPath::Work("large".into()),
            destination: out("large"),
        }],
        BuildSourceFormat::Raw,
        request(),
    );
    let directory = tempfile::tempdir().unwrap();
    let paths = paths(directory.path(), &selected);
    let source = File::create(paths.work.join("large")).unwrap();
    source
        .set_len(request().output_bytes + 1)
        .unwrap();
    assert!(matches!(
        execute_system_program(
            &selected,
            &paths,
            &Cancellation::default(),
            || Ok(())
        ),
        Err(BuildError::Output)
    ));
    assert!(!paths.output.join("out/large").exists());
    assert_eq!(
        source.metadata().unwrap().len(),
        request().output_bytes + 1
    );
}

#[test]
fn system_copy_exceeds_legacy_large_scratch_limit_without_expanding_that_profile() {
    let selected = action(
        vec![BuildStep::Copy {
            source: BuildPath::Work("large".into()),
            destination: BuildPath::Work("copied".into()),
        }],
        BuildSourceFormat::Raw,
        request(),
    );
    let directory = tempfile::tempdir().unwrap();
    let paths = paths(directory.path(), &selected);
    let bytes = 1024 * 1024 * 1024 + 17;
    let available = available_bytes(directory.path());
    if available < bytes + 64 * 1024 * 1024 {
        // Small tmpfs scratch (the VM guest) cannot hold the dense copy; the
        // property is still proven wherever the temporary directory fits it.
        println!("SRX_SYSTEM_COPY_LARGE_SKIPPED available={available} required={bytes}");
        return;
    }
    let source = File::create(paths.work.join("large")).unwrap();
    source.set_len(bytes).unwrap();
    source
        .write_all_at(b"system-copy-proof", bytes - 17)
        .unwrap();
    assert!(matches!(
        super::super::files::transfer(
            &paths.work.join("large"),
            &paths.work.join("legacy"),
            false,
            BuildResources::Large,
            &mut || Ok(())
        ),
        Err(BuildError::Output)
    ));
    assert!(!paths.work.join("legacy").exists());
    execute_system_program(
        &selected,
        &paths,
        &Cancellation::default(),
        || Ok(()),
    )
    .unwrap();
    let copy = File::open(paths.work.join("copied")).unwrap();
    assert_eq!(copy.metadata().unwrap().len(), bytes);
    let mut tail = [0; 17];
    copy.read_exact_at(&mut tail, bytes - 17).unwrap();
    assert_eq!(&tail, b"system-copy-proof");
}

fn available_bytes(path: &Path) -> u64 {
    use std::os::fd::AsRawFd as _;
    let directory = File::open(path).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: live descriptor and writable exact ABI storage.
    #[allow(unsafe_code)]
    let status = unsafe { libc::fstatvfs(directory.as_raw_fd(), stat.as_mut_ptr()) };
    assert_eq!(status, 0, "{}", io::Error::last_os_error());
    // SAFETY: fstatvfs initialized the structure on success.
    #[allow(unsafe_code)]
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail.saturating_mul(stat.f_frsize)
}

#[test]
fn cancellation_and_unsupported_workspace_geometry_precede_instruction_effects() {
    let selected = action(
        vec![BuildStep::Write {
            path: out("file"),
            text: BuildText(vec![BuildPart::Literal("data".into())]),
            executable: false,
        }],
        BuildSourceFormat::Raw,
        request(),
    );
    let directory = tempfile::tempdir().unwrap();
    let paths = paths(directory.path(), &selected);
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(matches!(
        execute_system_program(&selected, &paths, &cancellation, || Ok(())),
        Err(BuildError::Cancelled)
    ));
    assert!(!paths.output.exists());
    let unsupported = action(
        selected.program().steps.clone(),
        BuildSourceFormat::Raw,
        BuildBudget {
            output_bytes: 1024 * 1024,
            ..request()
        },
    );
    assert!(
        execute_system_program(
            &unsupported,
            &paths,
            &Cancellation::default(),
            || Ok(())
        )
        .is_err()
    );
    assert!(!paths.output.exists());
}

#[test]
fn host_environment_never_satisfies_the_system_worker_namespace_contract() {
    let selected = action(
        vec![BuildStep::Directory(BuildPath::Work(
            "directory".into(),
        ))],
        BuildSourceFormat::Raw,
        request(),
    );
    let layout = selected.workspace_layout().unwrap();
    let volume = WorkspaceVolumeObservation {
        device: 1,
        inode: 2,
        filesystem_bytes: 67_108_864,
        inodes: 256,
    };
    let observation = WorkspaceObservation {
        layout_sha256: layout.digest(),
        scratch: volume,
        output: WorkspaceVolumeObservation {
            device: 2,
            ..volume
        },
    };
    assert!(
        crate::execution::native::build_policy::validate_system_environment(&layout, &observation)
            .is_err()
    );
}
