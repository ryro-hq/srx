use super::{BuildProgress, RealizeContext, RealizeError, RealizeOptions, ResolvedBuild, outputs};
use crate::{
    build::BuildInput, build::BuildResult, cancellation::Cancellation,
    config::ManagedBuildConfiguration, config::UserConfiguration, store::ContentDigest,
    store::ObjectLease, store::RootName, store::Store,
};
use sha2::{Digest as _, Sha256};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
#[cfg(test)]
use std::path::Path;

const MAX_WORKER_BYTES: u64 = 128 * 1024 * 1024;

pub(super) fn realize(
    resolved: &ResolvedBuild,
    context: &RealizeContext<'_>,
    cancellation: &Cancellation,
    mut progress: impl FnMut(BuildProgress),
) -> Result<BuildResult, RealizeError> {
    let RealizeOptions {
        configuration: user,
        offline,
        ..
    } = context.options;
    cancellation.check()?;
    let configuration = user
        .managed_build()
        .ok_or(RealizeError::MissingManagedConfiguration)?;
    // Candidate refusal precedes Store initialization, transport and staging.
    let worker = read_worker(configuration, cancellation)?;
    progress(BuildProgress::PreparingStore);
    cancellation.check()?;
    let store = context.store()?;
    let source = ensure_source(
        resolved,
        user,
        store,
        offline,
        cancellation,
        &mut progress,
    )?;
    let mut inputs = Vec::new();
    let mut views = Vec::new();
    for selected in resolved.build.inputs() {
        cancellation.check()?;
        let output = super::resolve_plan_output(&resolved.prepared, selected)?;
        let package = outputs::realize_package(
            &output,
            context,
            cancellation,
            &mut progress as &mut dyn FnMut(BuildProgress),
        )?;
        let (view, output) = package.materialize(store, &selected.output, cancellation)?;
        views.push(view);
        inputs.push(BuildInput {
            output,
        });
        // The admitted package may own temporary Store access; only granular
        // view retention crosses the next dependency's execution.
    }
    let request = crate::build::BuildSpecification {
        inputs,
        ..resolved.build.request()
    };
    let prepared = crate::build::managed::preparation::prepare_managed_build_inputs(
        resolved.prepared.plan(),
        &request,
        store,
        &worker,
        cancellation,
    )?;
    drop((source, views));
    progress(BuildProgress::Building);
    cancellation.check()?;
    Ok(prepared.execute(store, configuration, None, cancellation)?)
}

fn read_worker(
    configuration: &ManagedBuildConfiguration,
    cancellation: &Cancellation,
) -> Result<Vec<u8>, RealizeError> {
    cancellation.check()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(configuration.worker())?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_WORKER_BYTES {
        return Err(RealizeError::ManagedWorker(
            "expected a nonempty regular file of at most 128 MiB",
        ));
    }
    let mut bytes = Vec::new();
    let mut hash = Sha256::new();
    let mut chunk = [0; 16 * 1024];
    loop {
        cancellation.check()?;
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 + read as u64 > MAX_WORKER_BYTES {
            return Err(RealizeError::ManagedWorker(
                "worker exceeds 128 MiB",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        hash.update(&chunk[..read]);
    }
    let after = file.metadata()?;
    if metadata_identity(&before) != metadata_identity(&after) || bytes.len() as u64 != before.len()
    {
        return Err(RealizeError::ManagedWorker(
            "worker changed while reading",
        ));
    }
    cancellation.check()?;
    if ContentDigest::from_sha256_hash(hash.finalize().into()) != configuration.worker_digest() {
        return Err(RealizeError::ManagedWorker(
            "worker SHA-256 does not match configuration",
        ));
    }
    crate::runtime::validate_static_worker_image(&bytes)
        .map_err(|_| RealizeError::ManagedWorker("worker must be a static ELF executable"))?;
    Ok(bytes)
}

fn metadata_identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn ensure_source(
    resolved: &ResolvedBuild,
    user: &UserConfiguration,
    store: &Store,
    offline: bool,
    cancellation: &Cancellation,
    mut progress: impl FnMut(BuildProgress),
) -> Result<ObjectLease, RealizeError> {
    let source = resolved
        .prepared
        .plan()
        .acquisitions()
        .find(|entry| entry.package() == resolved.build.package())
        .and_then(|entry| entry.sources().next())
        .expect("validated build source");
    let limit = source
        .maximum_bytes()
        .min(resolved.build.program().maximum_source_bytes());
    {
        let lease = store.operation()?;
        if super::source_cached(&lease, source.digest(), limit, cancellation)? {
            let interest = lease.retain_objects(&[source.digest()], &[])?;
            progress(BuildProgress::SourceCacheHit);
            return Ok(interest);
        }
    }
    if offline && source.url().starts_with("https://") {
        return Err(RealizeError::OfflineMissing(source.digest()));
    }
    if !source.url().starts_with("https://") && !source.url().starts_with("project:") {
        return Err(RealizeError::UnsupportedSource);
    }
    if source.url().starts_with("https://") && !user.permits_https(source.url()) {
        return Err(RealizeError::SourceDenied(
            source.url().to_owned(),
        ));
    }
    progress(BuildProgress::AcquiringSource);
    cancellation.check()?;
    let root = RootName::new(format!("source_{}", source.digest())).expect("bounded digest root");
    if let Some(relative) = source.url().strip_prefix("project:") {
        let origin = source
            .owner()
            .and_then(|owner| resolved.prepared.project_root(owner))
            .ok_or(RealizeError::UnsupportedSource)?;
        super::acquire_build_local(
            store,
            origin,
            relative,
            source.digest(),
            limit,
            &root,
            cancellation,
        )?;
    } else {
        super::acquire_build_https(
            store,
            source.url(),
            source.digest(),
            limit,
            &root,
            user.https_redirect_origins(),
            cancellation,
        )?;
    }
    let lease = store.operation()?;
    Ok(lease.retain_objects(&[source.digest()], &[])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{project::AuthenticatedStandardLibrary, project::CheckConfiguration};
    use std::fs;
    use std::os::unix::fs::symlink;

    fn fixture(url: &str) -> (tempfile::TempDir, ResolvedBuild) {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        let source = ContentDigest::sha256(b"managed source");
        fs::write(project.join("main.srx"), format!(r#"mod factories::recipe {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "managed"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("{url}", "{source}", 1024)]; }});
            build = std::Option::Some(std::Build {{ profile = std::BuildProfile::Managed;
                source_directory = "source"; timeout_seconds = 30; source_format = std::BuildSourceFormat::Raw;
                steps = [std::BuildStep::Directory(std::BuildPath::Output("out", "proof"))]; }});
            commands = [std::Command {{ name = "test"; output = "out"; path = "bin/test"; }}];
        }} }} }} pub publish(factories, recipe): std::Recipe;
        outputs {{
            os: std::Os = std::Os {{ pkgs = [std::select_package(recipe)]; services = []; }};
            shell: std::Shell = std::Shell {{ pkgs = [std::select_package(recipe)]; services = []; }};
        }}"#)).unwrap();
        let checks = CheckConfiguration {
            standard_library: Some(AuthenticatedStandardLibrary::bundled()),
            ..CheckConfiguration::default()
        };
        crate::project::lock_project_with(&project, &checks).unwrap();
        let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
        let resolved = super::super::resolve_build(
            &format!("{}#recipe", project.display()),
            &user,
            &checks,
        )
        .unwrap();
        (temp, resolved)
    }
    fn static_image() -> Vec<u8> {
        // Synthetic metadata exercises admission refusal before any launch. This
        // fixture is never executed and is not evidence of a working static worker.
        let mut bytes = crate::runtime::tests::elf(2, None, &[], None, None);
        bytes[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes
    }
    fn configuration(root: &Path, worker: &Path, pin: ContentDigest) -> UserConfiguration {
        UserConfiguration::parse(&format!(
            "[build.managed]\nworker='{}'\nworker-sha256='{pin}'\nscope='user'\nuser-bus='{}'\nsocket-parent='{}'\n",
            worker.display(), root.join("missing-bus").display(), root.join("missing-sockets").display(),
        ), root.join("store")).unwrap()
    }
    fn no_staging(user: &UserConfiguration) {
        let store = Store::open(user.store()).unwrap();
        let lease = store.operation().unwrap();
        let directory = lease.build_directory().unwrap();
        let names =
            crate::platform::linux::fd::read_directory(&directory, |_| Ok::<_, ()>(())).unwrap();
        assert!(
            names.is_empty(),
            "no staging operation may be created: {names:?}"
        );
    }
    fn run(
        resolved: &ResolvedBuild,
        user: &UserConfiguration,
        offline: bool,
    ) -> Result<BuildResult, RealizeError> {
        super::super::realize_build(
            resolved,
            RealizeOptions {
                configuration: user,
                worker: Path::new("/unselected-host-worker"),
                offline,
            },
            &Cancellation::default(),
            |_| {},
        )
    }

    #[test]
    fn managed_requires_explicit_configuration_before_store_and_ignores_host_fallback() {
        let (temp, resolved) = fixture("https://example.invalid/source");
        for text in ["", "[build]\nhost-toolchain='/usr'"] {
            let user = UserConfiguration::parse(text, temp.path().join("store")).unwrap();
            assert!(matches!(
                run(&resolved, &user, true),
                Err(RealizeError::MissingManagedConfiguration)
            ));
            assert!(!user.store().exists());
        }
    }

    #[test]
    fn command_and_consumer_reject_managed_configuration_before_store() {
        let (temp, resolved) = fixture("https://example.invalid/source");
        let checks = CheckConfiguration {
            standard_library: Some(AuthenticatedStandardLibrary::bundled()),
            ..CheckConfiguration::default()
        };
        let worker = temp.path().join("worker");
        fs::write(&worker, static_image()).unwrap();
        let users = [
            UserConfiguration::parse("", temp.path().join("store")).unwrap(),
            configuration(
                temp.path(),
                &worker,
                ContentDigest::sha256(b"wrong pin"),
            ),
        ];
        for user in users {
            let reference = format!("{}#recipe", resolved.project().display());
            let command =
                crate::realize::resolve_command(&reference, Some("test"), &user, &checks).unwrap();
            let error = crate::realize::realize_command(
                &command,
                &user,
                Path::new("/unselected-host-worker"),
                true,
                &Cancellation::default(),
                |_, _| {},
            )
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    crate::realize::CommandError::Resolve(
                        RealizeError::MissingManagedConfiguration | RealizeError::ManagedWorker(_)
                    )
                ),
                "{error:?}"
            );
            assert!(!user.store().exists());
            for name in ["os", "shell"] {
                let prepared = crate::project::prepare_project_consumer_with(
                    resolved.project(),
                    &checks,
                    name,
                )
                .unwrap();
                let error = crate::deployment::manifest::prepare_consumer(
                    prepared,
                    name,
                    &user,
                    Path::new("/unselected-host-worker"),
                    true,
                    &Cancellation::default(),
                    |_, _| {},
                )
                .unwrap_err();
                assert!(
                    matches!(
                        error,
                        crate::deployment::manifest::DeploymentError::Realize(
                            RealizeError::MissingManagedConfiguration
                                | RealizeError::ManagedWorker(_)
                        )
                    ),
                    "{error:?}"
                );
                assert!(!user.store().exists());
            }
        }
    }

    #[test]
    fn invalid_candidate_pin_static_image_and_size_fail_before_store() {
        let (temp, resolved) = fixture("https://example.invalid/source");
        let worker = temp.path().join("worker");
        let bytes = static_image();
        fs::write(&worker, &bytes).unwrap();
        let user = configuration(
            temp.path(),
            &worker,
            ContentDigest::sha256(b"wrong pin"),
        );
        assert!(matches!(
            run(&resolved, &user, true),
            Err(RealizeError::ManagedWorker(
                "worker SHA-256 does not match configuration"
            ))
        ));
        assert!(!user.store().exists());
        fs::write(&worker, b"#!/bin/sh\n").unwrap();
        let user = configuration(
            temp.path(),
            &worker,
            ContentDigest::sha256(b"#!/bin/sh\n"),
        );
        assert!(matches!(
            run(&resolved, &user, true),
            Err(RealizeError::ManagedWorker(
                "worker must be a static ELF executable"
            ))
        ));
        assert!(!user.store().exists());
        fs::File::create(&worker)
            .unwrap()
            .set_len(MAX_WORKER_BYTES + 1)
            .unwrap();
        let user = configuration(
            temp.path(),
            &worker,
            ContentDigest::sha256(&bytes),
        );
        assert!(matches!(
            run(&resolved, &user, true),
            Err(RealizeError::ManagedWorker(_))
        ));
        assert!(!user.store().exists());
    }

    #[test]
    fn symlink_directory_and_early_cancellation_never_open_a_manager_or_store() {
        let (temp, resolved) = fixture("https://example.invalid/source");
        let worker = temp.path().join("worker");
        let bytes = static_image();
        fs::write(&worker, &bytes).unwrap();
        let alias = temp.path().join("alias");
        symlink(&worker, &alias).unwrap();
        for path in [&alias, &temp.path().to_path_buf()] {
            let user = configuration(temp.path(), path, ContentDigest::sha256(&bytes));
            assert!(run(&resolved, &user, true).is_err());
            assert!(!user.store().exists());
        }
        let user = configuration(
            temp.path(),
            &temp.path().join("absent-worker"),
            ContentDigest::sha256(&bytes),
        );
        let cancelled = Cancellation::default();
        cancelled.cancel();
        assert!(matches!(
            read_worker(user.managed_build().unwrap(), &cancelled),
            Err(RealizeError::Cancelled)
        ));
        assert!(!user.store().exists());
    }

    #[test]
    fn offline_and_missing_grant_refuse_transport_without_host_preflight_or_staging() {
        let (temp, resolved) = fixture("https://example.invalid/source");
        let bytes = static_image();
        let worker = temp.path().join("worker");
        fs::write(&worker, &bytes).unwrap();
        let user = configuration(
            temp.path(),
            &worker,
            ContentDigest::sha256(&bytes),
        );
        assert!(matches!(
            run(&resolved, &user, true),
            Err(RealizeError::OfflineMissing(_))
        ));
        no_staging(&user);
        assert!(matches!(
            run(&resolved, &user, false),
            Err(RealizeError::SourceDenied(_))
        ));
        no_staging(&user);
        assert!(!temp.path().join("missing-sockets").exists());
    }

    #[test]
    fn project_source_uses_prepared_owner_and_retains_bytes_without_staging() {
        let (temp, resolved) = fixture("project:source");
        fs::write(
            resolved.project().join("source"),
            b"managed source",
        )
        .unwrap();
        fs::write(
            resolved.project().join("main.srx"),
            "changed editor text is not reevaluated",
        )
        .unwrap();
        let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
        let store = Store::initialize(user.store()).unwrap();
        let cancellation = Cancellation::default();
        let interest = ensure_source(
            &resolved,
            &user,
            &store,
            true,
            &cancellation,
            |_| {},
        )
        .unwrap();
        let pin = ContentDigest::sha256(b"managed source");
        let junk = ContentDigest::sha256(b"unrelated");
        store
            .operation()
            .unwrap()
            .ingest(&b"unrelated"[..], junk, 9)
            .unwrap();
        let report = store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                remove_roots: vec![RootName::new(format!("source_{pin}")).unwrap()],
                ..crate::store::GcRequest::default()
            })
            .unwrap();
        assert!(report.removed_objects.contains(&junk));
        assert!(!report.removed_objects.contains(&pin));
        no_staging(&user);
        drop(interest);
    }

    #[test]
    fn verified_managed_cache_hit_needs_neither_source_origin_nor_manager() {
        let (temp, resolved) = fixture("project:source");
        let bytes = static_image();
        let worker = temp.path().join("worker");
        fs::write(&worker, &bytes).unwrap();
        let user = configuration(
            temp.path(),
            &worker,
            ContentDigest::sha256(&bytes),
        );
        let store = Store::initialize(user.store()).unwrap();
        let source = ContentDigest::sha256(b"managed source");
        let lease = store.operation().unwrap();
        lease
            .ingest(&b"managed source"[..], source, 1024)
            .unwrap();
        // Controlled cache admission only: this synthetic ELF is never executed.
        let action = crate::build::records::Action {
            program: resolved.build.program().clone(),
            source,
            toolchain: None,
            worker: ContentDigest::sha256(&bytes),
            directory: resolved.build.source_directory().into(),
            inputs: Vec::new(),
        };
        let admitted = crate::build::cache::tests::retained(&lease, &action, b"cached output");
        drop(lease);
        crate::build::rebuild_build_index(&store).unwrap();
        assert!(!resolved.project().join("source").exists());
        assert!(!temp.path().join("missing-bus").exists());
        assert!(!temp.path().join("missing-sockets").exists());
        let result = run(&resolved, &user, true).unwrap();
        assert_eq!(result.action, admitted.action);
        assert_eq!(result.receipt, admitted.receipt);
        assert_eq!(result.toolchain, None);
        assert!(matches!(
            result.execution,
            crate::build::BuildExecution::Cached
        ));
        no_staging(&user);
        // A cache hit remains an integrity check, not permission to ignore mutation.
        let pin = source.to_string();
        fs::write(
            user.store()
                .join("objects/sha256")
                .join(&pin[..2])
                .join(pin),
            b"corrupt",
        )
        .unwrap();
        assert!(run(&resolved, &user, true).is_err());
        no_staging(&user);
        assert!(!temp.path().join("missing-sockets").exists());
    }
}
