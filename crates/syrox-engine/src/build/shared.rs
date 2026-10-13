//! Coordenação dos pedidos que compartilham um produtor de build.
//!
//! O primeiro chamador continua coordenando mesmo se retirar seu próprio
//! interesse. Para devolver um cache hit, o resultado precisa passar pela
//! verificação da Store; PID, journal ou lock não substituem essa conferência.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::journal::{Attempt, Operation};
use super::records::Action;
use super::{BuildError, BuildExecution, BuildResult, Cancellation, cache, journal};
use crate::platform::linux::fd::{self as fd, FlockMode, OpenedPath};
use crate::{store::OperationLease, store::RootName, store::Store};

pub(super) const CLOSING: &[u8] = b"syrox-build-closing\n";
const POLL: Duration = Duration::from_millis(25);
const WAIT_SETTLEMENT_MARGIN: Duration = Duration::from_mins(2);

struct Consumer {
    name: String,
    timeout_seconds: u32,
    directory: OpenedPath,
    parent: OpenedPath,
    interest: Option<OpenedPath>,
    _observer: OpenedPath,
}

impl Consumer {
    fn join(
        parent: &OpenedPath,
        directory: OpenedPath,
        name: String,
        timeout_seconds: u32,
    ) -> Result<Self, BuildError> {
        let interest = shared_lock(&directory, "consumers")?;
        let observer = shared_lock(&directory, "observers")?;
        Ok(Self {
            name,
            timeout_seconds,
            directory,
            parent: journal::directory(parent, ".")?,
            interest: Some(interest),
            _observer: observer,
        })
    }

    /// Admission and the last-interest transition use the same namespace lock.
    /// A late caller cannot join a producer that has already begun cancellation.
    fn detach(&mut self) -> Result<bool, BuildError> {
        let _mutation = journal::lock_namespace(&self.parent)?;
        self.interest.take();
        if journal::read(&self.directory, "closing", 64)?.is_some() {
            return Ok(true);
        }
        if journal::lock_existing(&self.directory, "consumers")?.is_some() {
            journal::write(&self.directory, "closing", CLOSING)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn failure(&self, reason: impl Into<String>) -> BuildError {
        BuildError::SharedProducer {
            operation: self.name.clone(),
            reason: reason.into(),
        }
    }

    fn wait(
        self,
        lease: &OperationLease,
        action: &Action,
        root: Option<&RootName>,
        cancellation: &Cancellation,
    ) -> Result<BuildResult, BuildError> {
        self.wait_lookup(cancellation, || {
            cache::lookup(lease, action, root, cancellation)
        })
    }

    fn wait_owned(
        self,
        store: &Store,
        action: &Action,
        root: Option<&RootName>,
        cancellation: &Cancellation,
    ) -> Result<BuildResult, BuildError> {
        self.wait_lookup(cancellation, || {
            let lease = store.operation()?;
            cache::lookup(&lease, action, root, cancellation)
        })
    }

    fn wait_lookup(
        mut self,
        cancellation: &Cancellation,
        mut lookup: impl FnMut() -> Result<Option<BuildResult>, BuildError>,
    ) -> Result<BuildResult, BuildError> {
        // Followers observe the already admitted producer's budget, regardless
        // of the deadline they would use for a new attempt of this Action.
        let deadline = Instant::now()
            + Duration::from_secs(u64::from(self.timeout_seconds))
            + WAIT_SETTLEMENT_MARGIN;
        let mut cancelled = false;
        loop {
            if !cancelled && cancellation.is_cancelled() {
                if !self.detach()? {
                    return Err(BuildError::Cancelled);
                }
                // The last consumer waits for confirmed settlement, retaining an
                // observer lease so recovery cannot erase its evidence meanwhile.
                cancelled = true;
            }
            if let Some(_coordinator) = journal::lock_existing(&self.directory, "lease")? {
                if cancelled && journal::terminal_settlement(&self.directory)? {
                    return Err(BuildError::Cancelled);
                }
                if !cancelled && let Some(mut result) = lookup()? {
                    result.execution = BuildExecution::Shared {
                        operation: self.name.clone(),
                    };
                    return Ok(result);
                }
                let outcome = journal::read(&self.directory, "outcome", 4096)?;
                let diagnostic = outcome.as_deref().map_or_else(
                    || "coordinator disappeared; run srx store recover".into(),
                    |bytes| String::from_utf8_lossy(bytes).into_owned(),
                );
                return Err(self.failure(format!(
                    "ended without a reusable result or confirmed cancellation: {diagnostic}"
                )));
            }
            if Instant::now() >= deadline {
                self.detach()?;
                return Err(self
                    .failure("consumer wait exceeded producer deadline; settlement unconfirmed"));
            }
            std::thread::sleep(POLL);
        }
    }
}

fn shared_lock(directory: &OpenedPath, name: &str) -> Result<OpenedPath, BuildError> {
    let file = fd::open_existing_regular(directory.fd(), Path::new(name))?;
    if file.metadata().size() != 0 || !fd::flock(file.fd(), FlockMode::Shared)? {
        return Err(BuildError::Journal(
            "consumer lease unavailable".into(),
        ));
    }
    Ok(file)
}

#[derive(Debug)]
pub(super) struct Interest {
    requested: Cancellation,
    consumer: Mutex<InterestState>,
}

#[derive(Debug)]
struct InterestState {
    consumer: Consumer,
    checked: Option<Instant>,
    stopped: bool,
}

impl std::fmt::Debug for Consumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Consumer")
            .field("operation", &self.name)
            .field("interested", &self.interest.is_some())
            .finish_non_exhaustive()
    }
}

impl Interest {
    pub(super) fn check(&self) -> Result<(), BuildError> {
        self.check_interest(false)
    }

    pub(super) fn check_publication(&self) -> Result<(), BuildError> {
        self.check_interest(true)
    }

    fn check_interest(&self, publication: bool) -> Result<(), BuildError> {
        if !self.requested.is_cancelled() {
            return Ok(());
        }
        let mut state = self
            .consumer
            .lock()
            .map_err(|_| BuildError::Journal("consumer state poisoned".into()))?;
        if state.stopped {
            return Err(BuildError::Cancelled);
        }
        // Hashing /usr checks cancellation at every chunk. Once detached, probe
        // other interests at most once per tick, but always at the commit boundary.
        if !publication
            && state
                .checked
                .is_some_and(|last| last.elapsed() < POLL)
        {
            return Ok(());
        }
        state.stopped = state.consumer.detach()?;
        state.checked = Some(Instant::now());
        if state.stopped {
            Err(BuildError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn detached(&self) -> bool {
        self.consumer
            .lock()
            .expect("producer interest not poisoned")
            .consumer
            .interest
            .is_none()
    }
}

enum Admission {
    Ready(BuildResult),
    Follow(Consumer),
    Produce(Operation, Consumer),
}

fn admit(
    lease: &OperationLease,
    action: &Action,
    timeout_seconds: u32,
    root: Option<&RootName>,
    cancellation: &Cancellation,
) -> Result<Admission, BuildError> {
    let attempt = Attempt::new(action.digest(), timeout_seconds)?;
    let started = Instant::now();
    let parent = lease.build_directory()?;
    let _mutation = journal::lock_namespace(&parent)?;
    let acquired = Instant::now();
    let _profile = AdmissionLockProfile {
        acquired,
        wait: acquired.duration_since(started),
    };
    cancellation.check()?;
    // A producer may have committed between the first lookup and admission.
    if let Some(result) = cache::lookup(lease, action, root, cancellation)? {
        return Ok(Admission::Ready(result));
    }
    let mut other_producer = None;
    for name in journal::entries(&parent, journal::MAX_OPERATIONS)? {
        if !journal::valid_name(&name, "op-") {
            continue;
        }
        let directory = journal::directory(&parent, &name)?;
        let Some(existing) = Attempt::read(&directory)? else {
            continue;
        };
        if existing.action != attempt.action {
            if journal::lock_existing(&directory, "lease")?.is_none()
                || !journal::terminal_settlement(&directory)?
            {
                other_producer = Some(name);
            }
            continue;
        }
        if journal::validate_identity(&parent, &directory, &name)? != journal::boot_id()? {
            return Err(BuildError::SharedProducer {
                operation: name,
                reason: "previous-boot operation; run srx store recover".into(),
            });
        }
        if journal::lock_existing(&directory, "lease")?.is_none() {
            if journal::read(&directory, "closing", 64)?.is_some() {
                return Err(BuildError::SharedProducer {
                    operation: name,
                    reason: "last consumer already cancelled; retry after finalization".into(),
                });
            }
            return Ok(Admission::Follow(Consumer::join(
                &parent,
                directory,
                name,
                existing.timeout_seconds,
            )?));
        }
        if !journal::terminal_settlement(&directory)? {
            return Err(BuildError::SharedProducer {
                operation: name,
                reason: "orphaned or unsettled operation; run srx store recover".into(),
            });
        }
    }
    if let Some(operation) = other_producer {
        return Err(BuildError::SharedProducer {
            operation,
            reason:
                "one build producer allowed; settle or recover the existing attempt before retrying"
                    .into(),
        });
    }
    let budget = acquire_producer_budget()?;
    let mut operation = Operation::create_locked(&parent)?;
    operation.producer_budget = Some(budget);
    // Bind before leaving admission, and before any launch authorization. An
    // abrupt death from this point cannot lead to an overlapping replacement.
    operation.bind(attempt)?;
    let consumer = Consumer::join(
        &parent,
        journal::directory(&parent, &operation.name)?,
        operation.name.clone(),
        timeout_seconds,
    )?;
    Ok(Admission::Produce(operation, consumer))
}

struct AdmissionLockProfile {
    acquired: Instant,
    wait: Duration,
}

impl Drop for AdmissionLockProfile {
    fn drop(&mut self) {
        if std::env::var_os("SYROX_PROFILE_LOCKS").is_some() {
            eprintln!(
                "syrox-lock producer-admission wait_us={} held_us={}",
                self.wait.as_micros(),
                self.acquired.elapsed().as_micros()
            );
        }
    }
}

pub(super) fn realize(
    lease: &OperationLease,
    action: &Action,
    timeout_seconds: u32,
    root: Option<&RootName>,
    cancellation: &Cancellation,
    produce: impl FnOnce(
        &Operation,
        &dyn super::cancellation::BuildControl,
    ) -> Result<BuildResult, BuildError>,
) -> Result<BuildResult, BuildError> {
    let (operation, consumer) = match admit(lease, action, timeout_seconds, root, cancellation)? {
        Admission::Ready(result) => return Ok(result),
        Admission::Follow(consumer) => return consumer.wait(lease, action, root, cancellation),
        Admission::Produce(operation, consumer) => (operation, consumer),
    };
    let interest = Arc::new(Interest {
        requested: cancellation.clone(),
        consumer: Mutex::new(InterestState {
            consumer,
            checked: None,
            stopped: false,
        }),
    });
    let producer = super::cancellation::ProducerControl(Arc::clone(&interest));
    let result = operation.finish(produce(&operation, &producer))?;
    cache::record(lease, action, &result).map_err(|source| BuildError::PublishedAndCache {
        root: result.root.clone(),
        source: Box::new(source),
    })?;
    if interest.detached() {
        return Err(BuildError::Cancelled);
    }
    if let Some(root) = root {
        // Per-consumer retention is separate from the shared producer's managed
        // root. A caller's root conflict cannot prevent another caller's success.
        let mut retained = cache::lookup(lease, action, Some(root), cancellation)?
            .ok_or_else(|| BuildError::Cache("committed producer result disappeared".into()))?;
        retained.execution = result.execution;
        return Ok(retained);
    }
    Ok(result)
}

/// Admit a producer under a short Store barrier, then transfer the sole operation
/// into its owned preparation. The caller retains input `ObjectLease`s; neither
/// running the producer nor waiting as a follower holds a global Store lease.
pub(super) fn realize_owned(
    store: &Store,
    action: &Action,
    timeout_seconds: u32,
    root: Option<&RootName>,
    cancellation: &Cancellation,
    produce: impl FnOnce(
        Arc<Operation>,
        &super::cancellation::ProducerControl,
    ) -> Result<BuildResult, BuildError>,
) -> Result<BuildResult, BuildError> {
    let admission = {
        let lease = store.operation()?;
        admit(
            &lease,
            action,
            timeout_seconds,
            root,
            cancellation,
        )?
    };
    let (operation, consumer) = match admission {
        Admission::Ready(result) => return Ok(result),
        Admission::Follow(consumer) => {
            return consumer.wait_owned(store, action, root, cancellation);
        }
        Admission::Produce(operation, consumer) => (Arc::new(operation), consumer),
    };
    let interest = Arc::new(Interest {
        requested: cancellation.clone(),
        consumer: Mutex::new(InterestState {
            consumer,
            checked: None,
            stopped: false,
        }),
    });
    let producer = super::cancellation::ProducerControl(Arc::clone(&interest));
    let result = operation.finish(produce(Arc::clone(&operation), &producer))?;
    // Only publication/index/root verification reacquires the Store barrier.
    let lease = store.operation()?;
    cache::record(&lease, action, &result).map_err(|source| BuildError::PublishedAndCache {
        root: result.root.clone(),
        source: Box::new(source),
    })?;
    if interest.detached() {
        return Err(BuildError::Cancelled);
    }
    if let Some(root) = root {
        let mut retained = cache::lookup(&lease, action, Some(root), cancellation)?
            .ok_or_else(|| BuildError::Cache("committed producer result disappeared".into()))?;
        retained.execution = result.execution;
        return Ok(retained);
    }
    Ok(result)
}

use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

pub(in crate::build) fn acquire_producer_budget() -> Result<std::fs::File, BuildError> {
    let uid = fd::effective_uid();
    let path = format!("/tmp/syrox-build-producer-{uid}.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != 0
    {
        return Err(BuildError::Capability(
            "invalid single-producer budget lease",
        ));
    }
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => BuildError::Capability(
            "one build producer allowed in the minimum environment; retry after settlement",
        ),
        std::fs::TryLockError::Error(error) => BuildError::Io(error),
    })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::super::cache::tests::{action, retained};
    use super::*;
    use crate::{build::BuildRecoveryState, store::Store};
    use std::sync::mpsc;

    #[test]
    fn cancelling_either_consumer_keeps_the_single_producer_for_the_other() {
        for cancel_producer_consumer in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            let lease = store.operation().unwrap();
            let action = action();
            let first = Cancellation::default();
            let second = Cancellation::default();
            let (started, ready) = mpsc::channel();
            let (resume, resume_rx) = mpsc::channel();
            std::thread::scope(|scope| {
                let (producer_lease, description, request) = (&lease, &action, &first);
                let build = scope.spawn(move || {
                    realize(
                        producer_lease,
                        description,
                        30,
                        None,
                        request,
                        |operation, cancellation| {
                            started.send(()).unwrap();
                            resume_rx
                                .recv_timeout(Duration::from_secs(5))
                                .unwrap();
                            cancellation.check_publication()?;
                            operation.clean_stage()?;
                            Ok(retained(
                                producer_lease,
                                description,
                                b"one producer",
                            ))
                        },
                    )
                });
                ready
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                let Admission::Follow(consumer) =
                    admit(&lease, &action, 60, None, &second).unwrap()
                else {
                    panic!("must join active producer");
                };
                assert_eq!(
                    consumer.timeout_seconds, 30,
                    "joining preserves the producer's budget"
                );
                let root = RootName::new("second_consumer").unwrap();
                if cancel_producer_consumer {
                    first.cancel();
                    resume.send(()).unwrap();
                    let result = consumer
                        .wait(&lease, &action, Some(&root), &second)
                        .unwrap();
                    assert!(matches!(
                        result.execution,
                        BuildExecution::Shared { .. }
                    ));
                    assert_eq!(result.root, root);
                    assert!(matches!(
                        build.join().unwrap(),
                        Err(BuildError::Cancelled)
                    ));
                } else {
                    second.cancel();
                    assert!(matches!(
                        consumer.wait(&lease, &action, Some(&root), &second),
                        Err(BuildError::Cancelled)
                    ));
                    resume.send(()).unwrap();
                    assert!(build.join().unwrap().is_ok());
                    assert!(
                        !directory
                            .path()
                            .join("roots/retained")
                            .join(root.as_str())
                            .exists()
                    );
                }
            });
            assert_eq!(
                journal::entries(&lease.build_directory().unwrap(), 10)
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                cache::lookup(&lease, &action, None, &Cancellation::default())
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn last_consumer_waits_for_settlement_and_closing_rejects_late_admission() {
        use super::super::cancellation::BuildControl as _;
        // Unrelated harness forks can inherit the final observer OFD between the
        // coordinator's exit and the follower's drop. The deterministic fork test
        // below proves that Active is correct until that unrelated child exits.
        // Keep this test's immediate last-close assertion free of other test forks.
        if fd::retention_fork_tests::isolate_test(
            "build::shared::tests::last_consumer_waits_for_settlement_and_closing_rejects_late_admission",
            "SYROX_SHARED_SETTLEMENT_ISOLATED",
        ) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let action = action();
        let first = Cancellation::default();
        let second = Cancellation::default();
        let (started, ready) = mpsc::channel();
        let (resume, resume_rx) = mpsc::channel();
        let (stopping, stopped) = mpsc::channel();
        let (detached, detached_rx) = mpsc::channel();
        let (settle, settle_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let (producer_store, description, request) = (&store, &action, &first);
            let build = scope.spawn(move || {
                realize_owned(
                    producer_store,
                    description,
                    30,
                    None,
                    request,
                    |operation, cancellation| {
                        started.send(()).unwrap();
                        resume_rx
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                        cancellation.check().unwrap();
                        detached.send(()).unwrap();
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while cancellation.check().is_ok() {
                            assert!(Instant::now() < deadline);
                            std::thread::sleep(POLL);
                        }
                        stopping.send(()).unwrap();
                        settle_rx
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                        operation.clean_stage()?;
                        Err(BuildError::Cancelled)
                    },
                )
            });
            ready
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            let Admission::Follow(consumer) = admit(
                &store.operation().unwrap(),
                &action,
                10,
                None,
                &second,
            )
            .unwrap() else {
                panic!("must follow");
            };
            first.cancel();
            resume.send(()).unwrap();
            detached_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            second.cancel();
            let follower = scope.spawn(|| consumer.wait_owned(&store, &action, None, &second));
            stopped
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert!(!follower.is_finished());
            assert!(matches!(
                admit(
                    &store.operation().unwrap(),
                    &action,
                    60,
                    None,
                    &Cancellation::default()
                ),
                Err(BuildError::SharedProducer { .. })
            ));
            assert_eq!(
                journal::recover(&store).unwrap().entries[0].state,
                BuildRecoveryState::Active
            );
            settle.send(()).unwrap();
            assert!(matches!(
                build.join().unwrap(),
                Err(BuildError::Cancelled)
            ));
            assert!(matches!(
                follower.join().unwrap(),
                Err(BuildError::Cancelled)
            ));
        });
        assert!(
            cache::lookup(
                &store.operation().unwrap(),
                &action,
                None,
                &Cancellation::default()
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            journal::recover(&store).unwrap().entries[0].state,
            BuildRecoveryState::Recovered
        );
    }

    #[test]
    fn orphaned_producer_cannot_be_replaced_until_recovery_and_observers_block_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let action = action();
        let cancel = Cancellation::default();
        let Admission::Produce(operation, consumer) =
            admit(&lease, &action, 30, None, &cancel).unwrap()
        else {
            panic!("must produce");
        };
        drop(operation);
        assert!(matches!(
            admit(&lease, &action, 60, None, &cancel),
            Err(BuildError::SharedProducer { .. })
        ));
        assert_eq!(
            journal::recover(&store).unwrap().entries[0].state,
            BuildRecoveryState::Active
        );
        assert!(matches!(
            consumer.wait(&lease, &action, None, &cancel),
            Err(BuildError::SharedProducer { .. })
        ));
        assert_eq!(
            journal::recover(&store).unwrap().entries[0].state,
            BuildRecoveryState::Recovered
        );
        assert!(matches!(
            admit(&lease, &action, 60, None, &cancel).unwrap(),
            Admission::Produce(_, _)
        ));
    }

    #[test]
    fn consumer_root_conflict_does_not_invalidate_the_shared_committed_result() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let action = action();
        let root = RootName::new("occupied").unwrap();
        lease.publish_root(&root, &[]).unwrap();
        let result = realize(
            &lease,
            &action,
            30,
            Some(&root),
            &Cancellation::default(),
            |operation, cancellation| {
                operation.clean_stage()?;
                cancellation.check_publication()?;
                Ok(retained(&lease, &action, b"shared output"))
            },
        );
        assert!(matches!(
            result,
            Err(BuildError::Store(
                crate::store::StoreError::RootConflict { .. }
            ))
        ));
        assert!(
            cache::lookup(&lease, &action, None, &Cancellation::default())
                .unwrap()
                .is_some()
        );
        assert_eq!(
            lease.build_references(&root).unwrap(),
            Some(Vec::new())
        );
    }

    #[test]
    fn owned_producer_and_follower_allow_gc_and_keep_independent_interests() {
        use super::super::cancellation::BuildControl as _;
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let action = action();
        let first = Cancellation::default();
        let second = Cancellation::default();
        let (interest, live, garbage) = {
            let lease = store.operation().unwrap();
            let live = crate::store::ContentDigest::sha256(b"live input");
            let garbage = crate::store::ContentDigest::sha256(b"unrelated");
            lease
                .ingest(&b"live input"[..], live, 10)
                .unwrap();
            lease
                .ingest(&b"unrelated"[..], garbage, 9)
                .unwrap();
            (
                lease.retain_objects(&[live], &[]).unwrap(),
                live,
                garbage,
            )
        };
        let (started, ready) = mpsc::channel();
        let (resume, resume_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let (store_ref, action_ref, first_ref) = (&store, &action, &first);
            let producer = scope.spawn(move || {
                realize_owned(
                    store_ref,
                    action_ref,
                    30,
                    None,
                    first_ref,
                    |operation, control| {
                        started.send(()).unwrap();
                        resume_rx
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                        control.check_publication()?;
                        operation.clean_stage()?;
                        let lease = store_ref.operation()?;
                        Ok(retained(&lease, action_ref, b"owned producer"))
                    },
                )
            });
            ready
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            let consumer = {
                let lease = store.operation().unwrap();
                let Admission::Follow(consumer) =
                    admit(&lease, &action, 60, None, &second).unwrap()
                else {
                    panic!("owned producer must coalesce");
                };
                consumer
            };
            first.cancel();
            let report = store
                .maintenance()
                .unwrap()
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    ..crate::store::GcRequest::default()
                })
                .unwrap();
            assert_eq!(report.removed_objects, [garbage]);
            assert!(
                interest
                    .open_verified_checked(live, 10, || Ok(()))
                    .unwrap()
                    .is_some()
            );
            resume.send(()).unwrap();
            assert!(
                consumer
                    .wait_owned(&store, &action, None, &second)
                    .is_ok()
            );
            assert!(matches!(
                producer.join().unwrap(),
                Err(BuildError::Cancelled)
            ));
        });
        let lease = store.operation().unwrap();
        assert_eq!(
            journal::entries(&lease.build_directory().unwrap(), 10)
                .unwrap()
                .len(),
            1
        );
        assert!(
            cache::lookup(&lease, &action, None, &second)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn inherited_observer_prevents_recovery_until_the_fork_child_exits() {
        if fd::retention_fork_tests::isolate_test(
            "build::shared::tests::inherited_observer_prevents_recovery_until_the_fork_child_exits",
            "SYROX_SHARED_OBSERVER_FORK_ISOLATED",
        ) {
            return;
        }
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        let lease = store.operation().unwrap();
        let Admission::Produce(operation, mut consumer) = admit(
            &lease,
            &action(),
            30,
            None,
            &Cancellation::default(),
        )
        .unwrap() else {
            panic!("new operation must produce");
        };
        operation.clean_stage().unwrap();
        drop(operation);
        assert!(consumer.detach().unwrap());
        let directory = journal::directory(&consumer.parent, &consumer.name).unwrap();
        assert!(
            journal::lock_existing(&directory, "lease")
                .unwrap()
                .is_some()
        );
        assert!(
            journal::lock_existing(&directory, "consumers")
                .unwrap()
                .is_some()
        );
        fd::retention_fork_tests::with_forked_descriptors(|| {
            drop(consumer);
            assert!(
                journal::lock_existing(&directory, "lease")
                    .unwrap()
                    .is_some()
            );
            assert!(
                journal::lock_existing(&directory, "consumers")
                    .unwrap()
                    .is_some()
            );
            assert!(
                journal::lock_existing(&directory, "observers")
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                journal::recover(&store).unwrap().entries[0].state,
                BuildRecoveryState::Active
            );
        });
        assert!(
            journal::lock_existing(&directory, "observers")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            journal::recover(&store).unwrap().entries[0].state,
            BuildRecoveryState::Recovered
        );
    }

    #[test]
    fn minimum_budget_refuses_other_actions_but_allows_followers_and_releases_on_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        let lease = store.operation().unwrap();
        let first = action();
        let mut second = first.clone();
        second.source = crate::store::ContentDigest::sha256(b"another action");
        let cancellation = Cancellation::default();
        let Admission::Produce(operation, consumer) =
            admit(&lease, &first, 30, None, &cancellation).unwrap()
        else {
            panic!("producer required")
        };
        assert!(matches!(
            admit(&lease, &first, 30, None, &cancellation).unwrap(),
            Admission::Follow(_)
        ));
        assert!(matches!(
            admit(&lease, &second, 30, None, &cancellation),
            Err(BuildError::SharedProducer { .. })
        ));
        let other = tempfile::tempdir().unwrap();
        let other_store = Store::open(other.path()).unwrap();
        let other_lease = other_store.operation().unwrap();
        assert!(matches!(
            admit(&other_lease, &second, 30, None, &cancellation),
            Err(BuildError::Capability(_))
        ));
        drop(consumer);
        drop(operation);
        assert!(
            matches!(
                admit(&lease, &second, 30, None, &cancellation),
                Err(BuildError::SharedProducer { .. })
            ),
            "unsettled attempts must continue to block replacement"
        );
        assert!(matches!(
            admit(&other_lease, &second, 30, None, &cancellation).unwrap(),
            Admission::Produce(_, _)
        ));
    }
}
