use crate::build::cancellation::BuildControl;
use crate::result::artifact;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read as _;
use std::ops::Deref;
use std::path::Path;
use std::time::{Duration, Instant};

use super::records::{Action, BuildDescription, MAX_RECORD_BYTES, Receipt, invalid};

use super::{BuildError, BuildExecution, BuildIndexReport, BuildResult, Cancellation};
use crate::platform::linux::fd::{self as fd, FlockMode, OpenedPath};
use crate::{store::ContentDigest, store::OperationLease, store::RootName, store::Store};

const MAX_INDEX_BYTES: usize = 1024;
const MAX_SHARD_ENTRIES: usize = 4096;
const TEMP_PREFIX: &str = ".syrox-action.tmp.";

/// The descriptor owns the flock; record the whole critical section, including
/// candidate validation and publication, when opt-in diagnostics are requested.
struct ShardGuard {
    directory: OpenedPath,
    acquired: Instant,
    wait: Duration,
}

impl Deref for ShardGuard {
    type Target = OpenedPath;

    fn deref(&self) -> &OpenedPath {
        &self.directory
    }
}

impl Drop for ShardGuard {
    fn drop(&mut self) {
        if std::env::var_os("SYROX_PROFILE_LOCKS").is_some() {
            eprintln!(
                "syrox-lock shard wait_us={} held_us={}",
                self.wait.as_micros(),
                self.acquired.elapsed().as_micros()
            );
        }
    }
}
pub(crate) const MAX_INVENTORY_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    receipt: ContentDigest,
    root: RootName,
}

struct Verified {
    candidate: Candidate,
    receipt: Receipt,
}

pub(crate) fn lookup(
    lease: &OperationLease,
    action: &Action,
    root: Option<&RootName>,
    cancellation: &dyn BuildControl,
) -> Result<Option<BuildResult>, BuildError> {
    let shard = shard(lease, action.digest(), cancellation)?;
    let entries = read_index(&shard, action.digest())?;
    if entries.len() == 2 {
        return Err(index_divergence(action.digest(), &entries));
    }
    let mut verified = verify_candidates(lease, action, entries, cancellation)?;
    let Some(found) = verified.pop() else {
        return Ok(None);
    };
    let root = root
        .cloned()
        .unwrap_or_else(|| found.receipt.root());
    cancellation.check()?;
    // Also reconciles visibility versus durability, and grants this caller its
    // own requested retention. No signal after this boundary relabels success.
    lease.publish_root(&root, &found.receipt.references())?;
    let retention = lease
        .retain_objects(&found.receipt.references(), &[])
        .map_err(|source| BuildError::PublishedAndRetention {
            root: root.clone(),
            source,
        })?;
    Ok(Some(BuildResult {
        retention,
        execution: BuildExecution::Cached,
        action: found.receipt.action,
        artifact: found
            .receipt
            .output("out")
            .expect("validated receipt")
            .artifact,
        receipt: found.candidate.receipt,
        toolchain: found.receipt.toolchain,
        files: found
            .receipt
            .output("out")
            .expect("validated receipt")
            .files,
        root,
    }))
}

/// A retained application can be admitted with one fresh host inventory,
/// regardless of whether the provider has an independent root. Both results
/// still require their current action-index admission where that root exists.
pub(crate) struct RetainedQuery<'a> {
    pub application: BuildDescription<'a>,
    pub provider: BuildDescription<'a>,
    pub worker: ContentDigest,
    pub toolchain: Option<ContentDigest>,
    pub input_outputs: Vec<&'a str>,
}

impl RetainedQuery<'_> {
    fn matches_application(&self, action: &Action) -> bool {
        self.application.matches(action)
            && action.worker == self.worker
            && action.toolchain == self.toolchain
            && action.inputs.len() == self.input_outputs.len()
            && action
                .inputs
                .iter()
                .zip(&self.input_outputs)
                .all(|(input, name)| {
                    input.output == *name
                        && matches!(
                            input.origin,
                            crate::result::OutputOrigin::Built { .. }
                        )
                        && Some(&input.origin) == action.inputs.first().map(|first| &first.origin)
                })
    }

    fn matches_provider(&self, action: &Action) -> bool {
        self.provider.matches(action) && action.inputs.is_empty()
    }
}

pub(crate) fn retained_build_with_inputs(
    lease: &OperationLease,
    query: &RetainedQuery<'_>,
    cancellation: &dyn BuildControl,
) -> Result<Option<(BuildResult, ContentDigest)>, BuildError> {
    let mut found = None;
    for root in lease.managed_build_roots()? {
        cancellation.check()?;
        let digest = managed_receipt(&root);
        let bytes = lease
            .read_verified(digest, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed root receipt is missing"))?;
        if !current_receipt(bytes.as_bytes()) {
            continue;
        }
        let receipt = Receipt::parse(bytes.as_bytes())?;
        let bytes = lease
            .read_verified(receipt.action, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed action is missing"))?;
        let action = Action::parse(bytes.as_bytes())?;
        if !query.matches_application(&action) {
            continue;
        }
        let Some(crate::result::OutputOrigin::Built {
            receipt: provider_digest,
        }) = action
            .inputs
            .first()
            .map(|input| input.origin.clone())
        else {
            continue;
        };
        let provider_root =
            RootName::new(format!("build_{provider_digest}")).expect("digest-derived root");
        let Some(provider_action) =
            verified_selected_provider(lease, provider_digest, query, cancellation)?
        else {
            continue;
        };
        let (index, provider_index) = index_shards(
            lease,
            action.digest(),
            provider_action.digest(),
            cancellation,
        )?;
        let index = &index;
        let provider_index = provider_index.as_ref().unwrap_or(index);
        // Only explicit reconstruction may clear a durable divergence marker.
        let entries = read_index(index, action.digest())?;
        if entries.len() == 2 {
            return Err(index_divergence(action.digest(), &entries));
        }
        if entries
            .first()
            .is_none_or(|candidate| candidate.receipt != digest || candidate.root != root)
        {
            // A visible but unindexed root does not prove successful producer
            // finalization, even when all of its objects are still readable.
            continue;
        }
        if lease.build_references(&provider_root)?.is_some()
            && !indexed_provider(
                lease,
                provider_index,
                &provider_root,
                provider_digest,
                &provider_action,
                cancellation,
            )?
        {
            continue;
        }
        let candidate = Candidate {
            receipt: digest,
            root: root.clone(),
        };
        let verified = verify_candidate(lease, &action, candidate, cancellation)?
            .ok_or_else(|| invalid("retained application root disappeared"))?;
        if found.is_some() {
            return Err(invalid(
                "multiple retained application results match this build",
            ));
        }
        cancellation.check()?;
        lease.publish_root(&root, &verified.receipt.references())?;
        let out = verified
            .receipt
            .output("out")
            .expect("verified output");
        let retention = lease
            .retain_objects(&verified.receipt.references(), &[])
            .map_err(|source| BuildError::PublishedAndRetention {
                root: root.clone(),
                source,
            })?;
        found = Some((
            BuildResult {
                retention,
                execution: BuildExecution::Cached,
                action: verified.receipt.action,
                artifact: out.artifact,
                receipt: digest,
                toolchain: query.toolchain,
                files: out.files,
                root,
            },
            provider_digest,
        ));
    }
    Ok(found)
}

fn verified_selected_provider(
    lease: &OperationLease,
    provider_digest: ContentDigest,
    query: &RetainedQuery<'_>,
    cancellation: &dyn BuildControl,
) -> Result<Option<Action>, BuildError> {
    let provider_bytes = lease
        .read_verified(provider_digest, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("retained provider receipt is missing"))?;
    let provider_receipt = Receipt::parse(provider_bytes.as_bytes())?;
    let provider_bytes = lease
        .read_verified(provider_receipt.action, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("retained provider action is missing"))?;
    let provider_action = Action::parse(provider_bytes.as_bytes())?;
    if !query.matches_provider(&provider_action) {
        // Equal application programs may legitimately select different
        // runtime providers in other projects retained by this Store.
        return Ok(None);
    }
    // Producer provenance is its own authenticated Action, not the
    // consumer's worker or inventory. Even an orphaned producer must retain
    // its declared source/inventory within the consumer's complete closure.
    if !provider_receipt.matches_action(&provider_action) {
        return Err(invalid("provider receipt and action disagree"));
    }
    provider_receipt.verify_inputs(lease, &provider_action, cancellation)?;
    provider_receipt.verify_retained_inputs(lease, &provider_action, || cancellation.check())?;
    Ok(Some(provider_action))
}

/// Hold both witnesses in a stable order; one lock covers coincident shards.
/// The first returned descriptor always belongs to the application.
fn index_shards(
    lease: &OperationLease,
    application: ContentDigest,
    provider: ContentDigest,
    cancellation: &dyn BuildControl,
) -> Result<(ShardGuard, Option<ShardGuard>), BuildError> {
    let application_prefix = &application.to_string()[..2];
    let provider_prefix = &provider.to_string()[..2];
    if application_prefix == provider_prefix {
        return Ok((shard(lease, application, cancellation)?, None));
    }
    if application_prefix < provider_prefix {
        let app = shard(lease, application, cancellation)?;
        let provider = shard(lease, provider, cancellation)?;
        Ok((app, Some(provider)))
    } else {
        let provider = shard(lease, provider, cancellation)?;
        let app = shard(lease, application, cancellation)?;
        Ok((app, Some(provider)))
    }
}

/// An independent provider root must have completed its own index publication.
/// A retained consumer closure alone cannot admit an unindexed provider.
fn indexed_provider(
    lease: &OperationLease,
    index: &OpenedPath,
    root: &RootName,
    receipt: ContentDigest,
    action: &Action,
    cancellation: &dyn BuildControl,
) -> Result<bool, BuildError> {
    let candidates = read_index(index, action.digest())?;
    if candidates.len() == 2 {
        return Err(index_divergence(action.digest(), &candidates));
    }
    if candidates
        .first()
        .is_none_or(|candidate| candidate.receipt != receipt || &candidate.root != root)
    {
        return Ok(false);
    }
    verify_candidate(
        lease,
        action,
        Candidate {
            receipt,
            root: root.clone(),
        },
        cancellation,
    )?
    .ok_or_else(|| invalid("retained provider root disappeared"))?;
    Ok(true)
}

pub(crate) fn has_retained_build_with_inputs(
    lease: &OperationLease,
    description: &BuildDescription<'_>,
    cancellation: &dyn BuildControl,
) -> Result<bool, BuildError> {
    for root in lease.managed_build_roots()? {
        cancellation.check()?;
        let digest = managed_receipt(&root);
        let bytes = lease
            .read_verified(digest, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed root receipt is missing"))?;
        if !current_receipt(bytes.as_bytes()) {
            continue;
        }
        let receipt = Receipt::parse(bytes.as_bytes())?;
        let bytes = lease
            .read_verified(receipt.action, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed action is missing"))?;
        let action = Action::parse(bytes.as_bytes())?;
        if description.matches(&action) && !action.inputs.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Called only after root publication and operation finalization succeeded.
pub(crate) fn record(
    lease: &OperationLease,
    action: &Action,
    result: &BuildResult,
) -> Result<(), BuildError> {
    record_candidate(
        lease,
        action,
        Candidate {
            receipt: result.receipt,
            root: result.root.clone(),
        },
    )
}

fn record_candidate(
    lease: &OperationLease,
    action: &Action,
    candidate: Candidate,
) -> Result<(), BuildError> {
    // Root publication is already committed. Index bookkeeping reports its own
    // actual outcome, independently of cancellation arriving after that commit.
    let cancellation = Cancellation::default();
    let shard = shard(lease, action.digest(), &cancellation)?;
    let existing = read_index(&shard, action.digest())?;
    // A two-receipt record is a durable ambiguity marker. Evicting a witness
    // does not silently clear it; explicit reconstruction re-evaluates roots.
    if existing.len() == 2 {
        return Err(index_divergence(action.digest(), &existing));
    }
    let mut verified = verify_candidates(lease, action, existing, &cancellation)?;
    let new = verify_candidate(lease, action, candidate, &cancellation)?
        .ok_or_else(|| invalid("new result root is missing"))?;
    if !verified
        .iter()
        .any(|old| old.candidate.receipt == new.candidate.receipt)
        && verified.len() < 2
    {
        verified.push(new);
    }
    // Losing a hint must not hide a different retained result of this action.
    // This scan can establish ambiguity, never turn an unindexed/uncertain root
    // into a cache hit. The new producer has independently completed publication.
    discover_conflicts(lease, action, &mut verified, &cancellation)?;
    verified.sort_by_key(|entry| entry.candidate.receipt);
    let candidates: Vec<_> = verified
        .iter()
        .map(|entry| entry.candidate.clone())
        .collect();
    save_index(&shard, action.digest(), &candidates)?;
    if verified.len() == 2 {
        return Err(divergence(action.digest(), &verified));
    }
    Ok(())
}

fn discover_conflicts(
    lease: &OperationLease,
    action: &Action,
    verified: &mut Vec<Verified>,
    cancellation: &dyn BuildControl,
) -> Result<(), BuildError> {
    for root in lease.managed_build_roots()? {
        if verified.len() == 2 {
            break;
        }
        let digest = managed_receipt(&root);
        if verified
            .iter()
            .any(|entry| entry.candidate.receipt == digest)
        {
            continue;
        }
        let bytes = lease
            .read_verified(digest, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed root receipt is missing"))?;
        if !current_receipt(bytes.as_bytes()) {
            continue;
        }
        let receipt = Receipt::parse(bytes.as_bytes())?;
        if receipt.action != action.digest() {
            continue;
        }
        if let Some(found) = verify_candidate(
            lease,
            action,
            Candidate {
                receipt: digest,
                root,
            },
            cancellation,
        )? {
            verified.push(found);
        }
    }
    Ok(())
}

fn managed_receipt(root: &RootName) -> ContentDigest {
    root.as_str()
        .strip_prefix("build_")
        .expect("managed root")
        .parse()
        .expect("managed digest")
}

fn divergence(action: ContentDigest, entries: &[Verified]) -> BuildError {
    BuildError::DivergentResults {
        action,
        first: entries[0].candidate.receipt,
        second: entries[1].candidate.receipt,
    }
}

fn index_divergence(action: ContentDigest, entries: &[Candidate]) -> BuildError {
    BuildError::DivergentResults {
        action,
        first: entries[0].receipt,
        second: entries[1].receipt,
    }
}

fn save_index(
    directory: &OpenedPath,
    action: ContentDigest,
    candidates: &[Candidate],
) -> Result<(), BuildError> {
    let entries = clean_temporaries(directory)?;
    if entries.len() >= MAX_SHARD_ENTRIES
        && !entries
            .iter()
            .any(|name| name == &action.to_string())
    {
        return Err(invalid("action index shard entry limit reached"));
    }
    fd::write_atomic_beneath_with_prefix(
        directory.fd(),
        Path::new(&action.to_string()),
        &encode_index(action, candidates),
        TEMP_PREFIX,
    )
    .map_err(problem)
}

fn verify_candidates(
    lease: &OperationLease,
    action: &Action,
    candidates: Vec<Candidate>,
    cancellation: &dyn BuildControl,
) -> Result<Vec<Verified>, BuildError> {
    candidates
        .into_iter()
        .filter_map(|candidate| {
            verify_candidate(lease, action, candidate, cancellation).transpose()
        })
        .collect()
}

fn verify_candidate(
    lease: &OperationLease,
    action: &Action,
    candidate: Candidate,
    cancellation: &dyn BuildControl,
) -> Result<Option<Verified>, BuildError> {
    cancellation.check()?;
    // Missing retention is an ordinary stale hint. Broken objects underneath a
    // present root are corruption, never a reason to silently rebuild/replace.
    let Some(references) = lease.build_references(&candidate.root)? else {
        return Ok(None);
    };
    let receipt_bytes = lease
        .read_verified(candidate.receipt, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("retained receipt is missing"))?;
    let receipt = Receipt::parse(receipt_bytes.as_bytes())?;
    if !receipt.matches_action(action) || references != receipt.references() {
        return Err(invalid(
            "receipt, action or root references disagree",
        ));
    }
    receipt.verify_inputs(lease, action, cancellation)?;
    let action_bytes = lease
        .read_verified(receipt.action, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("retained action is missing"))?;
    if action_bytes.as_bytes() != action.encode() {
        return Err(invalid("retained action is incompatible"));
    }
    receipt.verify_retained_inputs(lease, action, || cancellation.check())?;
    cancellation.check()?;
    let artifact_limit = action.program.resources.envelope().output_bytes;
    for output in receipt.outputs.values() {
        cancellation.check()?;
        let artifact = lease
            .open_verified_checked(output.artifact, artifact_limit, || {
                if cancellation.is_cancelled() {
                    Err(crate::cancellation::cancellation_io())
                } else {
                    Ok(())
                }
            })
            .map_err(|error| {
                if cancellation.is_cancelled() {
                    BuildError::Cancelled
                } else {
                    error.into()
                }
            })?
            .ok_or_else(|| invalid("retained named artifact is missing"))?;
        if artifact::validate_stream_checked(artifact, "", cancellation)? != output.files {
            return Err(invalid(
                "named output file count disagrees with artifact",
            ));
        }
    }
    Ok(Some(Verified {
        candidate,
        receipt,
    }))
}

/// Validate an explicitly retained provider without constructing a filesystem
/// view. A consumer Action can therefore be looked up before preparing any
/// build-only mounts, while preserving the same complete result checks as a hit.
#[cfg(test)]
pub(crate) fn retained_result(
    lease: &OperationLease,
    root: &RootName,
    digest: ContentDigest,
    cancellation: &dyn BuildControl,
) -> Result<(Action, Receipt), BuildError> {
    let (action, _) = read_result(lease, digest, cancellation)?;
    let verified = verify_candidate(
        lease,
        &action,
        Candidate {
            receipt: digest,
            root: root.clone(),
        },
        cancellation,
    )?
    .ok_or_else(|| invalid("retained provider root is missing"))?;
    Ok((action, verified.receipt))
}

/// Verify a receipt/Action binding inside an already retained closure. This
/// alone grants neither root retention nor action-index admission.
pub(crate) fn read_result(
    lease: &OperationLease,
    digest: ContentDigest,
    cancellation: &dyn BuildControl,
) -> Result<(Action, Receipt), BuildError> {
    cancellation.check()?;
    let bytes = lease
        .read_verified(digest, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("retained provider receipt is missing"))?;
    let receipt = Receipt::parse(bytes.as_bytes())?;
    let bytes = lease
        .read_verified(receipt.action, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("retained provider action is missing"))?;
    let action = Action::parse(bytes.as_bytes())?;
    if !receipt.matches_action(&action) {
        return Err(invalid("retained receipt and action disagree"));
    }
    receipt.verify_inputs(lease, &action, cancellation)?;
    Ok((action, receipt))
}

pub(crate) fn rebuild(store: &Store) -> Result<BuildIndexReport, BuildError> {
    let lease = store.operation()?;
    let mut report = BuildIndexReport::default();
    let mut actions: BTreeMap<ContentDigest, (Action, Vec<Candidate>)> = BTreeMap::new();
    for root in lease.managed_build_roots()? {
        let digest = managed_receipt(&root);
        let bytes = lease
            .read_verified(digest, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed root receipt is missing"))?;
        if !current_receipt(bytes.as_bytes()) {
            report.skipped += 1;
            continue;
        }
        let receipt = Receipt::parse(bytes.as_bytes())?;
        let bytes = lease
            .read_verified(receipt.action, MAX_RECORD_BYTES)?
            .ok_or_else(|| invalid("managed action is missing"))?;
        let action = Action::parse(bytes.as_bytes())?;
        let candidate = Candidate {
            receipt: digest,
            root: root.clone(),
        };
        let verified = verify_candidate(
            &lease,
            &action,
            candidate.clone(),
            &Cancellation::default(),
        )?
        .ok_or_else(|| invalid("managed root disappeared"))?;
        // Explicit reconstruction can confirm a previously uncertain root's
        // durability now; it does not rewrite the historical producer outcome.
        lease.publish_root(&root, &verified.receipt.references())?;
        let (_, candidates) = actions
            .entry(action.digest())
            .or_insert_with(|| (action, Vec::new()));
        admit_candidate(candidates, candidate);
    }
    // Validate the complete bounded managed-root inventory before replacing any
    // index entries. A concurrent producer may add a candidate after that scan;
    // merge valid current hints while holding the same publication lock.
    let rebuilt: BTreeSet<_> = actions.keys().copied().collect();
    for (digest, (action, mut candidates)) in actions {
        let cancellation = Cancellation::default();
        let shard = shard(&lease, digest, &cancellation)?;
        if let Some(bytes) = read_index_bytes(&shard, digest)?
            && let Ok(existing) = parse_index(digest, &bytes)
        {
            for found in verify_candidates(&lease, &action, existing, &cancellation)? {
                admit_candidate(&mut candidates, found.candidate);
            }
        }
        candidates.sort_by_key(|candidate| candidate.receipt);
        save_index(&shard, digest, &candidates)?;
        if candidates.len() == 2 {
            report.conflicts.push(digest);
        } else {
            report.indexed += 1;
        }
    }
    report.removed_stale = prune_stale(&lease, &rebuilt)?;
    Ok(report)
}

fn current_receipt(bytes: &[u8]) -> bool {
    bytes.starts_with(b"syrox-build-result-v4\n")
}

fn prune_stale(
    lease: &OperationLease,
    rebuilt: &BTreeSet<ContentDigest>,
) -> Result<usize, BuildError> {
    let parent = lease.action_directory()?;
    let mut count = 0;
    let shards = fd::read_directory(&parent, |_| {
        count += 1;
        if count > 256 {
            Err(())
        } else {
            Ok(())
        }
    })
    .map_err(problem)?;
    let mut removed = 0;
    for name in shards {
        let name = name
            .to_str()
            .ok_or_else(|| invalid("invalid index shard name"))?;
        if name.len() != 2
            || !name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid index shard name"));
        }
        let sample: ContentDigest = format!("{name}{}", "0".repeat(62))
            .parse()
            .expect("validated shard prefix");
        let directory = shard(lease, sample, &Cancellation::default())?;
        for entry in clean_temporaries(&directory)? {
            let action: ContentDigest = entry.parse().map_err(problem)?;
            if !entry.starts_with(name) {
                return Err(invalid("index entry is in the wrong shard"));
            }
            if rebuilt.contains(&action) {
                continue;
            }
            let candidates = read_index(&directory, action)?;
            let mut retained = false;
            for candidate in candidates {
                retained |= lease.build_references(&candidate.root)?.is_some();
            }
            if retained {
                continue;
            }
            let file = fd::open_existing_regular(directory.fd(), Path::new(&entry))?;
            fd::unlink_opened(
                directory.fd(),
                Path::new(&entry),
                file.metadata().identity(),
            )?;
            fd::sync_directory(directory.fd())?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn admit_candidate(candidates: &mut Vec<Candidate>, candidate: Candidate) {
    if candidates.len() < 2
        && !candidates
            .iter()
            .any(|old| old.receipt == candidate.receipt)
    {
        candidates.push(candidate);
    }
}

fn shard(
    lease: &OperationLease,
    action: ContentDigest,
    cancellation: &dyn BuildControl,
) -> Result<ShardGuard, BuildError> {
    cancellation.check()?;
    let started = Instant::now();
    let parent = lease.action_directory()?;
    let directory = fd::ensure_directory_beneath(parent.fd(), Path::new(&action.to_string()[..2]))
        .map_err(problem)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        cancellation.check()?;
        if fd::flock(directory.fd(), FlockMode::ExclusiveNonblocking)? {
            return Ok(ShardGuard {
                directory,
                acquired: Instant::now(),
                wait: started.elapsed(),
            });
        }
        if Instant::now() >= deadline {
            return Err(invalid("action index shard is busy"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn read_index(directory: &OpenedPath, action: ContentDigest) -> Result<Vec<Candidate>, BuildError> {
    read_index_bytes(directory, action)?.map_or_else(
        || Ok(Vec::new()),
        |bytes| parse_index(action, &bytes),
    )
}

fn read_index_bytes(
    directory: &OpenedPath,
    action: ContentDigest,
) -> Result<Option<Vec<u8>>, BuildError> {
    let file = match fd::open_beneath(
        directory.fd(),
        Path::new(&action.to_string()),
        false,
    ) {
        Ok(file) => file,
        Err(fd::OpenError::Other(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(problem(error)),
    };
    if !file.metadata().is_trusted_regular() {
        return Err(invalid("unsafe action index entry"));
    }
    let mut bytes = Vec::new();
    file.into_file()
        .take(MAX_INDEX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(invalid("oversized action index entry"));
    }
    Ok(Some(bytes))
}

fn encode_index(action: ContentDigest, entries: &[Candidate]) -> Vec<u8> {
    let mut text = format!("syrox-build-index\naction {action}\n");
    for entry in entries {
        writeln!(text, "result {} {}", entry.receipt, entry.root)
            .expect("String writes are infallible");
    }
    text.into_bytes()
}

fn parse_index(action: ContentDigest, bytes: &[u8]) -> Result<Vec<Candidate>, BuildError> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(invalid("oversized action index entry"));
    }
    let text = std::str::from_utf8(bytes).map_err(problem)?;
    let mut lines = text.lines();
    if lines.next() != Some("syrox-build-index")
        || lines.next() != Some(format!("action {action}").as_str())
    {
        return Err(invalid("wrong action index identity"));
    }
    let mut entries = Vec::new();
    for line in lines {
        if entries.len() == 2 {
            return Err(invalid("too many indexed results"));
        }
        let (receipt, root) = line
            .strip_prefix("result ")
            .and_then(|value| value.split_once(' '))
            .ok_or_else(|| invalid("invalid index result"))?;
        let receipt = receipt
            .parse()
            .map_err(|_| invalid("invalid indexed receipt"))?;
        let root = RootName::new(root).map_err(problem)?;
        entries.push(Candidate {
            receipt,
            root,
        });
    }
    if entries.is_empty()
        || entries
            .windows(2)
            .any(|pair| pair[0].receipt >= pair[1].receipt)
        || encode_index(action, &entries) != bytes
    {
        return Err(invalid("noncanonical action index entry"));
    }
    Ok(entries)
}

fn clean_temporaries(directory: &OpenedPath) -> Result<Vec<String>, BuildError> {
    let mut count = 0;
    let names = fd::read_directory(directory, |_| {
        count += 1;
        // Allow one interrupted atomic replacement at the entry limit.
        if count > MAX_SHARD_ENTRIES + 1 {
            Err(())
        } else {
            Ok(())
        }
    })
    .map_err(problem)?;
    let mut entries = Vec::new();
    let mut temporary = Vec::new();
    for name in names {
        let text = name
            .to_str()
            .ok_or_else(|| invalid("invalid index filename"))?;
        if text.parse::<ContentDigest>().is_ok() {
            entries.push(text.to_owned());
            continue;
        }
        if !text
            .strip_prefix(TEMP_PREFIX)
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(invalid("unexpected index shard entry"));
        }
        let file = fd::open_existing_regular(directory.fd(), Path::new(&name))?;
        if file.metadata().size() > MAX_INDEX_BYTES as u64 {
            return Err(invalid("oversized temporary index entry"));
        }
        temporary.push((name, file));
    }
    for (name, file) in temporary {
        fd::unlink_opened(
            directory.fd(),
            Path::new(&name),
            file.metadata().identity(),
        )?;
    }
    fd::sync_directory(directory.fd())?;
    Ok(entries)
}

fn problem(error: impl std::fmt::Debug) -> BuildError {
    invalid(&format!("{error:?}"))
}

#[cfg(test)]
#[path = "tests/cache.rs"]
pub(crate) mod tests;
