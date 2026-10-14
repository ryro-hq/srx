use super::*;

pub(in crate::build) fn toolchain_inventory(
    root: &Path,
    cancellation: &dyn BuildControl,
) -> Result<(Vec<u8>, Vec<PathBuf>), BuildError> {
    let available_workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(INVENTORY_WORKERS);
    let permits = InventoryPermits::acquire(available_workers, cancellation)?;
    toolchain_inventory_with_workers(root, cancellation, permits.count)
}

pub(in crate::build) fn toolchain_inventory_with_workers(
    root: &Path,
    cancellation: &dyn BuildControl,
    workers: usize,
) -> Result<(Vec<u8>, Vec<PathBuf>), BuildError> {
    let mut paths = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            cancellation.check()?;
            if paths.len() >= MAX_TOOLCHAIN_FILES {
                return Err(BuildError::Toolchain);
            }
            let path = entry?.path();
            if path.components().count() > 64 {
                return Err(BuildError::Toolchain);
            }
            if fs::symlink_metadata(&path)?.is_dir() {
                pending.push(path.clone());
            }
            paths.push(path);
        }
    }
    paths.sort();
    let opened =
        crate::platform::linux::fd::open_top_directory(root).map_err(|_| BuildError::Toolchain)?;
    let workers = workers
        .clamp(1, INVENTORY_WORKERS)
        .min(paths.len().max(1));
    let opened = &opened;
    let paths = &paths;
    std::thread::scope(|scope| {
        let (jobs, incoming) = mpsc::sync_channel(workers * INVENTORY_TASKS_PER_WORKER);
        let incoming = Arc::new(Mutex::new(incoming));
        let (finished, replies) = mpsc::channel();
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let incoming = Arc::clone(&incoming);
            let finished = finished.clone();
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                inventory_worker(
                    root,
                    opened,
                    paths,
                    cancellation,
                    &incoming,
                    &finished,
                );
            }) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    drop(jobs);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(BuildError::Io(error));
                }
            }
        }
        drop(finished);
        // Only workers retain the receiving end. If all of them exit, a full
        // bounded queue must fail the send instead of blocking forever.
        drop(incoming);
        let result = serialize_inventory(
            root,
            paths,
            cancellation,
            workers,
            &jobs,
            &replies,
        );
        drop(jobs);
        let mut panicked = false;
        for handle in handles {
            panicked |= handle.join().is_err();
        }
        if panicked {
            return Err(BuildError::Inventory(
                "inventory worker panicked".into(),
            ));
        }
        result
    })
}

fn serialize_inventory(
    root: &Path,
    paths: &[PathBuf],
    cancellation: &dyn BuildControl,
    workers: usize,
    jobs: &mpsc::SyncSender<InventoryJob>,
    replies: &mpsc::Receiver<InventoryReply>,
) -> Result<(Vec<u8>, Vec<PathBuf>), BuildError> {
    let mut bytes = b"syrox-host-toolchain\n".to_vec();
    let mut total = 0_u64;
    let mut blocked = Vec::new();
    let mut queue = InventoryQueue {
        workers,
        jobs,
        replies,
        hashes: Vec::with_capacity(INVENTORY_BATCH),
        errors: BTreeMap::new(),
    };
    let mut metadata = Vec::with_capacity(INVENTORY_BATCH);
    for (number, batch) in paths.chunks(INVENTORY_BATCH).enumerate() {
        let mut budget = total;
        metadata.clear();
        for path in batch {
            cancellation.check()?;
            let item = fs::symlink_metadata(path)?;
            if item.is_file() {
                budget = budget
                    .checked_add(item.len())
                    .filter(|size| *size <= MAX_TOOLCHAIN_BYTES)
                    .ok_or(BuildError::Toolchain)?;
            }
            metadata.push(item);
        }
        queue.hash_batch(number * INVENTORY_BATCH, &metadata, cancellation)?;
        for (index, (path, metadata)) in batch.iter().zip(&metadata).enumerate() {
            cancellation.check()?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| BuildError::Toolchain)?;
            let name = relative.to_str().ok_or(BuildError::Toolchain)?;
            if name.len() > 4096 || bytes.len() + name.len() + 8192 > MAX_INVENTORY_BYTES {
                return Err(BuildError::Toolchain);
            }
            let link;
            let digest;
            let content = if metadata.is_symlink() {
                bytes.push(b'l');
                link = fs::read_link(path)?
                    .to_str()
                    .ok_or(BuildError::Toolchain)?
                    .as_bytes()
                    .to_vec();
                link.as_slice()
            } else if metadata.is_dir() {
                bytes.push(b'd');
                &[][..]
            } else if metadata.is_file() {
                bytes.push(b'f');
                total = total
                    .checked_add(metadata.len())
                    .filter(|n| *n <= MAX_TOOLCHAIN_BYTES)
                    .ok_or(BuildError::Toolchain)?;
                if let Some(error) = queue.errors.remove(&index) {
                    return Err(error);
                }
                let HashOutcome::Digest(value) = queue.hashes[index]
                    .take()
                    .expect("file has a hash result")
                else {
                    // Excluded helpers cannot execute: the supervisor masks them.
                    blocked.push(path.clone());
                    bytes.extend_from_slice(b"blocked\0");
                    bytes.extend_from_slice(name.as_bytes());
                    bytes.push(0);
                    continue;
                };
                digest = value;
                digest.as_slice()
            } else {
                return Err(BuildError::Toolchain);
            };
            if name.len() > 4096 || content.len() > 4096 {
                return Err(BuildError::Toolchain);
            }
            for field in [
                name.as_bytes(),
                &metadata.mode().to_le_bytes(),
                &metadata.len().to_le_bytes(),
                content,
            ] {
                if bytes.len() + 8 + field.len() > MAX_INVENTORY_BYTES {
                    return Err(BuildError::Toolchain);
                }
                bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
                bytes.extend_from_slice(field);
            }
        }
    }
    Ok((bytes, blocked))
}

type InventoryHash = Result<Option<[u8; 32]>, BuildError>;

struct InventoryJob {
    files: Vec<(usize, u64)>,
}

struct InventoryReply {
    digests: Vec<(usize, HashOutcome)>,
    errors: Vec<(usize, BuildError)>,
}

enum HashOutcome {
    Digest([u8; 32]),
    Blocked,
}

struct InventoryQueue<'a> {
    workers: usize,
    jobs: &'a mpsc::SyncSender<InventoryJob>,
    replies: &'a mpsc::Receiver<InventoryReply>,
    hashes: Vec<Option<HashOutcome>>,
    errors: BTreeMap<usize, BuildError>,
}

fn inventory_worker(
    root: &Path,
    opened: &crate::platform::linux::fd::OpenedPath,
    paths: &[PathBuf],
    cancellation: &dyn BuildControl,
    incoming: &Mutex<mpsc::Receiver<InventoryJob>>,
    finished: &mpsc::Sender<InventoryReply>,
) {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let job = incoming
            .lock()
            .expect("inventory queue poisoned")
            .recv();
        let Ok(job) = job else {
            break;
        };
        let mut digests = Vec::with_capacity(job.files.len());
        let mut errors = Vec::new();
        for (index, size) in job.files {
            match hash_inventory_file(
                root,
                opened,
                &paths[index],
                size,
                &mut buffer,
                cancellation,
            ) {
                Ok(Some(digest)) => digests.push((index, HashOutcome::Digest(digest))),
                Ok(None) => digests.push((index, HashOutcome::Blocked)),
                Err(error) => errors.push((index, error)),
            }
        }
        if finished
            .send(InventoryReply {
                digests,
                errors,
            })
            .is_err()
        {
            break;
        }
    }
}

impl InventoryQueue<'_> {
    fn hash_batch(
        &mut self,
        base: usize,
        metadata: &[fs::Metadata],
        cancellation: &dyn BuildControl,
    ) -> Result<(), BuildError> {
        self.hashes.clear();
        self.hashes.resize_with(metadata.len(), || None);
        self.errors.clear();
        let chunk_size = metadata
            .len()
            .div_ceil(self.workers * INVENTORY_TASKS_PER_WORKER)
            .max(1);
        let mut submitted = 0;
        for (number, group) in metadata.chunks(chunk_size).enumerate() {
            cancellation.check()?;
            let files = group
                .iter()
                .enumerate()
                .filter(|(_, metadata)| metadata.is_file())
                .map(|(index, metadata)| (base + number * chunk_size + index, metadata.len()))
                .collect::<Vec<_>>();
            if !files.is_empty() {
                self.jobs
                    .send(InventoryJob {
                        files,
                    })
                    .map_err(|_| BuildError::Inventory("inventory workers exited".into()))?;
                submitted += 1;
            }
        }
        for _ in 0..submitted {
            let reply = self
                .replies
                .recv()
                .map_err(|_| BuildError::Inventory("inventory workers exited".into()))?;
            for (index, digest) in reply.digests {
                self.hashes[index - base] = Some(digest);
            }
            for (index, error) in reply.errors {
                self.errors.insert(index - base, error);
            }
        }
        cancellation.check()?;
        Ok(())
    }
}

fn hash_inventory_file(
    root: &Path,
    opened: &crate::platform::linux::fd::OpenedPath,
    path: &Path,
    size: u64,
    buffer: &mut [u8; 16 * 1024],
    cancellation: &dyn BuildControl,
) -> InventoryHash {
    cancellation.check()?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| BuildError::Toolchain)?;
    let file = match crate::platform::linux::fd::open_beneath(opened.fd(), relative, false) {
        Ok(file) => file,
        Err(crate::platform::linux::fd::OpenError::Other(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(BuildError::Inventory(format!(
                "{}: {error:?}",
                path.display()
            )));
        }
    };
    if file.metadata().file_type() != crate::platform::linux::fd::FileType::Regular {
        return Err(BuildError::Toolchain);
    }
    hash_file(file.into_file(), size, buffer, cancellation).map(Some)
}

pub(in crate::build) fn hash_file(
    file: fs::File,
    size: u64,
    buffer: &mut [u8; 16 * 1024],
    cancellation: &dyn BuildControl,
) -> Result<[u8; 32], BuildError> {
    let mut reader = file.take(size + 1);
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    loop {
        cancellation.check()?;
        let read = reader.read(buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        hash.update(&buffer[..read]);
    }
    if count != size {
        return Err(BuildError::InputChanged);
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_inventory_failures_are_indexed_in_canonical_order() {
        let root = tempfile::tempdir().unwrap();
        let paths = (0..64)
            .map(|index| root.path().join(format!("file-{index:03}")))
            .collect::<Vec<_>>();
        for path in &paths {
            fs::write(path, b"data").unwrap();
        }
        let metadata = paths
            .iter()
            .map(|path| fs::metadata(path).unwrap())
            .collect::<Vec<_>>();
        let opened = crate::platform::linux::fd::open_top_directory(root.path()).unwrap();
        fs::remove_file(&paths[0]).unwrap();
        fs::remove_file(&paths[63]).unwrap();
        let cancellation = Cancellation::default();
        std::thread::scope(|scope| {
            let (jobs, incoming) = mpsc::sync_channel(32);
            let incoming = Arc::new(Mutex::new(incoming));
            let (finished, replies) = mpsc::channel();
            let handles = (0..4)
                .map(|_| {
                    let sender = finished.clone();
                    let incoming = Arc::clone(&incoming);
                    let paths = &paths;
                    let opened = &opened;
                    let cancellation = &cancellation;
                    let path = root.path();
                    scope.spawn(move || {
                        inventory_worker(
                            path,
                            opened,
                            paths,
                            cancellation,
                            &incoming,
                            &sender,
                        );
                    })
                })
                .collect::<Vec<_>>();
            drop(finished);
            let mut queue = InventoryQueue {
                workers: 4,
                jobs: &jobs,
                replies: &replies,
                hashes: Vec::new(),
                errors: BTreeMap::new(),
            };
            queue
                .hash_batch(0, &metadata, &cancellation)
                .unwrap();
            assert_eq!(
                queue.errors.keys().copied().collect::<Vec<_>>(),
                [0, 63]
            );
            drop(jobs);
            for handle in handles {
                handle.join().unwrap();
            }
        });
    }
}
