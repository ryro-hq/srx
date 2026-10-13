use super::*;

mod reopen;

const DURABLE_HEADER: &[u8] = b"syrox-durable-interest-v1\n";

pub(crate) struct DurableInterest {
    inner: Arc<StoreInner>,
    directory: Arc<crate::platform::linux::fd::OpenedPath>,
    name: String,
    identity: crate::platform::linux::fd::FileIdentity,
    bytes: Vec<u8>,
}

impl ObjectLease {
    pub(crate) fn durable_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.durable_bytes())
    }

    fn durable_bytes(&self) -> Vec<u8> {
        let mut bytes = DURABLE_HEADER.to_vec();
        bytes.extend_from_slice(&encode(&self.references, &self.views));
        bytes
    }
    /// Publish under a caller-owned 128-bit lowercase execution identity. The
    /// caller journals that identity before spawning; it is never an authority
    /// to infer process settlement. Matching publication can be resumed, while
    /// changing the retained set under an existing identity is refused.
    pub(crate) fn persist_checked(
        &self,
        execution: &str,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> Result<DurableInterest, StoreError> {
        check()?;
        let name = format!("hold-{execution}");
        if !exact_temporary(&name, "hold-") {
            return Err(StoreError::InterestCorrupt);
        }
        let _barrier = self.operation()?;
        let directory = Arc::new(open_interest_directory(&self.inner)?);
        let mut budget = WorkBudget::new(MAX_GC_WORK, "durable interest publication work");
        let entries = directory_names_bounded(
            &directory,
            MAX_INTERESTS,
            "interests",
            &mut budget,
        )?;
        if entries.len() as u64 >= MAX_INTERESTS && !entries.contains(&name) {
            return Err(StoreError::LimitExceeded {
                resource: "interests",
            });
        }
        let bytes = self.durable_bytes();
        charge(
            bytes.len() as u64,
            MAX_INTEREST_BYTES,
            "interest bytes",
        )?;
        check()?;
        // An interrupted temporary is an ordinary unlocked op-* record, which
        // GC may remove. The hold-* name becomes visible only after full fsync.
        let mut temporary =
            crate::platform::linux::fd::create_atomic_beneath_with_prefix(directory.fd(), "op-")
                .map_err(map_create_atomic_error)?;
        if let Err(source) = temporary.write_all(&bytes) {
            return Err(fail_atomic_publication(
                &mut temporary,
                StoreError::Io(source),
            ));
        }
        if let Err(source) = check() {
            return Err(fail_atomic_publication(
                &mut temporary,
                StoreError::Io(source),
            ));
        }
        match temporary.publish_noreplace(Path::new(&name)) {
            Ok(crate::platform::linux::fd::PublishStatus::Published) => {}
            Ok(crate::platform::linux::fd::PublishStatus::AlreadyExists) => {
                temporary
                    .discard()
                    .map_err(map_cleanup_uncertain)?;
            }
            Err(error) if error.committed => {
                return Err(StoreError::PublicationUncertain {
                    source: error.source,
                });
            }
            Err(error) => {
                return Err(fail_atomic_publication(
                    &mut temporary,
                    StoreError::Io(error.source),
                ));
            }
        }
        let opened = read_exact(&directory, &name, &bytes)?;
        crate::platform::linux::fd::sync_file(opened.fd())
            .and_then(|()| crate::platform::linux::fd::sync_directory(directory.fd()))
            .and_then(|()| {
                crate::platform::linux::fd::sync_directory(self.inner.private_parent.fd())
            })
            .map_err(|source| StoreError::PublicationUncertain {
                source,
            })?;
        Ok(DurableInterest {
            inner: Arc::clone(&self.inner),
            directory,
            name,
            identity: opened.metadata().identity(),
            bytes,
        })
    }
}

impl DurableInterest {
    pub(crate) fn execution(&self) -> &str {
        self.name
            .strip_prefix("hold-")
            .expect("validated durable name")
    }

    pub(crate) fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.bytes)
    }

    /// Revalidate the currently named durable record before recording a
    /// publication confirmation. A cached handle is not proof of persistence.
    pub(crate) fn verify_current_checked(
        &self,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> Result<(), StoreError> {
        check()?;
        let _barrier = Store {
            inner: Arc::clone(&self.inner),
        }
        .operation()?;
        let current = open_interest_directory(&self.inner)?;
        if current.metadata().identity() != self.directory.metadata().identity() {
            return Err(StoreError::InterestCorrupt);
        }
        let opened = read_exact(&current, &self.name, &self.bytes)?;
        if opened.metadata().identity() != self.identity {
            return Err(StoreError::InterestCorrupt);
        }
        check()?;
        Ok(())
    }

    /// Store primitive, not a process-liveness check. The session coordinator
    /// must require its authentic settlement capability before calling this.
    /// Failure retains the record or reports an uncertain durable removal.
    pub(crate) fn retire_checked(
        self,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> Result<(), StoreError> {
        check()?;
        let _barrier = Store {
            inner: Arc::clone(&self.inner),
        }
        .operation()?;
        let current = open_interest_directory(&self.inner)?;
        if current.metadata().identity() != self.directory.metadata().identity() {
            return Err(StoreError::InterestCorrupt);
        }
        let opened = read_exact(&current, &self.name, &self.bytes)?;
        if opened.metadata().identity() != self.identity {
            return Err(StoreError::InterestCorrupt);
        }
        check()?;
        crate::platform::linux::fd::unlink_opened(
            current.fd(),
            Path::new(&self.name),
            self.identity,
        )?;
        crate::platform::linux::fd::sync_directory(current.fd()).map_err(|source| {
            StoreError::PublicationUncertain {
                source,
            }
        })
    }
}

fn read_exact(
    directory: &crate::platform::linux::fd::OpenedPath,
    name: &str,
    expected: &[u8],
) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    let opened = open_regular(directory, name)?;
    if opened.metadata().mode() & 0o7777 != 0o600
        || opened.metadata().size() != expected.len() as u64
    {
        return Err(StoreError::InterestCorrupt);
    }
    let identity = opened.metadata().identity();
    let mut bytes = Vec::new();
    opened
        .into_file()
        .take(MAX_INTEREST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err(StoreError::InterestCorrupt);
    }
    let reopened = open_regular(directory, name)?;
    if reopened.metadata().identity() != identity {
        return Err(StoreError::InterestCorrupt);
    }
    Ok(reopened)
}

pub(super) fn decode(bytes: &[u8]) -> Result<(Vec<ContentDigest>, Vec<ContentDigest>), StoreError> {
    super::decode(
        bytes
            .strip_prefix(DURABLE_HEADER)
            .ok_or(StoreError::InterestCorrupt)?,
    )
}

#[cfg(test)]
mod tests;
