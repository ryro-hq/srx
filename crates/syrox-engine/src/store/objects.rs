use super::*;

impl StoreStaging {
    pub const fn expected_digest(&self) -> ContentDigest {
        self.expected
    }

    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn append(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        #[cfg(target_os = "linux")]
        {
            if self.failed {
                return Err(StoreError::StagingFailed);
            }
            let size = self
                .size
                .checked_add(bytes.len() as u64)
                .filter(|size| *size <= self.maximum_bytes)
                .ok_or_else(|| {
                    self.failed = true;
                    StoreError::BlobTooLarge {
                        limit: self.maximum_bytes,
                    }
                })?;
            if let Err(source) = self.temporary.write_all(bytes) {
                self.failed = true;
                return Err(StoreError::Io(source));
            }
            self.hasher.update(bytes);
            self.size = size;
            Ok(())
        }
    }

    pub fn finish(self) -> Result<StoreObject, StoreError> {
        #[cfg(target_os = "linux")]
        {
            self.finish_in(None)
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn finish_in(
        mut self,
        directory: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<StoreObject, StoreError> {
        #[cfg(target_os = "linux")]
        {
            if self.failed {
                return self.fail_with_cleanup(StoreError::StagingFailed);
            }
            let actual = ContentDigest::from_sha256_hash(self.hasher.clone().finalize().into());
            if actual != self.expected {
                let expected = self.expected;
                return self.fail_with_cleanup(StoreError::DigestMismatch {
                    expected,
                    actual,
                });
            }
            match self
                .temporary
                .publish_noreplace_in(directory, Path::new(&self.expected.to_string()))
            {
                Ok(crate::platform::linux::fd::PublishStatus::Published) => Ok(StoreObject {
                    digest: self.expected,
                    size: self.size,
                    state: StoreObjectState::Published,
                }),
                Ok(crate::platform::linux::fd::PublishStatus::AlreadyExists) => {
                    self.temporary
                        .discard()
                        .map_err(map_cleanup_uncertain)?;
                    verify_from_directory(
                        directory.unwrap_or(self.temporary.directory()),
                        self.expected,
                        MAX_STORE_BLOB_BYTES,
                    )?
                    .ok_or(StoreError::ObjectDisappeared {
                        digest: self.expected,
                    })
                }
                Err(error) if error.committed => Err(StoreError::PublicationUncertain {
                    source: error.source,
                }),
                Err(error) => self.fail_with_cleanup(StoreError::Io(error.source)),
            }
        }
    }

    pub fn abort(self) -> Result<(), StoreError> {
        #[cfg(target_os = "linux")]
        {
            let mut self_ = self;
            self_
                .temporary
                .discard()
                .map_err(map_cleanup_uncertain)
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn fail_with_cleanup(
        mut self,
        primary: StoreError,
    ) -> Result<StoreObject, StoreError> {
        match self.temporary.discard() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(StoreError::CleanupFailed {
                primary: Box::new(primary),
                cleanup: map_cleanup_error(cleanup),
            }),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct StoreAdmission {
    pub(super) staging: StoreStaging,
}

#[cfg(target_os = "linux")]
impl StoreAdmission {
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        self.staging.append(bytes)
    }
    pub(crate) fn size(&self) -> u64 {
        self.staging.size
    }
    pub(crate) fn digest(&self) -> ContentDigest {
        ContentDigest::from_sha256_hash(self.staging.hasher.clone().finalize().into())
    }
    pub(crate) fn abort(self) -> Result<(), StoreError> {
        self.staging.abort()
    }
    pub(crate) fn finish(mut self) -> Result<StoreObject, StoreError> {
        self.staging.expected = self.digest();
        let shard = open_shard(&self.staging.lease.inner, self.staging.expected)?;
        self.staging.finish_in(Some(shard.fd()))
    }
}
