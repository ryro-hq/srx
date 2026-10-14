use super::*;

impl Store {
    /// Identity of permanent Store anchors, stable across reopening this Store.
    /// Journal this separately from the hold's retained-content digest. A path
    /// alone or a matching hold copied into another Store is not sufficient.
    #[cfg(test)]
    pub(crate) fn durable_interest_anchor(&self) -> Result<ContentDigest, StoreError> {
        let _barrier = self.operation()?;
        Ok(anchor(&self.inner))
    }

    pub(crate) fn reopen_durable_interest_checked(
        &self,
        execution: &str,
        expected_pin: ContentDigest,
        expected_store: ContentDigest,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> Result<DurableInterest, StoreError> {
        check()?;
        let name = format!("hold-{execution}");
        if !exact_temporary(&name, "hold-") {
            return Err(StoreError::InterestCorrupt);
        }
        let _barrier = self.operation()?;
        if anchor(&self.inner) != expected_store {
            return Err(StoreError::InterestStoreMismatch);
        }
        let directory = Arc::new(open_interest_directory(&self.inner)?);
        let opened = open_regular(&directory, &name)?;
        let identity = opened.metadata().identity();
        if opened.metadata().mode() & 0o7777 != 0o600
            || opened.metadata().size() > MAX_INTEREST_BYTES
        {
            return Err(StoreError::InterestCorrupt);
        }
        let bytes = read_bounded(opened.into_file(), &mut check)?;
        decode(&bytes)?;
        if ContentDigest::sha256(&bytes) != expected_pin {
            return Err(StoreError::InterestCorrupt);
        }
        check()?;
        // Re-read canonical bytes and pin the final named inode. Replacement
        // during the read is refused even when its contents happen to match.
        let reopened = read_exact(&directory, &name, &bytes)?;
        if reopened.metadata().identity() != identity {
            return Err(StoreError::InterestCorrupt);
        }
        check()?;
        Ok(DurableInterest {
            inner: Arc::clone(&self.inner),
            directory,
            name,
            identity,
            bytes,
        })
    }
}
impl ObjectLease {
    pub(crate) fn durable_store_anchor(&self) -> Result<ContentDigest, StoreError> {
        let _barrier = self.operation()?;
        Ok(anchor(&self.inner))
    }
}
impl DurableInterest {
    /// Comparison data only. Reopening revalidates the Store anchors under its
    /// operation barrier; this digest is not authority for retirement.
    pub(crate) fn store_anchor(&self) -> ContentDigest {
        anchor(&self.inner)
    }
}
fn anchor(inner: &StoreInner) -> ContentDigest {
    let mut bytes = b"syrox-durable-store-anchor-v1\n".to_vec();
    for identity in [
        inner.objects_parent.metadata().identity(),
        inner.objects.metadata().identity(),
        inner.roots_parent.metadata().identity(),
        inner.roots.metadata().identity(),
        inner.private_parent.metadata().identity(),
        inner.coordination.metadata().identity(),
        inner.interests.metadata().identity(),
        inner.lease_identity,
    ] {
        bytes.extend(identity.device.to_le_bytes());
        bytes.extend(identity.inode.to_le_bytes());
    }
    ContentDigest::sha256(&bytes)
}
fn read_bounded(
    mut file: File,
    check: &mut impl FnMut() -> io::Result<()>,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() as u64 + count as u64 > MAX_INTEREST_BYTES {
            return Err(StoreError::InterestCorrupt);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}
