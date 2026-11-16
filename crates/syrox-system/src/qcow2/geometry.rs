use super::{CLUSTER_BYTES, QcowError, REFCOUNT_ENTRIES, TABLE_ENTRIES};

/// Private, checked geometry. Metadata sizes are solved including their own
/// refcounts, before any source read or output write. No deserialization bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub(super) virtual_bytes: u64,
    pub(super) data_clusters: u64,
    pub(super) l2_clusters: u64,
    pub(super) l1_clusters: u64,
    pub(super) refcount_table_clusters: u64,
    pub(super) refcount_blocks: u64,
    pub(super) total_clusters: u64,
}

impl Geometry {
    pub fn new(virtual_bytes: u64) -> Result<Self, QcowError> {
        if virtual_bytes == 0 || !virtual_bytes.is_multiple_of(512) {
            return Err(QcowError::InputSize);
        }
        let data_clusters = virtual_bytes.div_ceil(CLUSTER_BYTES);
        let l2_clusters = data_clusters.div_ceil(TABLE_ENTRIES);
        let l1_clusters = l2_clusters.div_ceil(TABLE_ENTRIES);
        // QEMU's supported L1 table ceiling is 32 MiB.
        if l1_clusters > 32 * 1024 * 1024 / CLUSTER_BYTES {
            return Err(QcowError::Geometry);
        }
        let fixed = 1_u64
            .checked_add(data_clusters)
            .and_then(|value| value.checked_add(l2_clusters))
            .and_then(|value| value.checked_add(l1_clusters))
            .ok_or(QcowError::Geometry)?;
        let mut refcount_blocks = 0;
        let mut refcount_table_clusters = 0;
        for _ in 0..16 {
            let total_clusters = fixed
                .checked_add(refcount_blocks)
                .and_then(|value| value.checked_add(refcount_table_clusters))
                .ok_or(QcowError::Geometry)?;
            let next_blocks = total_clusters.div_ceil(REFCOUNT_ENTRIES);
            let next_table = next_blocks.div_ceil(TABLE_ENTRIES);
            if next_blocks == refcount_blocks && next_table == refcount_table_clusters {
                let bytes = total_clusters
                    .checked_mul(CLUSTER_BYTES)
                    .ok_or(QcowError::Geometry)?;
                // Standard cluster offsets have only 56 usable bits. QEMU also
                // limits the refcount table to 8 MiB.
                if bytes > 1_u64 << 56 || next_table > 8 * 1024 * 1024 / CLUSTER_BYTES {
                    return Err(QcowError::Geometry);
                }
                return Ok(Self {
                    virtual_bytes,
                    data_clusters,
                    l2_clusters,
                    l1_clusters,
                    refcount_table_clusters,
                    refcount_blocks,
                    total_clusters,
                });
            }
            refcount_blocks = next_blocks;
            refcount_table_clusters = next_table;
        }
        Err(QcowError::Geometry)
    }
    pub const fn virtual_bytes(&self) -> u64 {
        self.virtual_bytes
    }
    pub const fn encoded_bytes(&self) -> u64 {
        self.total_clusters * CLUSTER_BYTES
    }
    pub const fn data_clusters(&self) -> u64 {
        self.data_clusters
    }
    pub const fn l2_tables(&self) -> u64 {
        self.l2_clusters
    }
    pub const fn refcount_blocks(&self) -> u64 {
        self.refcount_blocks
    }
    pub(super) const fn refcount_table_start(&self) -> u64 {
        1 + self.l1_clusters
    }
    pub(super) const fn refcount_blocks_start(&self) -> u64 {
        self.refcount_table_start() + self.refcount_table_clusters
    }
    pub(super) const fn l2_start(&self) -> u64 {
        self.refcount_blocks_start() + self.refcount_blocks
    }
    pub(super) const fn data_start(&self) -> u64 {
        self.l2_start() + self.l2_clusters
    }
}
