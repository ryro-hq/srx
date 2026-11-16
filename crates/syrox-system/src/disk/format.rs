use super::{DiskLayout, ENTRIES, ENTRY_BYTES, Guid, TABLE_BYTES};

fn guid_bytes(guid: Guid) -> [u8; 16] {
    let mut bytes = guid.0;
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    bytes
}

// UEFI CRC-32/ISO-HDLC, reflected polynomial, initial/final XOR all ones.
pub(super) fn crc32(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(value & 1));
        }
    }
    !value
}

pub(super) fn protective_mbr(layout: &DiskLayout) -> Vec<u8> {
    let block = layout.spec.logical_block_bytes as usize;
    let mut bytes = vec![0; block];
    bytes[447..450].copy_from_slice(&[0, 2, 0]);
    bytes[450] = 0xee;
    bytes[451..454].fill(0xff);
    bytes[454..458].copy_from_slice(&1_u32.to_le_bytes());
    let sectors = layout.spec.bytes / block as u64 - 1;
    bytes[458..462].copy_from_slice(
        &u32::try_from(sectors)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
    bytes
}

pub(super) fn table(layout: &DiskLayout) -> Vec<u8> {
    let block = u64::from(layout.spec.logical_block_bytes);
    let mut bytes = vec![0; TABLE_BYTES];
    for partition in &layout.spec.partitions {
        let offset = (partition.number as usize - 1) * ENTRY_BYTES;
        let entry = &mut bytes[offset..offset + ENTRY_BYTES];
        entry[..16].copy_from_slice(&guid_bytes(partition.partition_type));
        entry[16..32].copy_from_slice(&guid_bytes(partition.guid));
        entry[32..40].copy_from_slice(&(partition.start_bytes / block).to_le_bytes());
        entry[40..48].copy_from_slice(
            &((partition.start_bytes + partition.size_bytes) / block - 1).to_le_bytes(),
        );
        entry[48..56].copy_from_slice(&partition.attributes.to_le_bytes());
        for (index, character) in partition.name.encode_utf16().enumerate() {
            entry[56 + index * 2..58 + index * 2].copy_from_slice(&character.to_le_bytes());
        }
    }
    bytes
}

pub(super) fn header(layout: &DiskLayout, table_crc32: u32, backup: bool) -> Vec<u8> {
    let block = u64::from(layout.spec.logical_block_bytes);
    let last = layout.spec.bytes / block - 1;
    let mut bytes = vec![0; usize::try_from(block).expect("validated logical block size")];
    bytes[..8].copy_from_slice(b"EFI PART");
    bytes[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&92_u32.to_le_bytes());
    for (offset, value) in [
        (
            24,
            if backup {
                last
            } else {
                1
            },
        ),
        (
            32,
            if backup {
                1
            } else {
                last
            },
        ),
        (40, layout.first_usable),
        (48, layout.last_usable),
        (
            72,
            if backup {
                last - TABLE_BYTES as u64 / block
            } else {
                2
            },
        ),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[56..72].copy_from_slice(&guid_bytes(layout.spec.guid));
    bytes[80..84].copy_from_slice(
        &u32::try_from(ENTRIES)
            .expect("fixed GPT entry count")
            .to_le_bytes(),
    );
    bytes[84..88].copy_from_slice(
        &u32::try_from(ENTRY_BYTES)
            .expect("fixed GPT entry size")
            .to_le_bytes(),
    );
    bytes[88..92].copy_from_slice(&table_crc32.to_le_bytes());
    let checksum = crc32(&bytes[..92]);
    bytes[16..20].copy_from_slice(&checksum.to_le_bytes());
    bytes
}
