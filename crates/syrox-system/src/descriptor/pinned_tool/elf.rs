use super::refused;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;

/// Initial tools are ELF64 little-endian `x86_64` `ET_EXEC`, without `PT_INTERP`
/// or `PT_DYNAMIC`. This intentionally excludes static PIE and shared libraries.
pub(super) fn validate(
    file: &File,
    bytes: u64,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let mut header = [0_u8; 64];
    file.read_exact_at(&mut header, 0)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(header[7], 0 | 3)
        || header[8..16] != [0; 8]
        || u16_at(&header, 16) != 2
        || u16_at(&header, 18) != 62
        || u32_at(&header, 20) != 1
        || u32_at(&header, 48) != 0
        || u16_at(&header, 52) != 64
        || u16_at(&header, 54) != 56
    {
        return Err(refused(
            "system tool requires a static x86_64 ELF64 ET_EXEC",
        ));
    }
    let offset = u64_at(&header, 32);
    let count = u16_at(&header, 56);
    if !(1..=128).contains(&count) || offset < 64 || !offset.is_multiple_of(8) {
        return Err(refused(
            "invalid static tool program header table",
        ));
    }
    bounded(offset, u64::from(count) * 56, bytes)?;
    let entry = u64_at(&header, 24);
    let mut executable_entry = false;
    let mut program = [0_u8; 56];
    for index in 0..count {
        check()?;
        file.read_exact_at(&mut program, offset + u64::from(index) * 56)?;
        let kind = u32_at(&program, 0);
        let flags = u32_at(&program, 4);
        let start = u64_at(&program, 8);
        let address = u64_at(&program, 16);
        let size = u64_at(&program, 32);
        let memory = u64_at(&program, 40);
        if size > 0 {
            bounded(start, size, bytes)?;
        }
        if matches!(kind, 2 | 3) {
            return Err(refused(
                "system tool cannot have an interpreter or dynamic segment",
            ));
        }
        if kind == 1 {
            let alignment = u64_at(&program, 48);
            if size > memory
                || flags & !7 != 0
                || flags & 3 == 3
                || (alignment > 1
                    && (!alignment.is_power_of_two() || start % alignment != address % alignment))
            {
                return Err(refused(
                    "invalid or writable executable static tool segment",
                ));
            }
            let end = address
                .checked_add(size)
                .ok_or_else(|| refused("tool segment address overflow"))?;
            executable_entry |= flags & 1 != 0 && entry >= address && entry < end;
        }
        if kind == 0x6474_e551 && flags & 1 != 0 {
            return Err(refused(
                "system tool cannot request an executable stack",
            ));
        }
    }
    if !executable_entry {
        return Err(refused(
            "tool entry point is not in an executable file segment",
        ));
    }
    Ok(())
}

fn bounded(start: u64, size: u64, bytes: u64) -> io::Result<()> {
    if start
        .checked_add(size)
        .is_none_or(|end| end > bytes)
    {
        return Err(refused(
            "tool ELF range exceeds its pinned content",
        ));
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
