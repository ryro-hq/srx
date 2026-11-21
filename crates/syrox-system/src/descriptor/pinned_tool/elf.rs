use super::refused;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;
use syrox_encoding::{u16_le_at, u32_le_at, u64_le_at};

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
        || field(u16_le_at, &header, 16) != 2
        || field(u16_le_at, &header, 18) != 62
        || field(u32_le_at, &header, 20) != 1
        || field(u32_le_at, &header, 48) != 0
        || field(u16_le_at, &header, 52) != 64
        || field(u16_le_at, &header, 54) != 56
    {
        return Err(refused(
            "system tool requires a static x86_64 ELF64 ET_EXEC",
        ));
    }
    let offset = field(u64_le_at, &header, 32);
    let count = field(u16_le_at, &header, 56);
    if !(1..=128).contains(&count) || offset < 64 || !offset.is_multiple_of(8) {
        return Err(refused(
            "invalid static tool program header table",
        ));
    }
    bounded(offset, u64::from(count) * 56, bytes)?;
    let entry = field(u64_le_at, &header, 24);
    let mut executable_entry = false;
    let mut program = [0_u8; 56];
    for index in 0..count {
        check()?;
        file.read_exact_at(&mut program, offset + u64::from(index) * 56)?;
        let kind = field(u32_le_at, &program, 0);
        let flags = field(u32_le_at, &program, 4);
        let start = field(u64_le_at, &program, 8);
        let address = field(u64_le_at, &program, 16);
        let size = field(u64_le_at, &program, 32);
        let memory = field(u64_le_at, &program, 40);
        if size > 0 {
            bounded(start, size, bytes)?;
        }
        if matches!(kind, 2 | 3) {
            return Err(refused(
                "system tool cannot have an interpreter or dynamic segment",
            ));
        }
        if kind == 1 {
            let alignment = field(u64_le_at, &program, 48);
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

/// Fields of the fixed-size ELF header and program header buffers.
fn field<T>(read: fn(&[u8], usize) -> Option<T>, bytes: &[u8], at: usize) -> T {
    read(bytes, at).expect("ELF field lies inside its fixed-size header buffer")
}
