//! Confere se a imagem da release é ELF64/x86_64 estático.
//!
//! A leitura tem limites para tabelas e segmentos. Loader externo ou
//! dependência dinâmica fazem a imagem ser recusada para distribuição.

fn number(bytes: &[u8], start: usize, size: usize) -> Option<u64> {
    let slice = bytes.get(start..start.checked_add(size)?)?;
    let mut padded = [0_u8; 8];
    padded.get_mut(..size)?.copy_from_slice(slice);
    Some(u64::from_le_bytes(padded))
}

pub(crate) fn static_x86_64(bytes: &[u8]) -> bool {
    if bytes.get(..6) != Some(&b"\x7fELF\x02\x01"[..])
        || number(bytes, 18, 2) != Some(62)
        || !matches!(number(bytes, 16, 2), Some(2 | 3))
        || number(bytes, 52, 2) != Some(64)
    {
        return false;
    }
    let Some(start) = number(bytes, 32, 8).and_then(|value| usize::try_from(value).ok()) else {
        return false;
    };
    let Some(stride) = number(bytes, 54, 2).and_then(|value| usize::try_from(value).ok()) else {
        return false;
    };
    let Some(count) = number(bytes, 56, 2).and_then(|value| usize::try_from(value).ok()) else {
        return false;
    };
    if stride < 56 || count == 0 || count > 128 {
        return false;
    }
    let mut load = false;
    for index in 0..count {
        let Some(offset) = index
            .checked_mul(stride)
            .and_then(|n| start.checked_add(n))
        else {
            return false;
        };
        if bytes
            .get(offset..offset.saturating_add(56))
            .is_none()
        {
            return false;
        }
        match number(bytes, offset, 4) {
            Some(1) => load = true,
            Some(3) | None => return false, // PT_INTERP or incomplete header
            Some(2) => {
                let Some(begin) =
                    number(bytes, offset + 8, 8).and_then(|n| usize::try_from(n).ok())
                else {
                    return false;
                };
                let Some(length) =
                    number(bytes, offset + 32, 8).and_then(|n| usize::try_from(n).ok())
                else {
                    return false;
                };
                let Some(end) = begin.checked_add(length) else {
                    return false;
                };
                let Some(dynamic) = bytes.get(begin..end) else {
                    return false;
                };
                if length % 16 != 0
                    || dynamic
                        .as_chunks::<16>()
                        .0
                        .iter()
                        .any(|entry| number(entry, 0, 8) == Some(1))
                {
                    return false; // DT_NEEDED
                }
            }
            Some(_) => {}
        }
    }
    load
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_and_dynamic_elf_headers() {
        assert!(!static_x86_64(b"not an ELF"));
        let mut elf = vec![0; 128];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[16] = 3;
        elf[18] = 62;
        elf[32] = 64;
        elf[52] = 64;
        elf[54] = 56;
        elf[56] = 1;
        elf[64] = 1;
        assert!(static_x86_64(&elf));
        elf[64] = 3;
        assert!(!static_x86_64(&elf));
    }
}
