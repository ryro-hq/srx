use crate::source::Source;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionEncoding {
    Utf8,
    Utf16,
}

/// Zero-based editor position. `character` uses the requested encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextPosition {
    pub line: u32,
    pub character: u32,
}

#[derive(Clone, Debug)]
struct WideCharacter {
    byte: u32,
    utf16: u32,
    bytes: u32,
    units: u32,
}

#[derive(Clone, Debug)]
struct Line {
    start: u32,
    end: u32,
    wide: Vec<WideCharacter>,
}

/// Index for one immutable source. Conversions are exact: invalid byte or
/// surrogate boundaries, columns past EOL and the interior of CRLF return None.
/// LF, CRLF and bare CR delimit lines; the final empty line is retained.
#[derive(Clone, Debug)]
pub struct LineIndex {
    lines: Vec<Line>,
}

impl LineIndex {
    pub fn new(source: &Source) -> Self {
        let mut lines = Vec::new();
        let mut line = Line {
            start: 0,
            end: 0,
            wide: Vec::new(),
        };
        let mut utf16 = 0;
        let mut chars = source.text().char_indices().peekable();
        while let Some((offset, character)) = chars.next() {
            let offset = u32::try_from(offset).expect("source size is bounded");
            let bytes = u32::try_from(character.len_utf8()).expect("character size is bounded");
            if matches!(character, '\r' | '\n') {
                line.end = offset;
                lines.push(line);
                let mut start = offset + bytes;
                if character == '\r'
                    && chars
                        .peek()
                        .is_some_and(|(_, next)| *next == '\n')
                {
                    chars.next();
                    start += 1;
                }
                line = Line {
                    start,
                    end: start,
                    wide: Vec::new(),
                };
                utf16 = 0;
            } else {
                let units =
                    u32::try_from(character.len_utf16()).expect("character size is bounded");
                if !character.is_ascii() {
                    line.wide.push(WideCharacter {
                        byte: offset - line.start,
                        utf16,
                        bytes,
                        units,
                    });
                }
                utf16 += units;
            }
        }
        line.end = u32::try_from(source.text().len()).expect("source size is bounded");
        lines.push(line);
        Self {
            lines,
        }
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn position(&self, offset: u32, encoding: PositionEncoding) -> Option<TextPosition> {
        let index = self
            .lines
            .partition_point(|line| line.start <= offset)
            .checked_sub(1)?;
        let line = &self.lines[index];
        if offset > line.end {
            return None;
        }
        let byte = offset - line.start;
        let previous = line
            .wide
            .partition_point(|character| character.byte < byte);
        let mut utf16 = byte;
        if previous > 0 {
            let character = &line.wide[previous - 1];
            if byte < character.byte + character.bytes {
                return None;
            }
            utf16 -= character.byte + character.bytes - character.utf16 - character.units;
        }
        Some(TextPosition {
            line: u32::try_from(index).expect("source size bounds line count"),
            character: match encoding {
                PositionEncoding::Utf8 => byte,
                PositionEncoding::Utf16 => utf16,
            },
        })
    }

    pub fn offset(&self, position: TextPosition, encoding: PositionEncoding) -> Option<u32> {
        let line = self.lines.get(position.line as usize)?;
        let column = position.character;
        let byte = match encoding {
            PositionEncoding::Utf8 => column,
            PositionEncoding::Utf16 => {
                let previous = line
                    .wide
                    .partition_point(|character| character.utf16 < column);
                if previous == 0 {
                    column
                } else {
                    let character = &line.wide[previous - 1];
                    if column < character.utf16 + character.units {
                        return None;
                    }
                    column.checked_add(
                        character.byte + character.bytes - character.utf16 - character.units,
                    )?
                }
            }
        };
        let offset = line.start.checked_add(byte)?;
        (self.position(offset, encoding)? == position).then_some(offset)
    }

    /// Read-only protocol ranges may extend past EOL/EOF. Clamp those endpoints
    /// while still rejecting positions inside UTF-8 characters or surrogate pairs.
    /// Mutating edits should continue to use the exact `offset` conversion.
    pub fn offset_clamped(
        &self,
        position: TextPosition,
        encoding: PositionEncoding,
    ) -> Option<u32> {
        let Some(line) = self.lines.get(position.line as usize) else {
            return self.lines.last().map(|line| line.end);
        };
        let end = self.position(line.end, encoding)?;
        if position.character >= end.character {
            Some(line.end)
        } else {
            self.offset(position, encoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_ranges_clamp_past_eol_and_eof_but_reject_split_characters() {
        let source = Source::new("buffer.srx", "é😀\r\nx").unwrap();
        let index = LineIndex::new(&source);
        for encoding in [
            PositionEncoding::Utf8,
            PositionEncoding::Utf16,
        ] {
            assert_eq!(
                index.offset_clamped(
                    TextPosition {
                        line: 0,
                        character: u32::MAX
                    },
                    encoding
                ),
                Some(6)
            );
            assert_eq!(
                index.offset_clamped(
                    TextPosition {
                        line: u32::MAX,
                        character: u32::MAX
                    },
                    encoding
                ),
                Some(9)
            );
        }
        assert_eq!(
            index.offset_clamped(
                TextPosition {
                    line: 0,
                    character: 1
                },
                PositionEncoding::Utf8
            ),
            None
        );
        assert_eq!(
            index.offset_clamped(
                TextPosition {
                    line: 0,
                    character: 2
                },
                PositionEncoding::Utf16
            ),
            None
        );
    }

    #[test]
    fn unicode_positions_round_trip_and_reject_split_characters() {
        let source = Source::new("unicode.srx", "aé😀z\r\nβ\rx\n").unwrap();
        let index = LineIndex::new(&source);
        assert_eq!(index.line_count(), 4);
        for encoding in [
            PositionEncoding::Utf8,
            PositionEncoding::Utf16,
        ] {
            for offset in 0..=u32::try_from(source.text().len()).unwrap() {
                if let Some(position) = index.position(offset, encoding) {
                    assert!(source.text().is_char_boundary(offset as usize));
                    assert_eq!(index.offset(position, encoding), Some(offset));
                } else {
                    assert!(!source.text().is_char_boundary(offset as usize) || offset == 9);
                }
            }
        }
        assert_eq!(
            index.position(7, PositionEncoding::Utf16),
            Some(TextPosition {
                line: 0,
                character: 4
            })
        );
        assert_eq!(
            index.offset(
                TextPosition {
                    line: 0,
                    character: 3
                },
                PositionEncoding::Utf16
            ),
            None
        );
        assert_eq!(
            index.offset(
                TextPosition {
                    line: 0,
                    character: 4
                },
                PositionEncoding::Utf8
            ),
            None
        );
        assert_eq!(
            index.offset(
                TextPosition {
                    line: 0,
                    character: u32::MAX
                },
                PositionEncoding::Utf16
            ),
            None
        );
        assert_eq!(
            index.offset(
                TextPosition {
                    line: 4,
                    character: 0
                },
                PositionEncoding::Utf8
            ),
            None
        );
    }

    #[test]
    fn empty_lines_and_line_endings_have_exact_boundaries() {
        for text in [
            "", "\n", "\r", "\r\n", "\r\n\n\r", "abc",
        ] {
            let source = Source::new("lines.srx", text).unwrap();
            let index = LineIndex::new(&source);
            let end = u32::try_from(text.len()).unwrap();
            assert!(
                index
                    .position(end, PositionEncoding::Utf16)
                    .is_some()
            );
            assert!(
                index
                    .position(end + 1, PositionEncoding::Utf16)
                    .is_none()
            );
            for encoding in [
                PositionEncoding::Utf8,
                PositionEncoding::Utf16,
            ] {
                for offset in 0..=end {
                    if let Some(position) = index.position(offset, encoding) {
                        assert_eq!(index.offset(position, encoding), Some(offset));
                    }
                }
            }
        }
    }
}
