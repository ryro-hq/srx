use super::*;
use crate::image::tests::{budget, component, dir, file, link};
use std::collections::BTreeMap;
use std::io::Cursor;

#[derive(Default)]
struct Sources {
    files: BTreeMap<String, Vec<u8>>,
    opens: usize,
}
impl ComponentReader for Sources {
    fn open_file(&mut self, source: &FileSource) -> io::Result<Box<dyn Read + '_>> {
        self.opens += 1;
        Ok(Box::new(Cursor::new(
            self.files
                .get(&source.path)
                .ok_or(io::ErrorKind::NotFound)?
                .as_slice(),
        )))
    }
}

#[derive(Debug)]
struct Record {
    name: String,
    fields: [u32; 13],
    bytes: Vec<u8>,
}

// Independent reader of the upstream wire fields, including all padding.
fn records(archive: &[u8]) -> Vec<Record> {
    let mut cursor = 0;
    let mut result = Vec::new();
    loop {
        assert_eq!(&archive[cursor..cursor + 6], b"070701");
        let mut fields = [0; 13];
        for (index, field) in fields.iter_mut().enumerate() {
            let offset = cursor + 6 + index * 8;
            *field = u32::from_str_radix(
                std::str::from_utf8(&archive[offset..offset + 8]).unwrap(),
                16,
            )
            .unwrap();
        }
        cursor += 110;
        let name_end = cursor + fields[11] as usize;
        assert_eq!(archive[name_end - 1], 0);
        let name = std::str::from_utf8(&archive[cursor..name_end - 1])
            .unwrap()
            .to_owned();
        cursor = name_end.next_multiple_of(4);
        assert!(
            archive[name_end..cursor]
                .iter()
                .all(|byte| *byte == 0)
        );
        let data_end = cursor + fields[6] as usize;
        let bytes = archive[cursor..data_end].to_vec();
        cursor = data_end.next_multiple_of(4);
        assert!(
            archive[data_end..cursor]
                .iter()
                .all(|byte| *byte == 0)
        );
        if name == "TRAILER!!!" {
            assert_eq!(fields[6], 0);
            assert!(archive[cursor..].iter().all(|byte| *byte == 0));
            assert_eq!(archive.len() % 512, 0);
            break;
        }
        result.push(Record {
            name,
            fields,
            bytes,
        });
    }
    result
}

fn fixture() -> (SystemTree, Sources) {
    let mut executable = file(
        "/init",
        &"a".repeat(64),
        b"#!/bin/sh\nexec /bin/tool\n",
    );
    if let Entry::File {
        metadata,
        ..
    } = &mut executable.entry
    {
        metadata.uid = 42;
        metadata.gid = 43;
        metadata.mode = 0o4750;
    }
    let tree = SystemTree::compose(
        &[component(
            'a',
            vec![
                dir("/"),
                executable,
                link("/tool", "init"),
                dir("/empty"),
                dir("/TRAILER!!!"),
            ],
        )],
        &budget(10, 8192),
    )
    .unwrap();
    let sources = Sources {
        files: BTreeMap::from([(
            "out/bin/tool".into(),
            b"#!/bin/sh\nexec /bin/tool\n".to_vec(),
        )]),
        opens: 0,
    };
    (tree, sources)
}

#[test]
fn archive_preserves_explicit_metadata_empty_directories_and_links_and_escapes_trailer_filename() {
    let (tree, mut sources) = fixture();
    let mut bytes = Vec::new();
    let written = tree
        .write_initramfs(
            &mut sources,
            &mut bytes,
            &budget(10, 8192),
            || false,
        )
        .unwrap();
    assert_eq!(written.bytes, bytes.len() as u64);
    assert_eq!(
        written.sha256,
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(written.tree_sha256, tree.fingerprint());
    assert_eq!(sources.opens, 1);
    let entries = records(&bytes);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        [
            ".",
            "./TRAILER!!!",
            "empty",
            "init",
            "tool"
        ]
    );
    assert_eq!(entries[0].fields[1], 0o040_755);
    assert_eq!(entries[3].fields[1], 0o104_750);
    assert_eq!(&entries[3].fields[2..6], &[42, 43, 1, 0]);
    assert_eq!(entries[3].bytes, b"#!/bin/sh\nexec /bin/tool\n");
    assert_eq!(entries[4].fields[1], 0o120_777);
    assert_eq!(entries[4].bytes, b"init");
    for entry in &entries {
        assert_eq!(&entry.fields[7..11], &[0, 0, 0, 0]);
        assert_eq!(entry.fields[12], 0);
    }
    let mut again = Vec::new();
    let repeated = tree
        .write_initramfs(
            &mut sources,
            &mut again,
            &budget(20, 16384),
            || false,
        )
        .unwrap();
    assert_eq!(written, repeated);
    assert_eq!(bytes, again);
}

#[test]
fn budgets_and_newc_file_size_fail_before_source_open_or_output() {
    let (tree, mut sources) = fixture();
    for admitted in [budget(4, 8192), budget(10, 100)] {
        let mut output = Vec::new();
        assert!(matches!(
            tree.write_initramfs(&mut sources, &mut output, &admitted, || false),
            Err(ArchiveError::Budget(_))
        ));
        assert!(output.is_empty());
        assert_eq!(sources.opens, 0);
    }
    let mut huge = file("/huge", &"a".repeat(64), b"");
    if let Entry::File {
        source,
        ..
    } = &mut huge.entry
    {
        source.size_bytes = u64::from(u32::MAX) + 1;
    }
    let admitted = budget(10, 8 * 1024 * 1024 * 1024);
    let tree = SystemTree::compose(&[component('a', vec![dir("/"), huge])], &admitted).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        tree.write_initramfs(&mut sources, &mut output, &admitted, || false),
        Err(ArchiveError::Format(_))
    ));
    assert!(output.is_empty());
    assert_eq!(sources.opens, 0);
}

#[test]
fn changed_truncated_extended_and_missing_component_files_never_return_a_complete_archive() {
    let (tree, _) = fixture();
    for bytes in [
        b"bad".to_vec(),
        b"#!/bin/sh\nexec /bin/tool\nextra".to_vec(),
        b"#!/bin/xx\nexec /bin/tool\n".to_vec(),
    ] {
        let mut sources = Sources {
            files: BTreeMap::from([("out/bin/tool".into(), bytes)]),
            opens: 0,
        };
        let mut output = Vec::new();
        assert!(matches!(
            tree.write_initramfs(
                &mut sources,
                &mut output,
                &budget(10, 8192),
                || false
            ),
            Err(ArchiveError::Content(_))
        ));
        assert!(!output.is_empty());
    }
    assert!(matches!(
        tree.write_initramfs(
            &mut Sources::default(),
            &mut Vec::new(),
            &budget(10, 8192),
            || false
        ),
        Err(ArchiveError::Io(_))
    ));
}

#[test]
fn cooperative_cancellation_and_destination_failures_propagate() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::StorageFull.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (tree, mut sources) = fixture();
    let mut output = Vec::new();
    assert!(matches!(
        tree.write_initramfs(
            &mut sources,
            &mut output,
            &budget(10, 8192),
            || true
        ),
        Err(ArchiveError::Cancelled)
    ));
    assert!(output.is_empty());
    let mut calls = 0;
    assert!(matches!(
        tree.write_initramfs(
            &mut sources,
            &mut output,
            &budget(10, 8192),
            || {
                calls += 1;
                calls > 11
            }
        ),
        Err(ArchiveError::Cancelled)
    ));
    assert!(
        matches!(tree.write_initramfs(&mut sources, &mut Broken, &budget(10, 8192), || false), Err(ArchiveError::Io(error)) if error.kind() == io::ErrorKind::StorageFull)
    );
}

#[test]
fn payload_streaming_is_bounded_and_recovers_from_interrupted_reads() {
    use std::cell::Cell;
    use std::rc::Rc;
    const LENGTH: usize = 8 * 1024 * 1024 + 17;
    struct Generated {
        remaining: usize,
        interrupted: bool,
        largest: Rc<Cell<usize>>,
    }
    impl Read for Generated {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.largest
                .set(self.largest.get().max(buffer.len()));
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let read = buffer.len().min(self.remaining).min(7919);
            buffer[..read].fill(0x5a);
            self.remaining -= read;
            Ok(read)
        }
    }
    struct GeneratedSource(Rc<Cell<usize>>);
    impl ComponentReader for GeneratedSource {
        fn open_file(&mut self, _: &FileSource) -> io::Result<Box<dyn Read + '_>> {
            Ok(Box::new(Generated {
                remaining: LENGTH,
                interrupted: false,
                largest: self.0.clone(),
            }))
        }
    }
    let mut hash = Sha256::new();
    for _ in 0..(LENGTH / 1024) {
        hash.update([0x5a; 1024]);
    }
    hash.update(vec![0x5a; LENGTH % 1024]);
    let mut entry = file("/payload", &"a".repeat(64), b"");
    if let Entry::File {
        source,
        ..
    } = &mut entry.entry
    {
        source.size_bytes = LENGTH as u64;
        source.content_sha256 = format!("{:x}", hash.finalize());
    }
    let admitted = budget(2, LENGTH as u64 + 4096);
    let tree = SystemTree::compose(
        &[component('a', vec![dir("/"), entry])],
        &admitted,
    )
    .unwrap();
    let largest = Rc::new(Cell::new(0));
    let written = tree
        .write_initramfs(
            &mut GeneratedSource(largest.clone()),
            &mut io::sink(),
            &admitted,
            || false,
        )
        .unwrap();
    assert!(written.bytes > LENGTH as u64);
    assert_eq!(largest.get(), 64 * 1024);
}
