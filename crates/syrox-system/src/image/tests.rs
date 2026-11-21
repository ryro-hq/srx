use super::*;
use crate::budget::{BuildBudget, BuilderLimits};

pub(super) fn budget(files: u64, output_bytes: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 1024 * 1024,
        cpu_percent: 100,
        processes: 1,
        descriptors: 16,
        scratch_bytes: 1,
        files,
        output_bytes,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

fn metadata() -> FileMetadata {
    FileMetadata {
        uid: 0,
        gid: 0,
        mode: 0o755,
    }
}
pub(super) fn dir(path: &str) -> ComponentEntry {
    ComponentEntry {
        path: path.into(),
        entry: Entry::Directory {
            metadata: metadata(),
        },
    }
}
pub(super) fn link(path: &str, target: &str) -> ComponentEntry {
    ComponentEntry {
        path: path.into(),
        entry: Entry::Symlink {
            uid: 0,
            gid: 0,
            target: target.into(),
        },
    }
}
pub(super) fn file(path: &str, component: &str, bytes: &[u8]) -> ComponentEntry {
    ComponentEntry {
        path: path.into(),
        entry: Entry::File {
            metadata: metadata(),
            source: FileSource {
                component: component.into(),
                path: "out/bin/tool".into(),
                content_sha256: syrox_encoding::hex(&Sha256::digest(bytes)),
                size_bytes: bytes.len() as u64,
            },
        },
    }
}
pub(super) fn component(digit: char, entries: Vec<ComponentEntry>) -> ComponentManifest {
    ComponentManifest {
        identity_sha256: digit.to_string().repeat(64),
        entries,
    }
}
fn compose(components: &[ComponentManifest]) -> Result<SystemTree, ImageError> {
    SystemTree::compose(components, &budget(100, 1024 * 1024))
}

#[test]
fn merging_tracks_producers_and_is_independent_of_input_order_and_policy_ceiling() {
    let first = component(
        'a',
        vec![
            dir("/"),
            dir("/bin"),
            file("/bin/tool", &"a".repeat(64), b"tool"),
        ],
    );
    let second = component(
        'b',
        vec![
            dir("/"),
            dir("/bin"),
            link("/bin/alias", "tool"),
        ],
    );
    let forward = compose(&[first.clone(), second.clone()]).unwrap();
    let backward = compose(&[second, first]).unwrap();
    assert_eq!(forward, backward);
    assert_eq!(forward.version(), 1);
    assert_eq!(forward.content_bytes(), 4);
    assert_eq!(forward.entries()["/bin"].origins.len(), 2);
    assert_eq!(forward.fingerprint(), backward.fingerprint());
    let only = component('a', vec![dir("/")]);
    let small = SystemTree::compose(std::slice::from_ref(&only), &budget(1, 1)).unwrap();
    let large = SystemTree::compose(&[only], &budget(100, 100)).unwrap();
    assert_eq!(small.fingerprint(), large.fingerprint());
}

#[test]
fn every_file_has_one_producer_and_shared_directories_require_equal_metadata() {
    let first = component(
        'a',
        vec![
            dir("/"),
            file("/tool", &"a".repeat(64), b"same"),
        ],
    );
    let second = component(
        'b',
        vec![
            dir("/"),
            file("/tool", &"b".repeat(64), b"same"),
        ],
    );
    assert!(
        matches!(compose(&[first.clone(), second]), Err(ImageError::Collision { path, .. }) if path == "/tool")
    );
    let mut changed = dir("/");
    if let Entry::Directory {
        metadata,
    } = &mut changed.entry
    {
        metadata.uid = 1000;
    }
    assert!(matches!(
        compose(&[first, component('b', vec![changed])]),
        Err(ImageError::Collision { .. })
    ));
    assert!(matches!(
        compose(&[component('a', vec![dir("/"), dir("/")])]),
        Err(ImageError::Collision { .. })
    ));
}

#[test]
fn paths_require_explicit_directory_parents_without_host_lookup() {
    assert!(matches!(
        compose(&[component('a', vec![dir("/a")])]),
        Err(ImageError::Parent { .. })
    ));
    for parent in [
        link("/a", "/runtime"),
        file("/a", &"a".repeat(64), b"file"),
    ] {
        assert!(matches!(
            compose(&[component(
                'a',
                vec![dir("/"), parent, dir("/a/b")]
            )]),
            Err(ImageError::Parent { .. })
        ));
    }
    for bad in [
        "relative", "/a/", "/a//b", "/a/../b", "/a/./b", "/a\0b", "/a\nb",
    ] {
        assert!(matches!(
            compose(&[component('a', vec![dir("/"), dir(bad)])]),
            Err(ImageError::Path(_))
        ));
    }
    compose(&[component(
        'a',
        vec![
            dir("/"),
            link("/runtime", "/run/missing"),
            dir("/unicode space"),
        ],
    )])
    .unwrap();
}

#[test]
fn metadata_and_authenticated_sources_are_validated() {
    for invalid in [
        FileMetadata {
            uid: u32::MAX,
            ..metadata()
        },
        FileMetadata {
            gid: u32::MAX,
            ..metadata()
        },
        FileMetadata {
            mode: 0o100_755,
            ..metadata()
        },
    ] {
        assert!(matches!(
            compose(&[component(
                'a',
                vec![ComponentEntry {
                    path: "/".into(),
                    entry: Entry::Directory {
                        metadata: invalid
                    }
                }]
            )]),
            Err(ImageError::Metadata(_))
        ));
    }
    let mut source = file("/tool", &"b".repeat(64), b"bytes");
    assert_eq!(
        compose(&[component(
            'a',
            vec![dir("/"), source.clone()]
        )]),
        Err(ImageError::Identity)
    );
    if let Entry::File {
        source,
        ..
    } = &mut source.entry
    {
        source.component = "a".repeat(64);
        source.path = "../host".into();
    }
    assert!(matches!(
        compose(&[component(
            'a',
            vec![dir("/"), source.clone()]
        )]),
        Err(ImageError::Path(_))
    ));
    if let Entry::File {
        source,
        ..
    } = &mut source.entry
    {
        source.path = "out".into();
        source.content_sha256 = "A".repeat(64);
    }
    assert_eq!(
        compose(&[component('a', vec![dir("/"), source])]),
        Err(ImageError::Identity)
    );
    assert_eq!(
        compose(&[component('g', vec![dir("/")])]),
        Err(ImageError::Identity)
    );
    assert_eq!(
        compose(&[
            component('a', vec![dir("/")]),
            component('a', vec![])
        ]),
        Err(ImageError::Identity)
    );
}

#[test]
fn output_and_entry_budgets_cannot_be_exceeded_or_overflowed() {
    let input = component(
        'a',
        vec![
            dir("/"),
            file("/tool", &"a".repeat(64), b"1234"),
        ],
    );
    assert_eq!(
        SystemTree::compose(std::slice::from_ref(&input), &budget(1, 4)),
        Err(ImageError::Budget("files"))
    );
    assert_eq!(
        SystemTree::compose(std::slice::from_ref(&input), &budget(2, 3)),
        Err(ImageError::Budget("output bytes"))
    );
    SystemTree::compose(&[input], &budget(2, 4)).unwrap();
    let mut huge = file("/huge", &"a".repeat(64), b"");
    if let Entry::File {
        source,
        ..
    } = &mut huge.entry
    {
        source.size_bytes = u64::MAX - 1;
    }
    assert_eq!(
        SystemTree::compose(
            &[component(
                'a',
                vec![
                    dir("/"),
                    huge,
                    file("/small", &"a".repeat(64), b"12")
                ]
            )],
            &budget(3, u64::MAX - 1)
        ),
        Err(ImageError::Budget("output bytes"))
    );
}

#[test]
fn symlinks_resolve_prefixes_before_parent_traversal_and_never_escape() {
    compose(&[component(
        'a',
        vec![
            dir("/"),
            dir("/usr"),
            dir("/usr/lib"),
            link("/lib", "usr/lib"),
            link("/usr/alias", "../lib"),
        ],
    )])
    .unwrap();
    for entries in [
        vec![link("/escape", "../outside")],
        vec![link("/a", "b"), link("/b", "a")],
        // Lexically removing alias/.. would incorrectly miss this cycle.
        vec![
            dir("/dir"),
            link("/alias", "/dir"),
            link("/loop", "alias/../loop"),
        ],
        vec![
            link("/alias", "/"),
            link("/escape", "alias/../outside"),
        ],
        vec![link("/empty", "")],
        vec![link("/nul", "a\0b")],
        vec![
            file("/file", &"a".repeat(64), b""),
            link("/invalid", "file/../elsewhere"),
        ],
    ] {
        let mut all = vec![dir("/")];
        all.extend(entries);
        assert!(matches!(
            compose(&[component('a', all)]),
            Err(ImageError::Symlink(_))
        ));
    }
    // Reusing an acyclic link while resolving a path is legal.
    compose(&[component(
        'a',
        vec![
            dir("/"),
            dir("/dir"),
            link("/alias", "/dir"),
            link("/twice", "alias/../alias"),
        ],
    )])
    .unwrap();
}

#[test]
fn ownership_modes_links_and_content_all_change_tree_identity() {
    let original = component(
        'a',
        vec![
            dir("/"),
            file("/tool", &"a".repeat(64), b"v1"),
            link("/alias", "tool"),
        ],
    );
    let pin = compose(std::slice::from_ref(&original))
        .unwrap()
        .fingerprint();
    let mut variants = Vec::new();
    for field in 0..3 {
        let mut changed = original.clone();
        if let Entry::File {
            metadata,
            ..
        } = &mut changed.entries[1].entry
        {
            match field {
                0 => metadata.uid = 1000,
                1 => metadata.gid = 1000,
                _ => metadata.mode = 0o700,
            }
        }
        variants.push(changed);
    }
    let mut content = original.clone();
    content.entries[1] = file("/tool", &"a".repeat(64), b"v2");
    variants.push(content);
    let mut target = original;
    target.entries[2] = link("/alias", "/tool");
    variants.push(target);
    for variant in variants {
        assert_ne!(compose(&[variant]).unwrap().fingerprint(), pin);
    }
}

#[test]
fn persisted_trees_are_canonical_and_all_invariants_are_revalidated() {
    let first = component(
        'a',
        vec![
            dir("/"),
            file("/tool", &"a".repeat(64), b"123"),
        ],
    );
    let second = component('b', vec![dir("/"), link("/alias", "tool")]);
    let tree = compose(&[first, second]).unwrap();
    let bytes = tree.canonical_bytes();
    assert_eq!(
        SystemTree::parse(&bytes, &budget(10, 1024)).unwrap(),
        tree
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&bytes)),
        tree.fingerprint()
    );
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    assert_eq!(
        SystemTree::parse(&trailing, &budget(10, 1024)),
        Err(ImageError::Manifest)
    );
    assert_eq!(
        SystemTree::parse(b"syrox-system-tree-v2\n{}", &budget(10, 1024)),
        Err(ImageError::Manifest)
    );
    assert!(matches!(
        SystemTree::parse(&bytes, &budget(1, 1024)),
        Err(ImageError::Budget("files"))
    ));
    let fields: serde_json::Value = serde_json::from_slice(
        bytes
            .strip_prefix(b"syrox-system-tree-v1\n")
            .unwrap(),
    )
    .unwrap();
    for bad in [
        "version",
        "content_bytes",
        "ownership",
        "source",
        "symlink",
        "origins",
    ] {
        let mut modified = fields.clone();
        match bad {
            "version" => modified["version"] = 2.into(),
            "content_bytes" => modified["content_bytes"] = 100.into(),
            "ownership" => {
                modified["entries"]["/tool"]["entry"]["metadata"]["uid"] = u32::MAX.into();
            }
            "source" => {
                modified["entries"]["/tool"]["entry"]["source"]["component"] =
                    "b".repeat(64).into();
            }
            "symlink" => modified["entries"]["/alias"]["entry"]["target"] = "../outside".into(),
            _ => {
                modified["entries"]["/tool"]["origins"] =
                    serde_json::json!(["a".repeat(64), "b".repeat(64)]);
            }
        }
        let mut encoded = b"syrox-system-tree-v1\n".to_vec();
        serde_json::to_writer(&mut encoded, &modified).unwrap();
        assert!(
            SystemTree::parse(&encoded, &budget(10, 1024)).is_err(),
            "{bad}"
        );
    }
}
