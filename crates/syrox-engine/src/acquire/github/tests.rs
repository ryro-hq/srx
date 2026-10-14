use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::*;
use crate::{
    project::AuthenticatedStandardLibrary, project::CheckConfiguration,
    project::ProjectOperationError, project::check_project_lock_with,
    project::fetch_project_inputs_with, project::lock::LOCK_FILE_NAME, project::lock::LockStatus,
    project::lock_project_with, project::open_locked_project_with,
    project::open_project_analysis_with, project::plan_project_with, store::ContentDigest,
};

type Responses = VecDeque<(String, Vec<u8>)>;
thread_local! { static RESPONSES: RefCell<Option<Responses>> = const { RefCell::new(None) }; }

pub(super) fn fetch(url: &str, maximum: u64) -> Option<Result<Vec<u8>, GithubError>> {
    RESPONSES.with_borrow_mut(|responses| {
        let responses = responses.as_mut()?;
        let (expected, body) = responses
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected network request: {url}"));
        assert_eq!(url, expected);
        Some(if body.len() as u64 <= maximum {
            Ok(body)
        } else {
            Err(GithubError::Limit)
        })
    })
}

struct Network;
impl Network {
    fn new(responses: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        RESPONSES.with_borrow_mut(|slot| {
            assert!(slot.is_none());
            *slot = Some(responses.into_iter().collect());
        });
        Self
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        let remaining = RESPONSES.with_borrow_mut(Option::take).unwrap();
        if !std::thread::panicking() {
            assert!(
                remaining.is_empty(),
                "unused responses: {}",
                remaining.len()
            );
        }
    }
}

const FIRST: &str = "1111111111111111111111111111111111111111";
const SECOND: &str = "2222222222222222222222222222222222222222";

struct Fixture {
    directory: tempfile::TempDir,
    config: CheckConfiguration,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = CheckConfiguration {
            standard_library: Some(AuthenticatedStandardLibrary::bundled()),
            ..CheckConfiguration::default()
        };
        config.github.cache = Some(directory.path().join("cache"));
        Self {
            directory,
            config,
        }
    }
    fn path(&self, path: &str) -> PathBuf {
        self.directory.path().join(path)
    }
    fn write(&self, path: &str, contents: impl AsRef<[u8]>) {
        let path = self.path(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    fn catalog(&self, value: &str) {
        self.write(
            "catalog/main.srx",
            r#"inputs { recipes = "modules:recipes"; } pub publish(recipes, recipe): std::Recipe;"#,
        );
        self.write("catalog/assets/source", value);
        self.write("catalog/recipes/hello.srx", format!(r#"pub fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "hello"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::SourceRequest {{ url = "project:assets/source"; sha256 = "{}"; maximum_bytes = 100; }}]; }});
        }} }}"#, ContentDigest::sha256(value.as_bytes())));
        lock_project_with(&self.path("catalog"), &self.config).unwrap();
    }
    fn responses(&self, repository: &str, commit: &str, directory: &str) -> Vec<(String, Vec<u8>)> {
        let locator = GithubLocator::parse(&format!("github:example/{repository}")).unwrap();
        let pin = GithubPin::new(commit, [0; 32]).unwrap();
        vec![
            (locator.commit_url(), commit.as_bytes().to_vec()),
            (
                locator.archive_url(&pin),
                archive(&self.path(directory), repository, commit),
            ),
        ]
    }
}

pub(super) fn member(path: &str, data: &[u8], kind: u8) -> Vec<u8> {
    assert!(path.len() <= 100);
    let mut block = [0_u8; 512];
    block[..path.len()].copy_from_slice(path.as_bytes());
    block[100..108].copy_from_slice(b"0000644\0");
    block[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    block[156] = kind;
    block[148..156].fill(b' ');
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    block[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut result = block.to_vec();
    result.extend_from_slice(data);
    result.resize(result.len().div_ceil(512) * 512, 0);
    result
}

pub(super) fn compressed(mut tar: Vec<u8>) -> Vec<u8> {
    tar.extend_from_slice(&[0; 1024]);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&tar).unwrap();
    gzip.finish().unwrap()
}

fn archive(path: &Path, repository: &str, commit: &str) -> Vec<u8> {
    fn walk(root: &Path, path: &Path, prefix: &str, tar: &mut Vec<u8>) {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            if entry.file_name() == ".syrox" {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_path_buf();
            let name = format!("{prefix}/{}", relative.display());
            if entry.file_type().unwrap().is_dir() {
                tar.extend(member(&format!("{name}/"), b"", b'5'));
                walk(root, &entry.path(), prefix, tar);
            } else {
                tar.extend(member(
                    &name,
                    &fs::read(entry.path()).unwrap(),
                    b'0',
                ));
            }
        }
    }
    let prefix = format!("{repository}-{commit}");
    let mut tar = member(
        "pax_global_header",
        format!("52 comment={commit}\n").as_bytes(),
        b'g',
    );
    tar.extend(member(&format!("{prefix}/"), b"", b'5'));
    walk(path, path, &prefix, &mut tar);
    compressed(tar)
}

#[test]
fn github_relock_pins_catalog_offline_assets_and_read_only_navigation() {
    let fixture = Fixture::new();
    fixture.catalog("original");
    let source = r#"inputs { pkgs = "github:example/catalog"; alias = "github:example/catalog"; }
        pub use alias::hello;"#;
    fixture.write("consumer/main.srx", source);
    fixture.write("consumer/assets/source", "wrong owner");
    let consumer = fixture.path("consumer");
    let responses = fixture.responses("catalog", FIRST, "catalog");
    let archive_digest = ContentDigest::sha256(&responses[1].1).to_string();
    let _network = Network::new(responses);
    assert_eq!(
        lock_project_with(&consumer, &fixture.config)
            .unwrap()
            .status(),
        LockStatus::Created
    );
    let lock = fs::read_to_string(consumer.join(LOCK_FILE_NAME)).unwrap();
    assert!(lock.starts_with("syrox-lock-v4\n"));
    assert!(lock.contains(FIRST));
    assert!(lock.contains(&archive_digest));
    check_project_lock_with(&consumer, &fixture.config).unwrap();
    let locked = open_locked_project_with(&consumer, &fixture.config).unwrap();
    let sources = locked.loaded().sources();
    assert_eq!(
        sources.child_project_domain(
            syrox_lang::source::SourceDomainId::project(),
            "pkgs"
        ),
        sources.child_project_domain(
            syrox_lang::source::SourceDomainId::project(),
            "alias"
        )
    );
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("hello").unwrap());
    let prepared = evaluation.into_selected_prepared_plan().unwrap();
    drop(locked);
    let plan = prepared.plan().clone();
    let request = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    let root = prepared
        .project_root(request.owner().unwrap())
        .unwrap()
        .to_path_buf();
    assert_eq!(
        fs::read(root.join("assets/source")).unwrap(),
        b"original"
    );
    let assets = crate::acquire::local::AuthorizedLocalDirectory::open(&root).unwrap();
    let store_dir = fixture.path("outputs");
    fs::create_dir(&store_dir).unwrap();
    let store = crate::store::Store::open(&store_dir).unwrap();
    let url = url::Url::from_file_path(root.join("assets/source")).unwrap();
    crate::acquire::local::acquire_local(
        &store,
        &assets,
        &crate::acquire::local::LocalSourceRequest::new(url.as_str(), request.digest(), 100)
            .unwrap(),
        &crate::store::RootName::new("remote-asset").unwrap(),
    )
    .unwrap();
    let mut editor = open_project_analysis_with(&consumer, &fixture.config).unwrap();
    let snapshot = editor.snapshot();
    let cancellation = syrox_lang::analysis::AnalysisCancellation::default();
    let semantic = snapshot.analyze(&cancellation).unwrap();
    assert!(semantic.diagnostics().is_empty());
    let main = *snapshot
        .source_paths()
        .iter()
        .find(|(_, path)| path.ends_with("consumer/main.srx"))
        .unwrap()
        .0;
    let definition = semantic
        .definition_at(
            main,
            u32::try_from(source.find("alias::hello").unwrap() + 7).unwrap(),
        )
        .unwrap();
    assert!(
        !snapshot
            .source_paths()
            .contains_key(&definition.source_id())
    );
    assert!(matches!(
        editor.set_overlay(definition.source_id(), 1, "bad"),
        Err(crate::project::ProjectAnalysisError::ReadOnlySource)
    ));
    assert_eq!(
        fs::read_to_string(consumer.join(LOCK_FILE_NAME)).unwrap(),
        lock
    );
    // Compare equally selected descriptions across independently extracted paths.
    let locked = open_locked_project_with(&consumer, &fixture.config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    evaluation.select_package("hello").unwrap();
    let other = evaluation.into_selected_prepared_plan().unwrap();
    assert_eq!(&plan, other.plan());
    assert_ne!(
        prepared.project_root(request.owner().unwrap()),
        other.project_root(request.owner().unwrap())
    );
    drop((other, locked));
    let held = prepared.clone();
    drop(prepared);
    assert!(
        root.exists(),
        "clones share source resource ownership"
    );
    drop(held);
    assert!(
        !root.exists(),
        "only the live preparation retains its snapshot, not the plain Plan"
    );
    assert!(!plan.to_string().contains(root.to_str().unwrap()));
}

#[test]
fn only_relock_advances_refs_and_fetch_recovers_exact_locked_bytes() {
    let fixture = Fixture::new();
    fixture.catalog("first");
    fixture.write(
        "consumer/main.srx",
        r#"inputs { pkgs = "github:example/catalog"; } pub use pkgs::hello;"#,
    );
    let consumer = fixture.path("consumer");
    let responses = fixture.responses("catalog", FIRST, "catalog");
    {
        let _network = Network::new(responses.clone());
        lock_project_with(&consumer, &fixture.config).unwrap();
    }
    let original = fs::read(consumer.join(LOCK_FILE_NAME)).unwrap();
    let original_plan = {
        let _network = Network::new([]);
        plan_project_with(&consumer, &fixture.config)
            .unwrap()
            .to_string()
    };
    let mut fresh = fixture.config.clone();
    fresh.github.cache = Some(fixture.path("fresh"));
    {
        let _network = Network::new([]);
        assert!(check_project_lock_with(&consumer, &fresh).is_err());
    }
    {
        let _network = Network::new([responses[1].clone()]);
        fetch_project_inputs_with(&consumer, &fresh).unwrap();
    }
    assert_eq!(
        fs::read(consumer.join(LOCK_FILE_NAME)).unwrap(),
        original
    );
    {
        let _network = Network::new([]);
        assert_eq!(
            plan_project_with(&consumer, &fresh)
                .unwrap()
                .to_string(),
            original_plan
        );
    }
    fixture.catalog("second");
    let _network = Network::new(fixture.responses("catalog", SECOND, "catalog"));
    assert_eq!(
        lock_project_with(&consumer, &fixture.config)
            .unwrap()
            .status(),
        LockStatus::Updated
    );
    assert_ne!(
        fs::read(consumer.join(LOCK_FILE_NAME)).unwrap(),
        original
    );
    assert_ne!(
        plan_project_with(&consumer, &fixture.config)
            .unwrap()
            .to_string(),
        original_plan
    );
}

#[test]
fn remote_transitive_projects_use_child_pins_and_their_own_assets() {
    let fixture = Fixture::new();
    fixture.catalog("transitive");
    fixture.write(
        "facade/main.srx",
        r#"inputs { child = "github:example/catalog"; } pub use child::hello;"#,
    );
    let catalog = fixture.responses("catalog", FIRST, "catalog");
    {
        let _network = Network::new(catalog.clone());
        lock_project_with(&fixture.path("facade"), &fixture.config).unwrap();
    }
    fixture.write(
        "consumer/main.srx",
        r#"inputs { facade = "github:example/facade"; } pub use facade::hello;"#,
    );
    let mut config = fixture.config.clone();
    config.github.cache = Some(fixture.path("transitive-cache"));
    let mut responses = fixture.responses("facade", SECOND, "facade");
    responses.push(catalog[1].clone()); // A transitive mutable ref must never be resolved.
    let _network = Network::new(responses);
    lock_project_with(&fixture.path("consumer"), &config).unwrap();
    let prepared =
        crate::project::prepare_project_with(&fixture.path("consumer"), &config).unwrap();
    let plan = prepared.plan();
    let request = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        fs::read(
            prepared
                .project_root(request.owner().unwrap())
                .unwrap()
                .join("assets/source")
        )
        .unwrap(),
        b"transitive"
    );
    check_project_lock_with(&fixture.path("consumer"), &config).unwrap();
}

#[test]
fn malformed_locators_missing_pins_drift_and_cancellation_do_not_publish() {
    for locator in [
        "github:",
        "github:owner",
        "github:owner/repo/",
        "github:../repo",
        "github:o/r/../bad",
        "github:o/r/ref?dir=x",
        "github:o/r/a b",
        "github:o/r/a%2fb",
        "github:o/r/a\\b",
    ] {
        assert!(
            GithubLocator::parse(locator).is_err(),
            "{locator}"
        );
    }
    assert!(
        GithubLocator::parse("github:owner/repo/heads/topic")
            .unwrap()
            .commit_url()
            .ends_with("heads%2Ftopic")
    );
    let fixture = Fixture::new();
    fixture.catalog("old");
    fixture.write(
        "consumer/main.srx",
        r#"inputs { pkgs = "github:example/catalog"; }"#,
    );
    let _network = Network::new([]);
    assert!(matches!(
        check_project_lock_with(&fixture.path("consumer"), &fixture.config),
        Err(ProjectOperationError::Check(
            crate::project::CheckFailure::Github(GithubError::Unpinned(_))
        ))
    ));
    let config = fixture.config.clone();
    config.github.cancellation.cancel();
    assert!(lock_project_with(&fixture.path("consumer"), &config).is_err());
    assert!(!fixture.path("consumer/Syrox.lock").exists());
}

#[test]
fn stale_child_lock_and_snapshot_path_escape_are_rejected() {
    for escape in [false, true] {
        let fixture = Fixture::new();
        fixture.catalog("old");
        fixture.write(
            "catalog/main.srx",
            if escape {
                r#"inputs { escape = "path:../host"; }"#
            } else {
                "pub struct Changed {}"
            },
        );
        fixture.write(
            "consumer/main.srx",
            r#"inputs { pkgs = "github:example/catalog"; }"#,
        );
        let _network = Network::new(fixture.responses("catalog", FIRST, "catalog"));
        assert!(lock_project_with(&fixture.path("consumer"), &fixture.config).is_err());
        assert!(!fixture.path("consumer/Syrox.lock").exists());
    }
}

#[test]
fn corrupt_cache_and_changed_download_fail_without_lock_republication() {
    let fixture = Fixture::new();
    fixture.catalog("authenticated");
    fixture.write(
        "consumer/main.srx",
        r#"inputs { pkgs = "github:example/catalog"; }"#,
    );
    let consumer = fixture.path("consumer");
    let responses = fixture.responses("catalog", FIRST, "catalog");
    {
        let _network = Network::new(responses.clone());
        lock_project_with(&consumer, &fixture.config).unwrap();
    }
    let original = fs::read(consumer.join(LOCK_FILE_NAME)).unwrap();
    let mut fresh = fixture.config.clone();
    fresh.github.cache = Some(fixture.path("bad-download"));
    {
        let _network = Network::new([(
            responses[1].0.clone(),
            b"different bytes".to_vec(),
        )]);
        assert!(matches!(
            fetch_project_inputs_with(&consumer, &fresh),
            Err(ProjectOperationError::Check(
                crate::project::CheckFailure::Github(GithubError::ContentMismatch)
            ))
        ));
    }
    let digest = ContentDigest::sha256(&responses[1].1).to_string();
    let object = fixture.path(&format!(
        "cache/objects/sha256/{}/{digest}",
        &digest[..2]
    ));
    assert!(object.is_file());
    fs::write(object, b"corrupt").unwrap();
    let _network = Network::new([]);
    assert!(check_project_lock_with(&consumer, &fixture.config).is_err());
    assert!(fetch_project_inputs_with(&consumer, &fixture.config).is_err());
    assert_eq!(
        fs::read(consumer.join(LOCK_FILE_NAME)).unwrap(),
        original
    );
}

#[test]
fn different_refs_at_one_commit_share_one_snapshot_and_domain() {
    let fixture = Fixture::new();
    fixture.catalog("one");
    fixture.write(
        "consumer/main.srx",
        r#"inputs { a = "github:example/catalog"; b = "github:example/catalog/topic"; }"#,
    );
    let mut responses = fixture.responses("catalog", FIRST, "catalog");
    responses.push((
        GithubLocator::parse("github:example/catalog/topic")
            .unwrap()
            .commit_url(),
        FIRST.as_bytes().to_vec(),
    ));
    let _network = Network::new(responses);
    lock_project_with(&fixture.path("consumer"), &fixture.config).unwrap();
    let loaded = open_locked_project_with(&fixture.path("consumer"), &fixture.config).unwrap();
    let sources = loaded.loaded().sources();
    assert_eq!(
        sources.child_project_domain(syrox_lang::source::SourceDomainId::project(), "a"),
        sources.child_project_domain(syrox_lang::source::SourceDomainId::project(), "b")
    );
}

#[test]
#[ignore = "opt-in live GitHub API/codeload HTTPS transport proof"]
fn github_live_resolves_commit_verifies_archive_and_reopens_offline() {
    let directory = tempfile::tempdir().unwrap();
    let config = GithubConfiguration::default();
    let locator = GithubLocator::parse("github:ryro-hq/syrox-pkgs").unwrap();
    let mut online = GithubSession::new(directory.path(), &config, InputMode::Refresh);
    let snapshot = online.load(&locator, None).unwrap();
    assert!(snapshot.path().join("main.srx").is_file());
    eprintln!(
        "verified {} at {} archive {}",
        locator.origin,
        snapshot.pin.commit,
        ContentDigest::from_sha256_hash(snapshot.pin.archive)
    );
    let mut offline = GithubSession::new(directory.path(), &config, InputMode::Offline);
    let pinned = offline
        .load(&locator, Some(&snapshot.pin))
        .unwrap();
    assert_eq!(
        fs::read(snapshot.path().join("main.srx")).unwrap(),
        fs::read(pinned.path().join("main.srx")).unwrap()
    );
}

#[test]
fn prepared_consumer_retains_remote_assets_until_its_last_clone_is_dropped() {
    let fixture = Fixture::new();
    fixture.catalog("consumer snapshot");
    let recipe_path = fixture.path("catalog/recipes/hello.srx");
    let recipe = fs::read_to_string(&recipe_path).unwrap().replace("package = std::Package", r#"build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });package = std::Package"#);
    fs::write(recipe_path, recipe).unwrap();
    lock_project_with(&fixture.path("catalog"), &fixture.config).unwrap();
    fixture.write(
        "consumer/main.srx",
        r#"
        inputs { catalog = "github:example/catalog"; }
        outputs { shell: std::Shell = std::Shell {
            pkgs = [std::select_package(catalog::hello)]; services = [];
        }; }
    "#,
    );
    let consumer = fixture.path("consumer");
    let _network = Network::new(fixture.responses("catalog", FIRST, "catalog"));
    lock_project_with(&consumer, &fixture.config).unwrap();
    let prepared =
        crate::project::prepare_project_consumer_with(&consumer, &fixture.config, "shell").unwrap();
    let request = prepared
        .plan()
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    let root = prepared
        .project_root(request.owner().unwrap())
        .unwrap()
        .to_path_buf();
    assert_eq!(
        fs::read(root.join("assets/source")).unwrap(),
        b"consumer snapshot"
    );
    let clone = prepared.clone();
    let pure_plan = prepared.into_plan();
    assert!(
        root.exists(),
        "remaining clone owns the selected snapshot"
    );
    assert_eq!(clone.plan(), &pure_plan);
    drop(clone);
    assert!(
        !root.exists(),
        "plain Plan does not retain extracted snapshots"
    );
    assert!(
        !pure_plan
            .to_string()
            .contains(root.to_str().unwrap())
    );
}
