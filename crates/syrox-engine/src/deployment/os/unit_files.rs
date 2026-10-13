//! Publicação dos unit files pertencentes a uma instalação.
//!
//! O lock permanente da instalação serializa os escritores que seguem esse
//! protocolo. Outros processos do mesmo usuário não devem mudar esses arquivos
//! enquanto a operação trabalha neles. Publicar o arquivo não autoriza start.

use crate::platform::linux::fd::{self as linux_fd, FileIdentity, FlockMode, OpenedPath};
use crate::{cancellation::Cancellation, store::ContentDigest, systemd::SystemdUnitName};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read as _};
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_UNIT: usize = 64 * 1024;
const MAX_LEDGER: usize = 128 * 1024;
const MAX_UNITS: usize = 256;
const HEADER: &[u8] = b"syrox-unit-ownership-v1\n";
const MARKER: &[u8] = b"# syrox-os-unit-v1\n";

#[derive(Debug, thiserror::Error)]
pub(crate) enum UnitFilesError {
    #[error("invalid unit publication: {0}")]
    Invalid(&'static str),
    #[error("unit publication cancelled")]
    Cancelled,
    #[error("unit publication deadline expired")]
    Deadline,
    #[error("unit publication is uncertain; reopen and reconcile retained evidence")]
    Uncertain,
    #[error(transparent)]
    Io(#[from] io::Error),
}
type Result<T> = std::result::Result<T, UnitFilesError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Intent {
    unit: String,
    #[serde(with = "optional_digest")]
    previous: Option<ContentDigest>,
    #[serde(with = "digest")]
    target: ContentDigest,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    installation: String,
    #[serde(with = "digest_map")]
    units: BTreeMap<String, ContentDigest>,
    pending: Option<Intent>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnitReconciliation {
    NoPending,
    Published {
        unit: String,
        pin: ContentDigest,
    },
    NotPublished {
        unit: String,
        previous: Option<ContentDigest>,
    },
}
#[derive(Debug)]
pub(crate) struct UnitFiles {
    path: PathBuf,
    installation: String,
    root: OpenedPath,
    authority: OpenedPath,
    lock_identity: FileIdentity,
    poisoned: AtomicBool,
}
struct Guard(OpenedPath);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = linux_fd::flock(self.0.fd(), FlockMode::Unlock);
    }
}
impl UnitFiles {
    pub(crate) fn open(
        directory: &Path,
        installation: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        Self::open_mode(directory, installation, true, cancel, deadline)
    }
    pub(crate) fn open_existing(
        directory: &Path,
        installation: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        Self::open_mode(directory, installation, false, cancel, deadline)
    }
    fn open_mode(
        directory: &Path,
        installation: &str,
        initialize: bool,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        check(cancel, deadline)?;
        if installation.len() != 32
            || installation
                .bytes()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
            || installation.bytes().all(|b| b == b'0')
        {
            return Err(invalid(
                "installation identifier must be nonzero canonical hex",
            ));
        }
        let text = directory
            .to_str()
            .ok_or_else(|| invalid("directory is not UTF-8"))?;
        if text.is_empty()
            || text.len() > 4096
            || text.chars().any(char::is_control)
            || directory
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(invalid("invalid unit directory path"));
        }
        let path: PathBuf = std::path::absolute(directory)?
            .components()
            .collect();
        let text = path
            .to_str()
            .ok_or_else(|| invalid("absolute directory is not UTF-8"))?;
        if text.len() > 4096 || text.chars().any(char::is_control) {
            return Err(invalid("invalid absolute directory"));
        }
        let root = linux_fd::open_top_directory(&path).map_err(open_error)?;
        directory_mode(&root, false)?;
        if linux_fd::directory_path(&root)? != path {
            return Err(invalid("unit directory changed"));
        }
        let name = format!(".syrox-os-{installation}");
        let (authority, created) = if initialize {
            linux_fd::ensure_directory_beneath_with_status(root.fd(), Path::new(&name))
                .map_err(|_| invalid("cannot open publication authority"))?
        } else {
            (
                linux_fd::open_beneath(root.fd(), Path::new(&name), true).map_err(open_error)?,
                false,
            )
        };
        directory_mode(&authority, true)?;
        let lock = if created {
            let (lock, fresh) =
                linux_fd::initialize_regular(authority.fd(), Path::new("authority.lock"))?;
            if !fresh {
                return Err(invalid("new authority already has a lock"));
            }
            linux_fd::sync_file(lock.fd())?;
            linux_fd::sync_directory(authority.fd())?;
            linux_fd::sync_directory(root.fd())?;
            lock
        } else {
            linux_fd::open_existing_regular(authority.fd(), Path::new("authority.lock"))?
        };
        regular(&lock)?;
        let selected = Self {
            path,
            installation: installation.into(),
            root,
            authority,
            lock_identity: lock.metadata().identity(),
            poisoned: AtomicBool::new(false),
        };
        let _guard = selected.lock(cancel, deadline)?;
        if created {
            selected.save(&Ledger {
                version: 1,
                installation: installation.into(),
                units: BTreeMap::new(),
                pending: None,
            })?;
        } else {
            selected.load()?;
        }
        check(cancel, deadline)?;
        Ok(selected)
    }

    /// Read-only preflight, not a reservation or durability reconciliation.
    /// Publication repeats the ownership checks under the same authority lock.
    pub(crate) fn check_capacity(
        &self,
        units: &[SystemdUnitName],
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        let _guard = self.lock(cancel, deadline)?;
        let ledger = self.load()?;
        if ledger.pending.is_some() {
            return Err(invalid(
                "pending publication requires explicit reconciliation",
            ));
        }
        let mut names: BTreeSet<&str> = ledger.units.keys().map(String::as_str).collect();
        for unit in units {
            check(cancel, deadline)?;
            validate_unit(&self.installation, unit.as_str())?;
            names.insert(unit.as_str());
            if names.len() > MAX_UNITS {
                return Err(invalid("unit inventory capacity exhausted"));
            }
        }
        for name in names {
            check(cancel, deadline)?;
            if self.unit_pin(name)? != ledger.units.get(name).copied() {
                return Err(invalid("unit file differs or is not owned"));
            }
        }
        check(cancel, deadline)
    }

    pub(crate) fn publish(
        &self,
        unit: &SystemdUnitName,
        bytes: &[u8],
        expected: Option<ContentDigest>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<ContentDigest> {
        validate_unit(&self.installation, unit.as_str())?;
        if bytes.len() > MAX_UNIT || !bytes.starts_with(MARKER) {
            return Err(invalid("unit bytes lack marker or exceed limit"));
        }
        let target = ContentDigest::sha256(bytes);
        let _guard = self.lock(cancel, deadline)?;
        let mut ledger = self.load()?;
        if ledger.pending.is_some() {
            return Err(invalid(
                "pending publication requires explicit reconciliation",
            ));
        }
        if ledger.units.get(unit.as_str()).copied() != expected {
            return Err(invalid("unit ownership compare-and-swap failed"));
        }
        if self.unit_pin(unit.as_str())? != expected {
            return Err(invalid("unit file differs or is not owned"));
        }
        if expected.is_none() && ledger.units.len() >= MAX_UNITS {
            return Err(invalid("unit inventory capacity exhausted"));
        }
        self.budgets(cancel, deadline)?;
        ledger.pending = Some(Intent {
            unit: unit.as_str().into(),
            previous: expected,
            target,
        });
        check(cancel, deadline)?;
        self.save(&ledger)?; // Durable provenance precedes touching the unit.
        let result = (|| {
            check(cancel, deadline)?;
            #[cfg(test)]
            fail_at(1)?;
            // The lock is the CAS authority. Recheck bytes immediately before publication.
            if self.unit_pin(unit.as_str())? != expected {
                return Err(invalid("unit changed after publication intent"));
            }
            self.write(
                self.root.fd(),
                unit.as_str(),
                bytes,
                &format!(".syrox-os-{}.tmp.", self.installation),
            )?;
            #[cfg(test)]
            fail_at(2)?;
            self.sync_unit(unit.as_str())?;
            ledger.units.insert(unit.as_str().into(), target);
            ledger.pending = None;
            check(cancel, deadline)?;
            self.save(&ledger)?;
            Ok(target)
        })();
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Reconcile a lost caller reply after our ledger commit, without rewriting
    /// the unit. Unregistered matching bytes are not ownership evidence.
    pub(crate) fn observe(
        &self,
        unit: &SystemdUnitName,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<ContentDigest>> {
        validate_unit(&self.installation, unit.as_str())?;
        let _guard = self.lock(cancel, deadline)?;
        let ledger = self.load()?;
        if ledger.pending.is_some() {
            return Err(invalid(
                "pending publication requires explicit reconciliation",
            ));
        }
        let owned = ledger.units.get(unit.as_str()).copied();
        if self.unit_pin(unit.as_str())? != owned {
            return Err(invalid("unit file differs or is not owned"));
        }
        self.confirm_observation(unit.as_str(), owned, &ledger, cancel, deadline)?;
        check(cancel, deadline)?;
        Ok(owned)
    }

    /// Prove the exact prior state is durable, without publishing or adopting.
    /// The caller must first reconcile an exact pending publisher intent and
    /// holds the installation execution guard across its recovery decision.
    pub(crate) fn confirm_previous(
        &self,
        unit: &SystemdUnitName,
        previous: Option<ContentDigest>,
        target: ContentDigest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        validate_unit(&self.installation, unit.as_str())?;
        let _guard = self.lock(cancel, deadline)?;
        let ledger = self.load()?;
        if previous == Some(target) {
            return Err(invalid(
                "previous and target bytes are indistinguishable",
            ));
        }
        if ledger.pending.is_some() {
            return Err(invalid(
                "pending publication requires exact reconciliation",
            ));
        }
        if ledger.units.get(unit.as_str()).copied() != previous {
            return Err(invalid(
                "owned inventory differs from expected previous state",
            ));
        }
        self.confirm_observation(unit.as_str(), previous, &ledger, cancel, deadline)
    }

    fn confirm_observation(
        &self,
        name: &str,
        expected: Option<ContentDigest>,
        ledger: &Ledger,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        check(cancel, deadline)?;
        let record = linux_fd::open_existing_regular(self.authority.fd(), Path::new("ownership"))?;
        let bytes = encode(ledger)?;
        if read_opened(&record, MAX_LEDGER)? != bytes {
            return Err(invalid("ownership changed before observation"));
        }
        let file = open_optional(self.root.fd(), name)?;
        if observed_pin(file.as_ref())? != expected {
            return Err(invalid(
                "unit file differs from expected observation",
            ));
        }
        let synced = (|| {
            if let Some(file) = &file {
                linux_fd::sync_file(file.fd())?;
            }
            linux_fd::sync_file(record.fd())?;
            linux_fd::sync_directory(self.root.fd())?;
            linux_fd::sync_directory(self.authority.fd())?;
            Ok::<_, io::Error>(())
        })();
        if synced.is_err() {
            return Err(self.uncertain());
        }
        check(cancel, deadline)?;
        #[cfg(test)]
        OBSERVATION_HOOK.with(|hook| {
            if let Some(action) = hook.borrow_mut().take() {
                action();
            }
        });
        self.validate_authority()?;
        let current_record =
            linux_fd::open_existing_regular(self.authority.fd(), Path::new("ownership"))?;
        let current_file = open_optional(self.root.fd(), name)?;
        if current_record.metadata().identity() != record.metadata().identity()
            || read_opened(&current_record, MAX_LEDGER)? != bytes
            || current_file
                .as_ref()
                .map(|file| file.metadata().identity())
                != file
                    .as_ref()
                    .map(|file| file.metadata().identity())
            || observed_pin(current_file.as_ref())? != expected
        {
            return Err(invalid(
                "publication evidence changed during durable observation",
            ));
        }
        check(cancel, deadline)
    }

    /// Never retries a write to a unit. Only a durable publisher intent permits
    /// adoption of exact target bytes after an ambiguous reply.
    #[cfg(test)]
    pub(crate) fn reconcile(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<UnitReconciliation> {
        self.reconcile_selected(None, cancel, deadline)
    }
    /// Reconcile only an intent belonging to this exact requested publication.
    /// `NoPending` grants no ownership; the caller must separately observe bytes.
    pub(crate) fn reconcile_expected(
        &self,
        unit: &SystemdUnitName,
        previous: Option<ContentDigest>,
        target: ContentDigest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<UnitReconciliation> {
        validate_unit(&self.installation, unit.as_str())?;
        self.reconcile_selected(Some((unit, previous, target)), cancel, deadline)
    }
    fn reconcile_selected(
        &self,
        expected: Option<(
            &SystemdUnitName,
            Option<ContentDigest>,
            ContentDigest,
        )>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<UnitReconciliation> {
        let _guard = self.lock(cancel, deadline)?;
        let mut ledger = self.load()?;
        let Some(intent) = ledger.pending.clone() else {
            return Ok(UnitReconciliation::NoPending);
        };
        if expected.is_some_and(|(unit, previous, target)| {
            intent.unit != unit.as_str() || intent.previous != previous || intent.target != target
        }) {
            return Err(invalid(
                "pending publication differs from requested effect",
            ));
        }
        let observed = self.unit_pin(&intent.unit)?;
        let outcome = if observed == Some(intent.target) {
            self.sync_unit(&intent.unit)
                .map_err(|_| self.uncertain())?;
            ledger
                .units
                .insert(intent.unit.clone(), intent.target);
            UnitReconciliation::Published {
                unit: intent.unit,
                pin: intent.target,
            }
        } else if observed == intent.previous {
            // Preserve previous ownership; absence is only acceptable for first publication.
            if observed.is_some() {
                self.sync_unit(&intent.unit)
                    .map_err(|_| self.uncertain())?;
            } else {
                linux_fd::sync_directory(self.root.fd()).map_err(|_| self.uncertain())?;
            }
            UnitReconciliation::NotPublished {
                unit: intent.unit,
                previous: intent.previous,
            }
        } else {
            return Err(invalid(
                "publication evidence conflicts; preserved without adoption",
            ));
        };
        ledger.pending = None;
        check(cancel, deadline)?;
        self.save(&ledger)?;
        Ok(outcome)
    }

    fn lock(&self, cancel: &Cancellation, deadline: Instant) -> Result<Guard> {
        check(cancel, deadline)?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(UnitFilesError::Uncertain);
        }
        let file =
            linux_fd::open_existing_regular(self.authority.fd(), Path::new("authority.lock"))?;
        regular(&file)?;
        if file.metadata().identity() != self.lock_identity {
            return Err(invalid("unit authority lock changed"));
        }
        loop {
            check(cancel, deadline)?;
            if linux_fd::flock(file.fd(), FlockMode::ExclusiveNonblocking)? {
                break;
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            );
        }
        let guard = Guard(file);
        self.validate_authority()?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(UnitFilesError::Uncertain);
        }
        check(cancel, deadline)?;
        Ok(guard)
    }
    fn validate_authority(&self) -> Result<()> {
        let root = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        directory_mode(&root, false)?;
        let authority = linux_fd::open_beneath(
            self.root.fd(),
            Path::new(&format!(".syrox-os-{}", self.installation)),
            true,
        )
        .map_err(open_error)?;
        directory_mode(&authority, true)?;
        let lock = linux_fd::open_existing_regular(authority.fd(), Path::new("authority.lock"))?;
        regular(&lock)?;
        if root.metadata().identity() != self.root.metadata().identity()
            || authority.metadata().identity() != self.authority.metadata().identity()
            || lock.metadata().identity() != self.lock_identity
        {
            return Err(invalid("unit directory or authority replaced"));
        }
        if linux_fd::directory_path(&self.root)? != self.path {
            return Err(invalid("unit directory moved"));
        }
        Ok(())
    }
    fn unit_pin(&self, name: &str) -> Result<Option<ContentDigest>> {
        let Some(bytes) = read(self.root.fd(), name, MAX_UNIT)? else {
            return Ok(None);
        };
        if !bytes.starts_with(MARKER) {
            return Err(invalid("unit marker differs"));
        }
        Ok(Some(ContentDigest::sha256(&bytes)))
    }
    fn sync_unit(&self, name: &str) -> Result<()> {
        let file = linux_fd::open_existing_regular(self.root.fd(), Path::new(name))?;
        regular(&file)?;
        linux_fd::sync_file(file.fd())?;
        linux_fd::sync_directory(self.root.fd())?;
        Ok(())
    }
    fn load(&self) -> Result<Ledger> {
        let bytes = read(self.authority.fd(), "ownership", MAX_LEDGER)?
            .ok_or_else(|| invalid("ownership ledger absent; evidence preserved"))?;
        let body = bytes
            .strip_prefix(HEADER)
            .ok_or_else(|| invalid("unsupported ownership ledger"))?;
        let ledger: Ledger =
            serde_json::from_slice(body).map_err(|_| invalid("invalid ownership ledger"))?;
        if ledger.version != 1
            || ledger.installation != self.installation
            || ledger.units.len() > MAX_UNITS
            || encode(&ledger)? != bytes
        {
            return Err(invalid("noncanonical ownership ledger"));
        }
        for unit in ledger.units.keys() {
            validate_unit(&self.installation, unit)?;
        }
        if let Some(intent) = &ledger.pending {
            validate_unit(&self.installation, &intent.unit)?;
            if ledger.units.get(&intent.unit).copied() != intent.previous
                || intent.previous.is_none() && ledger.units.len() >= MAX_UNITS
            {
                return Err(invalid("intent differs from owned inventory"));
            }
        }
        Ok(ledger)
    }
    fn save(&self, ledger: &Ledger) -> Result<()> {
        self.write(
            self.authority.fd(),
            "ownership",
            &encode(ledger)?,
            ".syrox-unit-ledger.tmp.",
        )
    }
    fn write(
        &self,
        directory: BorrowedFd<'_>,
        name: &str,
        bytes: &[u8],
        prefix: &str,
    ) -> Result<()> {
        linux_fd::write_atomic_beneath_with_prefix(directory, Path::new(name), bytes, prefix)
            .map_err(|_| self.uncertain())
    }
    fn uncertain(&self) -> UnitFilesError {
        self.poisoned.store(true, Ordering::Release);
        UnitFilesError::Uncertain
    }
    fn budgets(&self, cancel: &Cancellation, deadline: Instant) -> Result<()> {
        for (directory, max, prefix) in [
            (
                &self.root,
                16384,
                format!(".syrox-os-{}.tmp.", self.installation),
            ),
            (
                &self.authority,
                128,
                ".syrox-unit-ledger.tmp.".into(),
            ),
        ] {
            let mut count = 0;
            let mut temporary = 0;
            linux_fd::read_directory(directory, |name| {
                check(cancel, deadline)?;
                count += 1;
                if name
                    .as_encoded_bytes()
                    .starts_with(prefix.as_bytes())
                {
                    temporary += 1;
                }
                if count >= max || temporary >= 64 {
                    return Err(invalid(
                        "unit publication directory budget exhausted",
                    ));
                }
                Ok(())
            })
            .map_err(|error| match error {
                linux_fd::ReadDirectoryError::Io(error) => UnitFilesError::Io(error),
                linux_fd::ReadDirectoryError::Admission(error) => error,
            })?;
        }
        Ok(())
    }
}
fn encode(ledger: &Ledger) -> Result<Vec<u8>> {
    let mut bytes = HEADER.to_vec();
    serde_json::to_writer(&mut bytes, ledger).map_err(|_| invalid("cannot encode ownership"))?;
    if bytes.len() > MAX_LEDGER {
        return Err(invalid("ownership ledger exceeds bound"));
    }
    Ok(bytes)
}
fn validate_unit(installation: &str, unit: &str) -> Result<()> {
    let hash = unit
        .strip_prefix(&format!("syrox-os-{installation}-"))
        .and_then(|text| text.strip_suffix(".service"));
    if hash.is_none_or(|text| text.parse::<ContentDigest>().is_err()) {
        return Err(invalid("unit is outside installation namespace"));
    }
    Ok(())
}
fn open_optional(directory: BorrowedFd<'_>, name: &str) -> Result<Option<OpenedPath>> {
    match linux_fd::open_existing_regular(directory, Path::new(name)) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn read(directory: BorrowedFd<'_>, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
    open_optional(directory, name)?
        .as_ref()
        .map(|file| read_opened(file, limit))
        .transpose()
}
fn read_opened(file: &OpenedPath, limit: usize) -> Result<Vec<u8>> {
    regular(file)?;
    if file.metadata().size() > limit as u64 {
        return Err(invalid("unit publication file exceeds bound"));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(file.fd().try_clone_to_owned()?)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("unit publication file grew beyond bound"));
    }
    Ok(bytes)
}
fn observed_pin(file: Option<&OpenedPath>) -> Result<Option<ContentDigest>> {
    let Some(file) = file else {
        return Ok(None);
    };
    let bytes = read_opened(file, MAX_UNIT)?;
    if !bytes.starts_with(MARKER) {
        return Err(invalid("unit marker differs"));
    }
    Ok(Some(ContentDigest::sha256(&bytes)))
}
fn regular(file: &OpenedPath) -> Result<()> {
    if !file.metadata().is_trusted_regular() || file.metadata().mode() & 0o7777 != 0o600 {
        return Err(invalid(
            "publication file must be owned, single linked and mode 0600",
        ));
    }
    Ok(())
}
fn directory_mode(directory: &OpenedPath, private: bool) -> Result<()> {
    let mode = directory.metadata().mode() & 0o7777;
    if !directory.metadata().is_trusted_directory()
        || mode & 0o7022 != 0
        || mode & 0o700 != 0o700
        || private && mode != 0o700
    {
        return Err(invalid(
            "unit directory must be owned and not group/world writable",
        ));
    }
    Ok(())
}
fn invalid(reason: &'static str) -> UnitFilesError {
    UnitFilesError::Invalid(reason)
}
fn open_error(error: linux_fd::OpenError) -> UnitFilesError {
    match error {
        linux_fd::OpenError::Symlink => invalid("publication traverses a symlink"),
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => error.into(),
    }
}
fn check(cancel: &Cancellation, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(UnitFilesError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(UnitFilesError::Deadline);
    }
    Ok(())
}
#[cfg(test)]
fn fail_at(stage: u8) -> Result<()> {
    if FAIL_AT.with(|value| value.get() == stage) {
        return Err(UnitFilesError::Uncertain);
    }
    Ok(())
}
#[cfg(test)]
thread_local! { static FAIL_AT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
thread_local! { static OBSERVATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) }; }

mod digest {
    use super::{ContentDigest, Deserialize};
    pub(super) fn serialize<S: serde::Serializer>(
        value: &ContentDigest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContentDigest, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
mod optional_digest {
    use super::{ContentDigest, Deserialize, Serialize};
    #[allow(clippy::ref_option)] // Serde with-module receives a reference to the complete field.
    pub(super) fn serialize<S: serde::Serializer>(
        value: &Option<ContentDigest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .map(|pin| pin.to_string())
            .serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ContentDigest>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}
mod digest_map {
    use super::{BTreeMap, ContentDigest, Deserialize, Serialize};
    pub(super) fn serialize<S: serde::Serializer>(
        value: &BTreeMap<String, ContentDigest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(|(key, pin)| (key, pin.to_string()))
            .collect::<BTreeMap<_, _>>()
            .serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, ContentDigest>, D::Error> {
        BTreeMap::<String, String>::deserialize(deserializer)?
            .into_iter()
            .map(|(key, pin)| {
                Ok((
                    key,
                    pin.parse().map_err(serde::de::Error::custom)?,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "tests/unit_files.rs"]
mod tests;
