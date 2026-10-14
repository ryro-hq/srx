use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

use serde::{Deserialize, Serialize};

use super::ProxyContext;
use crate::execution::journal::ExecutionId;
use crate::platform::linux::fd::PreparedLaunch;
use crate::store::ContentDigest;

pub(crate) const MAX_METADATA_BYTES: usize = 32 * 1024;
pub(crate) const DESCRIPTOR_COUNT: usize = 12;

pub(crate) struct EntryMetadata {
    pub(crate) context: ProxyContext,
    pub(crate) execution: ExecutionId,
    pub(crate) retention: ContentDigest,
    pub(crate) worker: ContentDigest,
    pub(crate) root_spec: ContentDigest,
    root_arguments_count: usize,
    root_arguments: ContentDigest,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMetadata {
    domain: String,
    version: u32,
    context: String,
    execution: String,
    retention: String,
    worker: String,
    root_spec: String,
    root_arguments_count: usize,
    root_arguments: String,
}
impl EntryMetadata {
    pub(crate) fn new(
        context: ProxyContext,
        execution: ExecutionId,
        retention: ContentDigest,
        worker: ContentDigest,
        root_spec: ContentDigest,
        arguments: &[OsString],
    ) -> io::Result<Self> {
        Ok(Self {
            context,
            execution,
            retention,
            worker,
            root_spec,
            root_arguments_count: arguments.len(),
            root_arguments: arguments_pin(arguments)?,
        })
    }
    pub(crate) fn root_arguments_count(&self) -> usize {
        self.root_arguments_count
    }
    pub(crate) fn validate_root_arguments(&self, arguments: &[OsString]) -> io::Result<()> {
        if arguments.len() != self.root_arguments_count
            || arguments_pin(arguments)? != self.root_arguments
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn root_announcement(&self) -> io::Result<Vec<u8>> {
        let mut bytes = b"SCRI1".to_vec();
        bytes.extend_from_slice(ContentDigest::sha256(self.encode()?.as_bytes()).as_bytes());
        Ok(bytes)
    }

    pub(crate) fn encode(&self) -> io::Result<String> {
        let value = WireMetadata {
            domain: "syrox-command-execution".into(),
            version: 2,
            context: String::from_utf8(self.context.canonical_bytes()?).map_err(|_| invalid())?,
            execution: self.execution.to_string(),
            retention: self.retention.to_string(),
            worker: self.worker.to_string(),
            root_spec: self.root_spec.to_string(),
            root_arguments_count: self.root_arguments_count,
            root_arguments: self.root_arguments.to_string(),
        };
        let text = serde_json::to_string(&value).map_err(|_| invalid())?;
        if text.len() > MAX_METADATA_BYTES {
            return Err(invalid());
        }
        Ok(text)
    }
    pub(crate) fn decode(text: &str) -> io::Result<Self> {
        if text.len() > MAX_METADATA_BYTES {
            return Err(invalid());
        }
        let value: WireMetadata = serde_json::from_str(text).map_err(|_| invalid())?;
        if value.domain != "syrox-command-execution" || value.version != 2 {
            return Err(invalid());
        }
        let parsed = Self {
            context: ProxyContext::decode(value.context.as_bytes())?,
            execution: ExecutionId::parse(&value.execution).map_err(|_| invalid())?,
            retention: value.retention.parse().map_err(|_| invalid())?,
            worker: value.worker.parse().map_err(|_| invalid())?,
            root_spec: value.root_spec.parse().map_err(|_| invalid())?,
            root_arguments_count: value.root_arguments_count,
            root_arguments: value
                .root_arguments
                .parse()
                .map_err(|_| invalid())?,
        };
        if parsed.root_arguments_count > super::request::MAX_ARGUMENTS || parsed.encode()? != text {
            return Err(invalid());
        }
        Ok(parsed)
    }
}

pub(crate) struct EntryDescriptors<'a> {
    pub(crate) bootstrap: BorrowedFd<'a>,
    pub(crate) settlement: BorrowedFd<'a>,
    pub(crate) control: BorrowedFd<'a>,
    pub(crate) resources: BorrowedFd<'a>,
    pub(crate) root_info: BorrowedFd<'a>,
    pub(crate) root_gate: BorrowedFd<'a>,
    pub(crate) listener: BorrowedFd<'a>,
    pub(crate) listener_node: BorrowedFd<'a>,
    pub(crate) directory: BorrowedFd<'a>,
    pub(crate) cwd: BorrowedFd<'a>,
    pub(crate) retention: BorrowedFd<'a>,
    pub(crate) frontend_pidfd: BorrowedFd<'a>,
    pub(crate) frontend_group: Option<BorrowedFd<'a>>,
}
impl<'a> EntryDescriptors<'a> {
    pub(crate) fn ordered(&self) -> [BorrowedFd<'a>; DESCRIPTOR_COUNT] {
        [
            self.bootstrap,
            self.settlement,
            self.control,
            self.resources,
            self.root_info,
            self.root_gate,
            self.listener,
            self.listener_node,
            self.directory,
            self.cwd,
            self.retention,
            self.frontend_pidfd,
        ]
    }
}

/// Caller adds the dedicated worker mode before this header, and, optionally,
/// the existing six terminal-custody arguments afterward. No payload is started.
pub(crate) fn configure<'a>(
    command: &mut PreparedLaunch<'a>,
    metadata: &EntryMetadata,
    descriptors: &EntryDescriptors<'a>,
    terminal: Option<BorrowedFd<'a>>,
) -> io::Result<()> {
    let fds = descriptors.ordered();
    for (index, fd) in fds.iter().enumerate() {
        if fd.as_raw_fd() < 3
            || fds[..index]
                .iter()
                .any(|other| other.as_raw_fd() == fd.as_raw_fd())
            || terminal.is_some_and(|terminal| terminal.as_raw_fd() == fd.as_raw_fd())
            || descriptors
                .frontend_group
                .is_some_and(|group| group.as_raw_fd() == fd.as_raw_fd())
        {
            return Err(invalid());
        }
    }
    if terminal.is_some_and(|fd| fd.as_raw_fd() < 3) {
        return Err(invalid());
    }
    if descriptors.frontend_group.is_some_and(|group| {
        group.as_raw_fd() < 3
            || terminal.is_none_or(|terminal| terminal.as_raw_fd() == group.as_raw_fd())
    }) {
        return Err(invalid());
    }
    command.arg(metadata.encode()?)?;
    for fd in fds {
        command.inherit(fd);
        command.arg(fd.as_raw_fd().to_string())?;
    }
    command.arg(descriptors.frontend_group.map_or_else(
        || OsString::from("none"),
        |fd| fd.as_raw_fd().to_string().into(),
    ))?;
    if let Some(group) = descriptors.frontend_group {
        command.inherit(group);
    }
    command.arg(terminal.map_or_else(
        || OsString::from("none"),
        |fd| fd.as_raw_fd().to_string().into(),
    ))?;
    if let Some(terminal) = terminal {
        command.inherit(terminal);
    }
    Ok(())
}
fn invalid() -> io::Error {
    io::Error::other("invalid private command execution header")
}

fn arguments_pin(arguments: &[OsString]) -> io::Result<ContentDigest> {
    use super::request::{MAX_ARGUMENT_BYTES, MAX_ARGUMENT_TOTAL_BYTES, MAX_ARGUMENTS};
    if arguments.len() > MAX_ARGUMENTS {
        return Err(invalid());
    }
    let mut canonical = b"syrox-command-root-arguments-v1\n".to_vec();
    canonical.extend_from_slice(&(arguments.len() as u64).to_le_bytes());
    let mut total = 0;
    for argument in arguments {
        let bytes = argument.as_bytes();
        total += bytes.len();
        if bytes.len() > MAX_ARGUMENT_BYTES
            || total > MAX_ARGUMENT_TOTAL_BYTES
            || bytes.contains(&0)
        {
            return Err(invalid());
        }
        canonical.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        canonical.extend_from_slice(bytes);
    }
    Ok(ContentDigest::sha256(&canonical))
}

/// Root payload status stays separate from guardian status and descendant
/// settlement. Neither a valid exit record nor EOF authorizes hold retirement.
pub(crate) struct RootExit(ExitStatus);
impl RootExit {
    pub(crate) fn new(status: ExitStatus) -> io::Result<Self> {
        let raw = status.into_raw();
        let canonical = if let Some(code) = status.code() {
            (0..=255).contains(&code) && raw == code << 8
        } else {
            status
                .signal()
                .is_some_and(|signal| (1..=64).contains(&signal))
                && raw & !0xff == 0
        };
        if !canonical {
            return Err(invalid());
        }
        Ok(Self(status))
    }
    pub(crate) fn encode(&self) -> [u8; 9] {
        let mut bytes = [0; 9];
        bytes[..5].copy_from_slice(b"SCRX1");
        bytes[5..].copy_from_slice(&self.0.into_raw().to_le_bytes());
        bytes
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 9 || &bytes[..5] != b"SCRX1" {
            return Err(invalid());
        }
        Self::new(ExitStatus::from_raw(i32::from_le_bytes(
            bytes[5..].try_into().map_err(|_| invalid())?,
        )))
    }
    pub(crate) fn status(&self) -> ExitStatus {
        self.0
    }
}

/// Root job-control observations are distinct from global descendant settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootEvent {
    Stopping {
        sequence: u64,
        signal: i32,
    },
    Stopped {
        sequence: u64,
        signal: i32,
    },
    Continued {
        sequence: u64,
    },
    Exited(ExitStatus),
}
impl RootEvent {
    pub(crate) fn encode(self) -> io::Result<Vec<u8>> {
        match self {
            Self::Exited(status) => Ok(RootExit::new(status)?.encode().to_vec()),
            Self::Stopping {
                sequence,
                signal,
            }
            | Self::Stopped {
                sequence,
                signal,
            } => {
                if sequence == 0
                    || !matches!(
                        signal,
                        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                    )
                {
                    return Err(invalid());
                }
                let mut bytes = if matches!(self, Self::Stopping { .. }) {
                    b"SCRP1"
                } else {
                    b"SCRS1"
                }
                .to_vec();
                bytes.extend_from_slice(&sequence.to_le_bytes());
                bytes.extend_from_slice(&signal.to_le_bytes());
                Ok(bytes)
            }
            Self::Continued {
                sequence,
            } => {
                if sequence == 0 {
                    return Err(invalid());
                }
                let mut bytes = b"SCRC1".to_vec();
                bytes.extend_from_slice(&sequence.to_le_bytes());
                Ok(bytes)
            }
        }
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let event = match bytes.get(..5) {
            Some(b"SCRX1") => Self::Exited(RootExit::decode(bytes)?.status()),
            Some(b"SCRP1") if bytes.len() == 17 => Self::Stopping {
                sequence: u64::from_le_bytes(bytes[5..13].try_into().map_err(|_| invalid())?),
                signal: i32::from_le_bytes(bytes[13..17].try_into().map_err(|_| invalid())?),
            },
            Some(b"SCRS1") if bytes.len() == 17 => Self::Stopped {
                sequence: u64::from_le_bytes(bytes[5..13].try_into().map_err(|_| invalid())?),
                signal: i32::from_le_bytes(bytes[13..17].try_into().map_err(|_| invalid())?),
            },
            Some(b"SCRC1") if bytes.len() == 13 => Self::Continued {
                sequence: u64::from_le_bytes(bytes[5..13].try_into().map_err(|_| invalid())?),
            },
            _ => return Err(invalid()),
        };
        if event.encode()? != bytes {
            return Err(invalid());
        }
        Ok(event)
    }
}

/// Private coordinator-to-guardian control; EOF remains an unconditional abort.
pub(crate) struct RootControl;
impl RootControl {
    pub(crate) fn abandon(sequence: u64) -> io::Result<[u8; 9]> {
        let mut bytes = Self::resume(sequence)?;
        bytes[0] = b'X';
        Ok(bytes)
    }
    pub(crate) fn pause(sequence: u64) -> io::Result<[u8; 9]> {
        let mut bytes = Self::resume(sequence)?;
        bytes[0] = b'P';
        Ok(bytes)
    }
    pub(crate) fn resume(sequence: u64) -> io::Result<[u8; 9]> {
        if sequence == 0 {
            return Err(invalid());
        }
        let mut bytes = [0; 9];
        bytes[0] = b'R';
        bytes[1..].copy_from_slice(&sequence.to_le_bytes());
        Ok(bytes)
    }
}

/// Validate the effective root argv before journal admission and revalidate it
/// in the dedicated monitor before creating any namespace.
pub(crate) fn validate_root_arguments(base: &[String], extras: &[OsString]) -> io::Result<()> {
    use super::request::{MAX_ARGUMENT_BYTES, MAX_ARGUMENT_TOTAL_BYTES, MAX_ARGUMENTS};
    if base
        .len()
        .checked_add(extras.len())
        .is_none_or(|count| count > MAX_ARGUMENTS)
    {
        return Err(invalid());
    }
    let mut total = 0_usize;
    for bytes in base
        .iter()
        .map(String::as_bytes)
        .chain(extras.iter().map(|arg| arg.as_bytes()))
    {
        if bytes.len() > MAX_ARGUMENT_BYTES || bytes.contains(&0) {
            return Err(invalid());
        }
        total = total
            .checked_add(bytes.len())
            .ok_or_else(invalid)?;
        if total > MAX_ARGUMENT_TOTAL_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}

/// The root without a private PTY may use files, pipes, sockets or /dev/null,
/// but must never delegate the caller's terminal device into a namespace.
pub(crate) fn validate_stdio(terminal: Option<BorrowedFd<'_>>) -> io::Result<()> {
    if let Some(terminal) = terminal {
        return crate::platform::linux::fd::terminal::validate_slave(terminal);
    }
    let (input, output, error) = (io::stdin(), io::stdout(), io::stderr());
    for (descriptor, input) in [
        (input.as_fd(), true),
        (output.as_fd(), false),
        (error.as_fd(), false),
    ] {
        super::request::validate_stdio(descriptor, input)?;
        let metadata = crate::platform::linux::fd::metadata(descriptor)?;
        if metadata.mode() & libc::S_IFMT == libc::S_IFCHR
            && !(libc::major(metadata.rdev()) == 1 && libc::minor(metadata.rdev()) == 3)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::journal::SessionId;
    use crate::platform::linux::fd::FileIdentity;
    use std::os::unix::ffi::OsStringExt as _;
    use std::path::Path;

    fn metadata(arguments: &[OsString]) -> io::Result<EntryMetadata> {
        EntryMetadata::new(
            ProxyContext::new(
                &SessionId::parse(&"1".repeat(32)).unwrap(),
                ContentDigest::sha256(b"index"),
                FileIdentity {
                    device: 1,
                    inode: 2,
                },
                Path::new("/work"),
            )?,
            ExecutionId::parse(&"2".repeat(32)).unwrap(),
            ContentDigest::sha256(b"hold"),
            ContentDigest::sha256(b"worker"),
            ContentDigest::sha256(b"root"),
            arguments,
        )
    }
    #[test]
    fn raw_root_arguments_are_bound_without_utf8_conversion_or_large_single_argument() {
        let arguments = vec![
            OsString::from_vec(vec![b'a', 0xff]),
            OsString::from("*;$()"),
        ];
        let original = metadata(&arguments).unwrap();
        let decoded = EntryMetadata::decode(&original.encode().unwrap()).unwrap();
        decoded
            .validate_root_arguments(&arguments)
            .unwrap();
        assert_eq!(decoded.root_arguments_count(), 2);
        assert_eq!(
            decoded.root_announcement().unwrap(),
            original.root_announcement().unwrap()
        );
        let mut changed = arguments.clone();
        changed.reverse();
        assert!(decoded.validate_root_arguments(&changed).is_err());
        assert_ne!(
            original.root_announcement().unwrap(),
            metadata(&changed)
                .unwrap()
                .root_announcement()
                .unwrap()
        );
        let maximum = vec![OsString::from_vec(vec![0xff; 4096]); 16];
        let bounded = metadata(&maximum).unwrap().encode().unwrap();
        assert!(
            bounded.len() < 8192,
            "argument bytes belong in separate argv entries"
        );
        EntryMetadata::decode(&bounded)
            .unwrap()
            .validate_root_arguments(&maximum)
            .unwrap();
    }
    #[test]
    fn root_argument_bounds_and_noncanonical_metadata_are_rejected() {
        for arguments in [
            vec![OsString::from_vec(vec![b'x'; 4097])],
            vec![OsString::from("a"); 257],
            vec![OsString::from_vec(vec![b'x'; 4096]); 17],
            vec![OsString::from_vec(vec![b'a', 0, b'b'])],
        ] {
            assert!(metadata(&arguments).is_err());
        }
        let text = metadata(&[]).unwrap().encode().unwrap();
        assert!(EntryMetadata::decode(&(text.clone() + "\n")).is_err());
        assert!(
            EntryMetadata::decode(&text.replacen("\"version\":2", "\"version\":1", 1)).is_err()
        );
        assert!(EntryMetadata::decode(&" ".repeat(MAX_METADATA_BYTES + 1)).is_err());
    }

    #[test]
    fn group_descriptor_cannot_alias_channels_or_terminal_or_omit_terminal() {
        use std::fs::File;
        let files: [File; 14] = std::array::from_fn(|_| File::open("/dev/null").unwrap());
        let mut descriptors = EntryDescriptors {
            bootstrap: files[0].as_fd(),
            settlement: files[1].as_fd(),
            control: files[2].as_fd(),
            resources: files[3].as_fd(),
            root_info: files[4].as_fd(),
            root_gate: files[5].as_fd(),
            listener: files[6].as_fd(),
            listener_node: files[7].as_fd(),
            directory: files[8].as_fd(),
            cwd: files[9].as_fd(),
            retention: files[10].as_fd(),
            frontend_pidfd: files[11].as_fd(),
            frontend_group: Some(files[12].as_fd()),
        };
        let terminal = Some(files[13].as_fd());
        let metadata = metadata(&[]).unwrap();
        let mut command = PreparedLaunch::new(std::ffi::OsStr::new("/unused-worker")).unwrap();
        configure(&mut command, &metadata, &descriptors, terminal).unwrap();
        assert!(configure(&mut command, &metadata, &descriptors, None).is_err());
        descriptors.frontend_group = terminal;
        assert!(configure(&mut command, &metadata, &descriptors, terminal).is_err());
        for fd in descriptors.ordered() {
            descriptors.frontend_group = Some(fd);
            assert!(configure(&mut command, &metadata, &descriptors, terminal).is_err());
        }
        descriptors.frontend_group = None;
        configure(&mut command, &metadata, &descriptors, None).unwrap();
    }
    #[test]
    fn root_exit_preserves_signal_and_rejects_stopped_or_noncanonical_status() {
        for raw in [
            0,
            37 << 8,
            137 << 8,
            libc::SIGKILL,
            libc::SIGSEGV | 0x80,
        ] {
            let value = RootExit::new(ExitStatus::from_raw(raw)).unwrap();
            assert_eq!(
                RootExit::decode(&value.encode())
                    .unwrap()
                    .status()
                    .into_raw(),
                raw
            );
        }
        assert_eq!(
            RootExit::new(ExitStatus::from_raw(137 << 8))
                .unwrap()
                .status()
                .code(),
            Some(137)
        );
        assert_eq!(
            RootExit::new(ExitStatus::from_raw(libc::SIGKILL))
                .unwrap()
                .status()
                .signal(),
            Some(libc::SIGKILL)
        );
        for raw in [
            0xffff,
            0x10000,
            (libc::SIGSTOP << 8) | 0x7f,
            -1,
        ] {
            assert!(RootExit::new(ExitStatus::from_raw(raw)).is_err());
        }
    }

    #[test]
    fn effective_root_arguments_count_and_bytes_include_base() {
        assert!(
            validate_root_arguments(&["base".into()], &vec![OsString::from("x"); 256]).is_err()
        );
        assert!(
            validate_root_arguments(
                &["x".repeat(4096)],
                &vec![OsString::from("x".repeat(4096)); 16]
            )
            .is_err()
        );
        validate_root_arguments(
            &["base".into()],
            &[OsString::from_vec(vec![0xff])],
        )
        .unwrap();
    }

    #[test]
    fn root_job_control_records_do_not_conflate_pause_with_exit_or_settlement() {
        for event in [
            RootEvent::Stopping {
                sequence: 1,
                signal: libc::SIGTSTP,
            },
            RootEvent::Stopped {
                sequence: 1,
                signal: libc::SIGTSTP,
            },
            RootEvent::Continued {
                sequence: 1,
            },
            RootEvent::Exited(ExitStatus::from_raw(137 << 8)),
            RootEvent::Exited(ExitStatus::from_raw(libc::SIGKILL)),
        ] {
            let bytes = event.encode().unwrap();
            assert_eq!(RootEvent::decode(&bytes).unwrap(), event);
            assert!(RootEvent::decode(&bytes[..bytes.len() - 1]).is_err());
            let mut extra = bytes;
            extra.push(0);
            assert!(RootEvent::decode(&extra).is_err());
        }
        assert!(
            RootEvent::Stopped {
                sequence: 1,
                signal: libc::SIGTERM
            }
            .encode()
            .is_err()
        );
        assert!(
            RootEvent::Stopped {
                sequence: 0,
                signal: libc::SIGSTOP
            }
            .encode()
            .is_err()
        );
        assert!(
            RootEvent::Continued {
                sequence: 0
            }
            .encode()
            .is_err()
        );
        assert!(RootEvent::decode(b"S").is_err());
        assert!(RootControl::resume(0).is_err());
        assert!(RootControl::pause(0).is_err());
        assert_eq!(RootControl::pause(7).unwrap()[0], b'P');
        assert_eq!(
            &RootControl::resume(7).unwrap()[1..],
            &7_u64.to_le_bytes()
        );
    }
}
