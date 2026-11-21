//! Non-root native qualification of the System output codec over a real pipe.
//!
//! Uses only newly created regular files beneath an explicit absent directory.
//! The worker and coordinator impose per-process address-space/descriptor limits;
//! this is not a System recipe, cgroup qualification, receipt or own-toolchain build.

#![allow(unsafe_code)]

use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd as _, RawFd},
        unix::fs::{DirBuilderExt as _, FileExt as _, MetadataExt as _, OpenOptionsExt as _},
    },
    path::Path,
    process::{Child, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};
use syrox_engine::{
    bundle::{export_system_bundle, import_system_bundle},
    cancellation::Cancellation,
    result::{
        ResultManifest, SystemOutputStream, admit_system_result, receive_system_outputs,
        write_system_outputs,
    },
    store::{ContentDigest, RootName, Store},
    system::budget::{AdmittedBudget, BuildBudget, BuilderLimits},
};

const PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024 + 17;
const ADDRESS_SPACE: u64 = 256 * 1024 * 1024;
const DESCRIPTORS: u64 = 64;

fn budget() -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: ADDRESS_SPACE,
        cpu_percent: 100,
        processes: 16,
        descriptors: u32::try_from(DESCRIPTORS).unwrap(),
        scratch_bytes: 64 * 1024 * 1024,
        files: 1024,
        output_bytes: PAYLOAD_BYTES + 4096,
        duration_seconds: 120,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

fn action() -> ContentDigest {
    ContentDigest::sha256(b"native System output transport probe; no build receipt")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: fixed observations of this process's actual credentials.
    let identity = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if identity.0 == 0 || identity.0 != identity.1 || identity.2 == 0 || identity.2 != identity.3 {
        return Err("probe requires matching non-root credentials".into());
    }
    impose_limits()?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, directory] if mode == "--worker" => worker(Path::new(directory)),
        [mode, directory] if mode == "--verify" => verify(Path::new(directory)),
        _ => Err("usage: system_output_transport --verify NEW_DIRECTORY".into()),
    }
}

fn impose_limits() -> io::Result<()> {
    for (resource, value) in [
        (libc::RLIMIT_AS, ADDRESS_SPACE),
        (libc::RLIMIT_NOFILE, DESCRIPTORS),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: fixed process-local limits, valid ABI structure; no elevation.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut observed = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: writable ABI output, fixed observation of this process's limit.
        if unsafe { libc::getrlimit(resource, &raw mut observed) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if observed.rlim_cur != value || observed.rlim_max != value {
            return Err(io::Error::other("probe limit readback differs"));
        }
    }
    Ok(())
}

fn worker(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cancel = Cancellation::default();
    let budget = budget();
    let stream = SystemOutputStream::from_directory(File::open(directory)?, &budget, &cancel)?;
    write_system_outputs(
        &mut io::stdout().lock(),
        action(),
        BTreeMap::from([("out".into(), stream)]),
        &budget,
        &cancel,
    )?;
    eprintln!("SRX_SYSTEM_OUTPUT_WORKER_OK {}", high_water()?);
    Ok(())
}

fn verify(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !directory.is_absolute() {
        return Err("verification directory must be an explicit absolute path".into());
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(directory)?; // Refuse all previous names; never replace evidence.
    let input = directory.join("input");
    builder.create(&input)?;
    let file = fresh(&input.join("payload"))?;
    file.set_len(PAYLOAD_BYTES)?;
    file.write_all_at(b"SRX first", 0)?;
    file.write_all_at(b"SRX last", PAYLOAD_BYTES - 8)?;
    file.sync_all()?;
    drop(file);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(120);
    let worker_log = fresh(&directory.join("worker.log"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--worker")
        .arg(&input)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(worker_log);
    let mut child = SettledChild(Some(command.spawn()?));
    drop(command);
    let pipe = child
        .0
        .as_mut()
        .unwrap()
        .stdout
        .take()
        .ok_or("worker pipe is missing")?;
    nonblocking(pipe.as_raw_fd())?;
    let mut input_pipe = DeadlinePipe {
        pipe,
        deadline,
    };
    let store = Store::initialize(&directory.join("store"))?;
    let cancel = Cancellation::default();
    let budget = budget();
    let outputs = receive_system_outputs(
        &store,
        &mut input_pipe,
        action(),
        &BTreeSet::from(["out".into()]),
        &budget,
        &cancel,
    )?;
    child.wait(deadline)?;
    let output = outputs.get("out").ok_or("missing output")?;
    let manifest = output.artifact().manifest();
    let content = independent_hash(&input.join("payload"), deadline)?;
    if manifest.content_digest() != content || manifest.size() <= 1024 * 1024 * 1024 {
        return Err("whole-frame digest or large-output size differs".into());
    }
    let result = ResultManifest::for_system(
        BTreeMap::from([("data".into(), output.metadata().clone())]),
        BTreeMap::new(),
        &budget,
    )?;
    let result_pin = result.digest()?;
    let root = RootName::new("native_system_output_transport")?;
    let admitted = admit_system_result(
        &store, &root, &result, result_pin, &budget, &cancel,
    )?;
    let bundle_path = directory.join("system.bundle");
    let mut bundle = fresh(&bundle_path)?;
    export_system_bundle(
        &store,
        &root,
        result_pin,
        &mut bundle,
        &budget,
        &cancel,
    )?;
    bundle.sync_all()?;
    drop(bundle);
    let destination = Store::initialize(&directory.join("imported-store"))?;
    let imported = import_system_bundle(
        &destination,
        &root,
        result_pin,
        &mut File::open(&bundle_path)?,
        &budget,
        &cancel,
    )?;
    if imported.manifest() != admitted.manifest() {
        return Err("imported result differs".into());
    }
    let log = fs::read_to_string(directory.join("worker.log"))?;
    if !log.contains("SRX_SYSTEM_OUTPUT_WORKER_OK ") {
        return Err("worker completion evidence is missing".into());
    }
    let report = serde_json::json!({
        "version": 1, "scope": "native_unprivileged_system_output_codec",
        "payload_bytes": PAYLOAD_BYTES, "package_bytes": manifest.size(),
        "content_sha256": content.to_string(), "artifact_sha256": output.metadata().artifact.to_string(),
        "result_sha256": result_pin.to_string(), "chunks": manifest.chunks().len(),
        "unique_result_references": result.references()?.len(), "bundle_bytes": fs::metadata(bundle_path)?.len(),
        "rlimit_as_bytes_per_process": ADDRESS_SPACE, "rlimit_nofile_per_process": DESCRIPTORS,
        "coordinator_vm_hwm": high_water()?, "worker_evidence": log.trim(),
        "elapsed_milliseconds": started.elapsed().as_millis(), "request": budget.request(),
        "worker_exit": 0, "system_recipe_executed": false, "build_receipt_created": false,
        "cgroup_qualification": false, "complete_system_qualification": false
    });
    let mut report_file = fresh(&directory.join("report.json"))?;
    serde_json::to_writer_pretty(&mut report_file, &report)?;
    report_file.write_all(b"\n")?;
    report_file.sync_all()?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn fresh(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

fn independent_hash(path: &Path, deadline: Instant) -> io::Result<ContentDigest> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != PAYLOAD_BYTES {
        return Err(io::Error::other("probe source changed"));
    }
    let mut hash = Sha256::new();
    hash.update(b"syrox-artifact\n");
    hash.update(1_u32.to_le_bytes());
    hash.update(7_u16.to_le_bytes());
    hash.update(b"payload");
    hash.update([0]);
    hash.update(PAYLOAD_BYTES.to_le_bytes());
    let mut buffer = vec![0; 64 * 1024];
    let mut offset = 0;
    while offset < PAYLOAD_BYTES {
        check_deadline(deadline)?;
        let take = usize::try_from((PAYLOAD_BYTES - offset).min(buffer.len() as u64)).unwrap();
        let n = file.read_at(&mut buffer[..take], offset)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        hash.update(&buffer[..n]);
        offset += n as u64;
    }
    hex(&hash.finalize())
        .parse()
        .map_err(io::Error::other)
}

fn high_water() -> io::Result<String> {
    fs::read_to_string("/proc/self/status")?
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("VmHWM observation missing"))
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: the parent exclusively owns this live pipe read description.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

struct DeadlinePipe {
    pipe: ChildStdout,
    deadline: Instant,
}
impl Read for DeadlinePipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            check_deadline(self.deadline)?;
            match self.pipe.read(bytes) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut poll = libc::pollfd {
                        fd: self.pipe.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: one initialized pollfd, live pipe, bounded 20ms wait.
                    if unsafe { libc::poll(&raw mut poll, 1, 20) } < 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() != io::ErrorKind::Interrupted {
                            return Err(e);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

struct SettledChild(Option<Child>);
impl SettledChild {
    fn wait(&mut self, deadline: Instant) -> io::Result<()> {
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait()? {
                self.0 = None;
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "probe worker failed: {status}"
                    )));
                }
                return Ok(());
            }
            check_deadline(deadline)?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for SettledChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("String write");
    }
    text
}
