//! Unpublished System worker outputs, separately versioned from legacy workers.

use super::{
    MAX_RESULT_OUTPUTS, PreparedSystemOutput, ResultError, SystemOutputStream,
    artifact::ArtifactLimits,
    check, invalid,
    producer::map_error,
    staging::{self, ScannedOutput},
    valid_name,
};
use crate::{
    cancellation::{CancellableReader, Cancellation},
    store::{ContentDigest, Store},
    system::budget::AdmittedBudget,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
};

const HEADER: &[u8] = b"syrox-system-worker-outputs-v1\n";

/// Transfer an exact output set from already settled, explicitly pinned trees.
/// Preflight charges all frames, including duplicate content, against one
/// budget. It checks every tree before writing the header. Later failure may
/// leave a partial destination, which must not be published as a result.
///
/// This framing carries no execution/peer authority or build receipt. A future
/// System executor must authenticate the transport, action, budget and settlement.
/// It is deliberately incompatible with the existing managed-worker protocol.
pub fn write_system_outputs(
    output: &mut impl Write,
    action: ContentDigest,
    mut streams: BTreeMap<String, SystemOutputStream<'_>>,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<(), ResultError> {
    check(cancellation)?;
    staging::system_limits(budget)?;
    validate_names(streams.keys().map(String::as_str))?;
    let mut used = Usage::default();
    for stream in streams.values() {
        let (bytes, files) = stream.charge();
        used.add(bytes, files as u64, budget)?;
        stream
            .preflight()
            .map_err(|e| map_error(&e, cancellation))?;
    }
    let mut output = CheckedWriter {
        output,
        cancellation,
    };
    output
        .write_all(HEADER)
        .map_err(|e| map_error(&e, cancellation))?;
    output
        .write_all(action.as_bytes())
        .map_err(|e| map_error(&e, cancellation))?;
    output
        .write_all(budget_pin(budget).as_bytes())
        .map_err(|e| map_error(&e, cancellation))?;
    output
        .write_all(
            &u16::try_from(streams.len())
                .expect("bounded outputs")
                .to_le_bytes(),
        )
        .map_err(|e| map_error(&e, cancellation))?;
    let mut buffer = vec![0; 64 * 1024];
    for (name, stream) in &mut streams {
        output
            .write_all(&[u8::try_from(name.len()).expect("bounded name")])
            .map_err(|e| map_error(&e, cancellation))?;
        output
            .write_all(name.as_bytes())
            .map_err(|e| map_error(&e, cancellation))?;
        output
            .write_all(&stream.encoded_size().to_le_bytes())
            .map_err(|e| map_error(&e, cancellation))?;
        let mut hash = Sha256::new();
        let mut copied = 0_u64;
        loop {
            check(cancellation)?;
            let n = match stream.read(&mut buffer) {
                Ok(n) => n,
                Err(e)
                    if e.kind() == io::ErrorKind::Interrupted
                        && !crate::cancellation::is_cancellation_io(&e) =>
                {
                    continue;
                }
                Err(e) => return Err(map_error(&e, cancellation)),
            };
            if n == 0 {
                break;
            }
            copied = copied
                .checked_add(n as u64)
                .filter(|n| *n <= stream.encoded_size())
                .ok_or_else(|| invalid("worker output length changed"))?;
            hash.update(&buffer[..n]);
            output
                .write_all(&buffer[..n])
                .map_err(|e| map_error(&e, cancellation))?;
        }
        if copied != stream.encoded_size() {
            return Err(invalid("worker output was truncated"));
        }
        output
            .write_all(&hash.finalize())
            .map_err(|e| map_error(&e, cancellation))?;
    }
    check(cancellation)
}

/// Receive exactly the names selected by an authenticated build description.
/// Each length is bounded before reading the body. Canonical package records,
/// alias expansion, aggregate bytes/inodes, per-frame SHA-256 and final EOF must
/// all pass. Failed receives publish no consumer root or build receipt; completed
/// unrooted uploads remain collectible. Returned handles retain their closure.
pub fn receive_system_outputs(
    store: &Store,
    input: &mut impl Read,
    action: ContentDigest,
    outputs: &BTreeSet<String>,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<BTreeMap<String, PreparedSystemOutput>, ResultError> {
    check(cancellation)?;
    let limits = staging::system_limits(budget)?;
    validate_names(outputs.iter().map(String::as_str))?;
    let mut input = CancellableReader {
        source: input,
        cancellation,
    };
    let mut header = vec![0; HEADER.len()];
    input
        .read_exact(&mut header)
        .map_err(|e| map_error(&e, cancellation))?;
    if header != HEADER
        || read::<32>(&mut input, cancellation)? != *action.as_bytes()
        || read::<32>(&mut input, cancellation)? != *budget_pin(budget).as_bytes()
        || usize::from(u16::from_le_bytes(read(
            &mut input,
            cancellation,
        )?)) != outputs.len()
    {
        return Err(invalid(
            "system worker output selection or budget differs",
        ));
    }
    let mut used = Usage::default();
    let mut prepared = BTreeMap::new();
    for expected in outputs {
        let length = usize::from(read::<1>(&mut input, cancellation)?[0]);
        if length != expected.len() {
            return Err(invalid("system worker output name differs"));
        }
        let mut name = vec![0; length];
        input
            .read_exact(&mut name)
            .map_err(|e| map_error(&e, cancellation))?;
        if name != expected.as_bytes() {
            return Err(invalid("system worker output name differs"));
        }
        let size = u64::from_le_bytes(read(&mut input, cancellation)?);
        // The scanner charges aliases and directories after the payload, but
        // a hostile declared length must fail before beginning CAS staging.
        if size == 0 || size > limits.bytes.saturating_sub(used.bytes) {
            return Err(invalid(
                "system worker output length exceeds remaining budget",
            ));
        }
        let frame_files = budget
            .request()
            .files
            .saturating_sub(used.files)
            .saturating_sub(1);
        if frame_files == 0 {
            return Err(invalid(
                "system worker output has no remaining inode budget",
            ));
        }
        let frame_limits = ArtifactLimits {
            bytes: limits.bytes - used.bytes,
            expanded_bytes: limits.expanded_bytes - used.bytes,
            files: usize::try_from(frame_files).expect("bounded files"),
        };
        let operation = store.operation()?;
        let mut staging = operation
            .begin_chunked(size, cancellation)
            .map_err(|e| invalid(e.to_string()))?;
        let mut body = input.by_ref().take(size);
        let ScannedOutput {
            files,
            entries,
            expanded_bytes,
            ..
        } = staging::scan_into(
            &mut body,
            &mut staging,
            frame_limits,
            false,
            cancellation,
        )?;
        if body.limit() != 0 {
            return Err(invalid(
                "system worker output frame length differs",
            ));
        }
        // Include the output root; empty directories have no wire records and
        // are charged by the worker, not reconstructed by this receiver.
        used.add(
            size.max(expanded_bytes),
            entries as u64 + 1,
            budget,
        )?;
        let pin = ContentDigest::from_sha256_hash(read(&mut input, cancellation)?);
        let result = staging::finish_staged(
            staging,
            pin,
            action,
            expected,
            files,
            cancellation,
        )?;
        prepared.insert(expected.clone(), result);
    }
    let trailing = loop {
        match input.read(&mut [0; 1]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => break result.map_err(|e| map_error(&e, cancellation))?,
        }
    };
    if trailing != 0 {
        return Err(invalid("trailing system worker output bytes"));
    }
    check(cancellation)?;
    Ok(prepared)
}

fn validate_names<'a>(names: impl Iterator<Item = &'a str>) -> Result<(), ResultError> {
    let names = names.collect::<Vec<_>>();
    if names.is_empty() || names.len() > MAX_RESULT_OUTPUTS || names.iter().any(|s| !valid_name(s))
    {
        return Err(invalid("invalid system worker output selection"));
    }
    Ok(())
}

fn budget_pin(budget: &AdmittedBudget) -> ContentDigest {
    let mut hash = Sha256::new();
    hash.update(b"syrox-system-output-budget-v1\n");
    hash.update(budget.policy_fingerprint());
    let request = budget.request();
    for value in [
        request.memory_bytes,
        u64::from(request.cpu_percent),
        u64::from(request.processes),
        u64::from(request.descriptors),
        request.scratch_bytes,
        request.files,
        request.output_bytes,
        u64::from(request.duration_seconds),
    ] {
        hash.update(value.to_le_bytes());
    }
    ContentDigest::from_sha256_hash(hash.finalize().into())
}

#[derive(Default)]
struct Usage {
    bytes: u64,
    files: u64,
}
impl Usage {
    fn add(&mut self, bytes: u64, files: u64, budget: &AdmittedBudget) -> Result<(), ResultError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= budget.request().output_bytes)
            .ok_or_else(|| invalid("aggregate system worker output bytes exceed budget"))?;
        self.files = self
            .files
            .checked_add(files)
            .filter(|n| *n <= budget.request().files)
            .ok_or_else(|| invalid("aggregate system worker output files exceed budget"))?;
        Ok(())
    }
}

fn read<const N: usize>(
    input: &mut impl Read,
    cancellation: &Cancellation,
) -> Result<[u8; N], ResultError> {
    let mut bytes = [0; N];
    input
        .read_exact(&mut bytes)
        .map_err(|e| map_error(&e, cancellation))?;
    Ok(bytes)
}

struct CheckedWriter<'a, W> {
    output: &'a mut W,
    cancellation: &'a Cancellation,
}
impl<W: Write> Write for CheckedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        self.output
            .write(&bytes[..bytes.len().min(64 * 1024)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        self.output.flush()
    }
}

#[cfg(test)]
mod tests;
