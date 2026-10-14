//! Bytes included in the action digest and receipts.
//!
//! Field ordering and the persisted format are part of build identity. Changes to
//! record encoding must account for objects and receipts already in the Store.

use super::{
    BuildError, BuildProfile, BuildProgram, BuildResources, BuildSpecification, PROFILE,
    relative_path,
};
use crate::{
    plan::Plan, plan::PlanPackageId, result::OutputOrigin, store::ContentDigest, store::RootName,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;

pub(crate) const MAX_RECORD_BYTES: u64 = 2 * super::MAX_BUILD_PROGRAM_BYTES as u64 + 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Action {
    pub program: BuildProgram,
    pub source: ContentDigest,
    pub toolchain: Option<ContentDigest>,
    pub worker: ContentDigest,
    pub directory: String,
    pub inputs: Vec<InputIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InputIdentity {
    pub origin: OutputOrigin,
    pub action: ContentDigest,
    pub artifact: ContentDigest,
    pub output: String,
}

impl From<&crate::result::OutputIdentity> for InputIdentity {
    fn from(identity: &crate::result::OutputIdentity) -> Self {
        Self {
            origin: identity.origin.clone(),
            action: identity.action,
            artifact: identity.artifact,
            output: identity.output.clone(),
        }
    }
}

pub(crate) fn origin_pin(origin: &OutputOrigin) -> ContentDigest {
    match origin {
        OutputOrigin::Built {
            receipt,
        } => *receipt,
        OutputOrigin::Imported {
            manifest,
        } => *manifest,
    }
}
fn origin_name(origin: &OutputOrigin) -> &'static str {
    match origin {
        OutputOrigin::Built {
            ..
        } => "built",
        OutputOrigin::Imported {
            ..
        } => "imported",
    }
}

/// Effective build values selected from an authenticated Plan. Graph labels,
/// the enclosing Lock and attempt deadlines are not result identities.
pub(crate) struct BuildDescription<'a> {
    pub source: ContentDigest,
    pub program: &'a BuildProgram,
    pub directory: &'a str,
}

impl<'a> BuildDescription<'a> {
    pub fn from_plan(plan: &'a Plan, package: &PlanPackageId) -> Result<Self, BuildError> {
        let build = plan
            .builds()
            .find(|build| build.package() == package)
            .ok_or(BuildError::UnsupportedInputs)?;
        let acquisition = plan
            .acquisitions()
            .find(|acquisition| acquisition.package() == package)
            .filter(|acquisition| acquisition.sources().len() == 1)
            .ok_or(BuildError::UnsupportedInputs)?;
        Ok(Self {
            source: acquisition
                .sources()
                .next()
                .expect("one source")
                .digest(),
            program: build.program(),
            directory: build.source_directory(),
        })
    }
    pub fn matches(&self, action: &Action) -> bool {
        action.source == self.source
            && &action.program == self.program
            && action.directory == self.directory
    }
}

impl Action {
    pub(crate) fn new(
        request: &BuildSpecification,
        source: ContentDigest,
        toolchain: Option<ContentDigest>,
        worker: ContentDigest,
    ) -> Self {
        Self {
            program: request.program.clone(),
            source,
            toolchain,
            worker,
            directory: request.source_directory.clone(),
            inputs: Vec::new(),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let profile = profile_name(self.program.profile);
        let envelope = envelope(self.program.resources);
        let mut text = format!(
            "syrox-build-action-v5\nprofile {profile}\nsource {}\ntoolchain {}\nworker {}\ndirectory {}\nenvelope {envelope}\n",
            self.source,
            optional_pin(self.toolchain),
            self.worker,
            self.directory
        );
        writeln!(text, "selected-inputs {}", self.inputs.len()).expect("String write");
        for input in &self.inputs {
            writeln!(
                text,
                "selected-input {} {} {} {} {}",
                origin_name(&input.origin),
                origin_pin(&input.origin),
                input.action,
                input.artifact,
                input.output
            )
            .expect("String write");
        }
        text.push_str("program ");
        for byte in self.program.encode() {
            write!(text, "{byte:02x}").expect("String write");
        }
        text.push_str("\npayload-settlement subreaper-echild\n");
        text.into_bytes()
    }

    pub(crate) fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encode())
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, BuildError> {
        let text = record_text(bytes)?;
        let mut lines = text.lines();
        if lines.next() != Some("syrox-build-action-v5") {
            return Err(invalid("unsupported action format"));
        }
        let profile = field(&mut lines, "profile ")?;
        if profile != PROFILE && profile != super::MANAGED_PROFILE {
            return Err(invalid("unsupported action profile"));
        }
        let source = digest(field(&mut lines, "source ")?)?;
        let toolchain = parse_optional_pin(field(&mut lines, "toolchain ")?)?;
        let worker = digest(field(&mut lines, "worker ")?)?;
        let directory = field(&mut lines, "directory ")?.to_owned();
        let limits = field(&mut lines, "envelope ")?;
        let count: usize = field(&mut lines, "selected-inputs ")?
            .parse()
            .map_err(|_| invalid("invalid build inputs"))?;
        if count > 64 {
            return Err(invalid("too many build inputs"));
        }
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let fields = field(&mut lines, "selected-input ")?
                .split(' ')
                .collect::<Vec<_>>();
            let [origin, pin, action, artifact, output] = fields.as_slice() else {
                return Err(invalid("invalid input identity"));
            };
            if !valid_output_name(output) {
                return Err(invalid("invalid input output name"));
            }
            inputs.push(InputIdentity {
                origin: match *origin {
                    "built" => OutputOrigin::Built {
                        receipt: digest(pin)?,
                    },
                    "imported" => OutputOrigin::Imported {
                        manifest: digest(pin)?,
                    },
                    _ => return Err(invalid("invalid input origin")),
                },
                action: digest(action)?,
                artifact: digest(artifact)?,
                output: (*output).to_owned(),
            });
        }
        let program = decode_program(field(&mut lines, "program ")?)?;
        if profile != profile_name(program.profile)
            || toolchain.is_some() != (program.profile == BuildProfile::HostBootstrap)
        {
            return Err(invalid("profile and toolchain provenance differ"));
        }
        if limits != envelope(program.resources) {
            return Err(invalid("unsupported build envelope"));
        }
        let action = Self {
            program,
            source,
            toolchain,
            worker,
            directory,
            inputs,
        };
        if !relative_path(&action.directory)
            || action.directory.contains('/')
            || action
                .program
                .input_indices()
                .iter()
                .any(|index| *index as usize >= action.inputs.len())
            || action.encode() != bytes
        {
            return Err(invalid("noncanonical or invalid action"));
        }
        Ok(action)
    }
}

fn decode_program(hex: &str) -> Result<BuildProgram, BuildError> {
    if !hex.len().is_multiple_of(2) || hex.len() > 2 * super::MAX_BUILD_PROGRAM_BYTES {
        return Err(invalid("invalid program length"));
    }
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |c: u8| match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(invalid("invalid program hex")),
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect::<Result<Vec<_>, BuildError>>()?;
    BuildProgram::decode(&bytes)
}

fn envelope(resources: BuildResources) -> String {
    let limits = resources.envelope();
    format!(
        "memory {} tasks {} cpu-percent {} nofile {} output-bytes {} work-tmpfs {} output-tmpfs {}",
        limits.memory,
        limits.tasks,
        limits.cpu_percent,
        limits.nofile,
        limits.output_bytes,
        limits.work_tmpfs,
        limits.output_tmpfs
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub action: ContentDigest,
    pub source: ContentDigest,
    pub toolchain: Option<ContentDigest>,
    /// Objects retained from the declared provider's complete result root.
    pub inputs: Vec<ContentDigest>,
    pub outputs: BTreeMap<String, NamedOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NamedOutput {
    pub artifact: ContentDigest,
    pub files: usize,
}

impl Receipt {
    /// The root lists opaque digests; its presence alone does not prove that
    /// every referenced input still exists or matches its named object.
    pub(crate) fn verify_retained_inputs(
        &self,
        lease: &crate::store::OperationLease,
        action: &Action,
        mut check: impl FnMut() -> Result<(), BuildError>,
    ) -> Result<(), BuildError> {
        let source = (
            self.source,
            if action.program.resources == BuildResources::Large {
                super::MAX_LARGE_SOURCE_BYTES
            } else {
                super::MAX_SOURCE_BYTES
            },
        );
        for (digest, maximum) in std::iter::once(source).chain(
            self.toolchain
                .map(|pin| (pin, super::cache::MAX_INVENTORY_BYTES)),
        ) {
            check()?;
            if lease.open_verified_checked(digest, maximum, || {
                check().map_err(|_| std::io::Error::new(std::io::ErrorKind::Interrupted, "build cancelled"))
            }).map_err(|error| if matches!(error, crate::store::StoreError::Io(ref io) if io.kind() == std::io::ErrorKind::Interrupted) { BuildError::Cancelled } else { error.into() })?.is_none() {
                return Err(invalid("retained build input is missing"));
            }
        }
        for digest in &self.inputs {
            check()?;
            if lease
                .open_verified_checked(*digest, crate::store::MAX_STORE_BLOB_BYTES, || {
                    check().map_err(|_| std::io::Error::new(std::io::ErrorKind::Interrupted, "build cancelled"))
                }).map_err(|error| if matches!(error, crate::store::StoreError::Io(ref io) if io.kind() == std::io::ErrorKind::Interrupted) { BuildError::Cancelled } else { error.into() })?
                .is_none()
            {
                return Err(invalid("retained provider input is missing"));
            }
        }
        Ok(())
    }

    pub(crate) fn new(action: &Action, artifact: ContentDigest, files: usize) -> Self {
        Self {
            action: action.digest(),
            source: action.source,
            toolchain: action.toolchain,
            inputs: Vec::new(),
            outputs: BTreeMap::from([(
                "out".into(),
                NamedOutput {
                    artifact,
                    files,
                },
            )]),
        }
    }
    pub(crate) fn with_outputs(
        mut self,
        action: &Action,
        outputs: BTreeMap<String, NamedOutput>,
    ) -> Result<Self, BuildError> {
        let names = outputs
            .keys()
            .chain(self.outputs.keys())
            .cloned()
            .collect::<Vec<_>>();
        let mut sorted = names.clone();
        sorted.sort();
        if outputs.is_empty()
            || outputs.len() > 8
            || action.digest() != self.action
            || action.program.outputs != sorted
            || outputs.iter().any(|(name, output)| {
                !valid_output_name(name) || name == "out" || !valid_output(output)
            })
        {
            return Err(invalid("invalid named output manifest"));
        }
        self.outputs.extend(outputs);
        Ok(self)
    }
    pub(crate) fn with_inputs(
        mut self,
        action: &Action,
        inputs: Vec<ContentDigest>,
    ) -> Result<Self, BuildError> {
        self.inputs = inputs;
        if action.digest() != self.action || !self.matches_inputs(action) {
            return Err(invalid("invalid retained build input closure"));
        }
        Ok(self)
    }
    pub(crate) fn matches_inputs(&self, action: &Action) -> bool {
        self.inputs.len() <= 4096
            && self
                .inputs
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && (!action.inputs.is_empty() || self.inputs.is_empty())
            && action.inputs.iter().all(|input| {
                self.inputs.contains(&origin_pin(&input.origin))
                    && self.inputs.contains(&input.artifact)
                    && (matches!(input.origin, OutputOrigin::Imported { .. })
                        || self.inputs.contains(&input.action))
            })
    }
    pub(crate) fn matches_action(&self, action: &Action) -> bool {
        self.action == action.digest()
            && self.source == action.source
            && self.toolchain == action.toolchain
            && self.names() == action.program.outputs
            && self.output("out").is_some()
            && self.matches_inputs(action)
    }
    pub(crate) fn verify_inputs(
        &self,
        lease: &crate::store::OperationLease,
        action: &Action,
        cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
    ) -> Result<(), BuildError> {
        let mut pending = vec![(self.clone(), action.clone())];
        let mut visited = std::collections::BTreeSet::from([self.digest()]);
        let mut imported = BTreeMap::new();
        while let Some((receipt, selected)) = pending.pop() {
            receipt.verify_inputs_once(
                lease,
                &selected,
                cancellation,
                &mut pending,
                &mut visited,
                &mut imported,
            )?;
        }
        Ok(())
    }
    fn verify_inputs_once(
        &self,
        lease: &crate::store::OperationLease,
        action: &Action,
        cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
        pending: &mut Vec<(Self, Action)>,
        visited: &mut std::collections::BTreeSet<ContentDigest>,
        imported: &mut BTreeMap<ContentDigest, crate::result::ResultManifest>,
    ) -> Result<(), BuildError> {
        cancellation
            .check_cancelled()
            .map_err(BuildError::from)?;
        if !self.matches_inputs(action) {
            return Err(invalid("invalid retained build input closure"));
        }
        let mut expected = std::collections::BTreeSet::new();
        let providers = action
            .inputs
            .iter()
            .map(|input| input.origin.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for origin in providers {
            let provider_digest = origin_pin(&origin);
            if matches!(origin, OutputOrigin::Imported { .. }) {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    imported.entry(provider_digest)
                {
                    if visited.len() >= 4096 {
                        return Err(invalid("input graph exceeds limit"));
                    }
                    let manifest = crate::result::verify_build_input_manifest(
                        lease,
                        provider_digest,
                        cancellation,
                    )?;
                    entry.insert(manifest);
                    visited.insert(provider_digest);
                }
                let manifest = &imported[&provider_digest];
                for input in action
                    .inputs
                    .iter()
                    .filter(|input| input.origin == origin)
                {
                    if !manifest.outputs().values().any(|output| {
                        output.action == input.action
                            && output.artifact == input.artifact
                            && output.output == input.output
                    }) {
                        return Err(invalid(
                            "imported selection disagrees with manifest",
                        ));
                    }
                }
                expected.extend(
                    manifest
                        .references()
                        .map_err(|_| invalid("invalid imported references"))?,
                );
                if expected.len() > 4096 {
                    return Err(invalid("input closure exceeds limit"));
                }
                continue;
            }
            cancellation
                .check_cancelled()
                .map_err(BuildError::from)?;
            let bytes = lease
                .read_verified(provider_digest, MAX_RECORD_BYTES)?
                .ok_or_else(|| invalid("provider receipt is missing"))?;
            let provider = Self::parse(bytes.as_bytes())?;
            if provider.digest() != provider_digest
                || action
                    .inputs
                    .iter()
                    .filter(|input| input.origin == origin)
                    .any(|input| {
                        input.action != provider.action
                            || provider
                                .output(&input.output)
                                .is_none_or(|output| input.artifact != output.artifact)
                    })
            {
                return Err(invalid(
                    "provider closure disagrees with retained inputs",
                ));
            }
            let bytes = lease
                .read_verified(provider.action, MAX_RECORD_BYTES)?
                .ok_or_else(|| invalid("provider action is missing"))?;
            let provider_action = Action::parse(bytes.as_bytes())?;
            if !provider.matches_action(&provider_action) {
                return Err(invalid("provider action disagrees with receipt"));
            }
            if visited.insert(provider_digest) {
                if visited.len() > 4096 {
                    return Err(invalid("input graph exceeds limit"));
                }
                provider.verify_retained_inputs(lease, &provider_action, || {
                    cancellation
                        .check_cancelled()
                        .map_err(BuildError::from)
                })?;
                provider.verify_artifacts(lease, &provider_action, cancellation)?;
                pending.push((provider.clone(), provider_action));
            }
            expected.extend(provider.references());
            if expected.len() > 4096 {
                return Err(invalid("input closure exceeds limit"));
            }
        }
        if expected
            .into_iter()
            .ne(self.inputs.iter().copied())
        {
            return Err(invalid(
                "input closure disagrees with retained inputs",
            ));
        }
        Ok(())
    }
    fn verify_artifacts(
        &self,
        lease: &crate::store::OperationLease,
        action: &Action,
        cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
    ) -> Result<(), BuildError> {
        for output in self.outputs.values() {
            let artifact = lease
                .open_verified_checked(
                    output.artifact,
                    action.program.resources.envelope().output_bytes,
                    || {
                        cancellation
                            .check_cancelled()
                            .map_err(|_| crate::cancellation::cancellation_io())
                    },
                )
                .map_err(|error| {
                    if cancellation.is_cancelled() {
                        BuildError::Cancelled
                    } else {
                        error.into()
                    }
                })?
                .ok_or_else(|| invalid("provider artifact is absent"))?;
            if crate::result::artifact::validate_stream_checked(artifact, "", cancellation)?
                != output.files
            {
                return Err(invalid("provider artifact file count differs"));
            }
        }
        Ok(())
    }
    pub(crate) fn output(&self, name: &str) -> Option<&NamedOutput> {
        self.outputs.get(name)
    }
    pub(crate) fn names(&self) -> Vec<String> {
        self.outputs.keys().cloned().collect()
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut text = format!(
            "syrox-build-result-v4\naction {}\nsource {}\ntoolchain {}\ninputs {}\n",
            self.action,
            self.source,
            optional_pin(self.toolchain),
            self.inputs.len()
        );
        for digest in &self.inputs {
            writeln!(text, "input {digest}").expect("String writes are infallible");
        }
        writeln!(text, "outputs {}", self.outputs.len()).expect("String writes are infallible");
        for (name, output) in &self.outputs {
            writeln!(
                text,
                "output {name} {} {}",
                output.artifact, output.files
            )
            .expect("String writes are infallible");
        }
        text.push_str(
            "payload-settlement subreaper-echild\nsettlement systemd-unit-inactive-or-collected\n",
        );
        text.into_bytes()
    }
    pub(crate) fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encode())
    }
    pub(crate) fn root(&self) -> RootName {
        RootName::new(format!("build_{}", self.digest())).expect("receipt-derived root")
    }
    pub(crate) fn references(&self) -> Vec<ContentDigest> {
        let mut references = vec![self.action, self.source, self.digest()];
        references.extend(self.toolchain);
        references.extend_from_slice(&self.inputs);
        references.extend(
            self.outputs
                .values()
                .map(|output| output.artifact),
        );
        references.sort_unstable();
        references.dedup();
        references
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, BuildError> {
        let text = record_text(bytes)?;
        let mut lines = text.lines();
        if lines.next() != Some("syrox-build-result-v4") {
            return Err(invalid("unsupported receipt format"));
        }
        let action = digest(field(&mut lines, "action ")?)?;
        let source = digest(field(&mut lines, "source ")?)?;
        let toolchain = parse_optional_pin(field(&mut lines, "toolchain ")?)?;
        let input_count: usize = field(&mut lines, "inputs ")?
            .parse()
            .map_err(|_| invalid("invalid input count"))?;
        if input_count > 4096 {
            return Err(invalid("too many retained inputs"));
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let input = digest(field(&mut lines, "input ")?)?;
            if inputs
                .last()
                .is_some_and(|previous| *previous >= input)
            {
                return Err(invalid("unsorted retained inputs"));
            }
            inputs.push(input);
        }
        let count: usize = field(&mut lines, "outputs ")?
            .parse()
            .map_err(|_| invalid("invalid output count"))?;
        if !(1..=9).contains(&count) {
            return Err(invalid("invalid output count"));
        }
        let mut previous = String::new();
        let mut outputs = BTreeMap::new();
        for _ in 0..count {
            let line = field(&mut lines, "output ")?;
            let mut parts = line.split(' ');
            let name = parts
                .next()
                .ok_or_else(|| invalid("missing output name"))?;
            let output = NamedOutput {
                artifact: digest(
                    parts
                        .next()
                        .ok_or_else(|| invalid("missing output artifact"))?,
                )?,
                files: parts
                    .next()
                    .ok_or_else(|| invalid("missing output file count"))?
                    .parse()
                    .map_err(|_| invalid("invalid output file count"))?,
            };
            if parts.next().is_some()
                || !valid_output_name(name)
                || name <= previous.as_str()
                || !valid_output(&output)
            {
                return Err(invalid("invalid output record"));
            }
            name.clone_into(&mut previous);
            if outputs.insert(name.to_owned(), output).is_some() {
                return Err(invalid("duplicate output record"));
            }
        }
        let receipt = Self {
            action,
            source,
            toolchain,
            inputs,
            outputs,
        };
        if receipt.output("out").is_none()
            || receipt.outputs.len() != count
            || receipt.encode() != bytes
        {
            return Err(invalid("noncanonical or invalid receipt"));
        }
        Ok(receipt)
    }
}

fn valid_output_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_output(output: &NamedOutput) -> bool {
    (1..=16384).contains(&output.files)
}

fn record_text(bytes: &[u8]) -> Result<&str, BuildError> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("oversized build record"));
    }
    std::str::from_utf8(bytes).map_err(|_| invalid("build record is not UTF-8"))
}
fn field<'a>(lines: &mut std::str::Lines<'a>, prefix: &str) -> Result<&'a str, BuildError> {
    lines
        .next()
        .and_then(|line| line.strip_prefix(prefix))
        .ok_or_else(|| invalid("invalid build record field"))
}
fn digest(text: &str) -> Result<ContentDigest, BuildError> {
    text.parse()
        .map_err(|_| invalid("invalid build record digest"))
}
pub(crate) fn invalid(reason: &str) -> BuildError {
    BuildError::Cache(reason.to_owned())
}

fn profile_name(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::HostBootstrap => PROFILE,
        BuildProfile::Managed => super::MANAGED_PROFILE,
    }
}
fn optional_pin(pin: Option<ContentDigest>) -> String {
    pin.map_or_else(|| "none".into(), |pin| pin.to_string())
}
fn parse_optional_pin(text: &str) -> Result<Option<ContentDigest>, BuildError> {
    if text == "none" {
        Ok(None)
    } else {
        digest(text).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_manifest_is_canonical_and_bound_to_a_distinct_action() {
        let old = super::super::cache::tests::action();
        let mut named = old.clone();
        named.program.outputs = vec!["dev".into(), "doc".into(), "out".into()];
        assert_ne!(old.digest(), named.digest());
        assert_eq!(Action::parse(&named.encode()).unwrap(), named);
        let extra = NamedOutput {
            artifact: ContentDigest::sha256(b"dev"),
            files: 1,
        };
        let outputs = BTreeMap::from([
            ("dev".into(), extra.clone()),
            (
                "doc".into(),
                NamedOutput {
                    artifact: ContentDigest::sha256(b"doc"),
                    ..extra.clone()
                },
            ),
        ]);
        assert!(
            Receipt::new(&old, ContentDigest::sha256(b"out"), 1)
                .with_outputs(&old, outputs.clone())
                .is_err()
        );
        let receipt = Receipt::new(&named, ContentDigest::sha256(b"out"), 1)
            .with_outputs(&named, outputs)
            .unwrap();
        let bytes = receipt.encode();
        assert_eq!(Receipt::parse(&bytes).unwrap(), receipt);
        let swapped = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("output dev ", "output TEMP ")
            .replace("output doc ", "output dev ")
            .replace("output TEMP ", "output doc ");
        assert!(Receipt::parse(swapped.as_bytes()).is_err());
        assert!(Receipt::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut invalid_action = named.clone();
        invalid_action.program.outputs.swap(0, 1);
        assert!(Action::parse(&invalid_action.encode()).is_err());
        invalid_action.program.outputs = vec!["../escape".into()];
        assert!(Action::parse(&invalid_action.encode()).is_err());
    }

    #[test]
    fn selected_input_content_and_order_are_part_of_action_identity() {
        let old = super::super::cache::tests::action();
        let runtime = old.clone();
        let mut supplied = runtime.clone();
        supplied.inputs.push(InputIdentity {
            origin: OutputOrigin::Built {
                receipt: ContentDigest::sha256(b"glibc result"),
            },
            action: ContentDigest::sha256(b"provider action"),
            artifact: ContentDigest::sha256(b"development artifact"),
            output: "dev".into(),
        });
        assert_ne!(runtime.digest(), supplied.digest());
        assert_eq!(
            Action::parse(&supplied.encode()).unwrap(),
            supplied
        );
        let mut other = supplied.clone();
        other.inputs[0].artifact = ContentDigest::sha256(b"changed dev");
        assert_ne!(supplied.digest(), other.digest());
        assert!(Action::parse(&other.encode()).is_ok());
        supplied.inputs.push(InputIdentity {
            output: "out".into(),
            ..supplied.inputs[0].clone()
        });
        let mut reversed = supplied.clone();
        reversed.inputs.reverse();
        assert_ne!(supplied.digest(), reversed.digest());
        assert_eq!(
            Action::parse(&reversed.encode()).unwrap(),
            reversed
        );
    }

    #[test]
    fn build_description_matches_effective_values_independently_of_dependencies() {
        let provider = super::super::cache::tests::action();
        let description = BuildDescription {
            source: provider.source,
            program: &provider.program,
            directory: &provider.directory,
        };
        assert!(description.matches(&provider));
        for changed in [
            Action {
                source: ContentDigest::sha256(b"other source"),
                ..provider.clone()
            },
            Action {
                directory: "another-directory".into(),
                ..provider.clone()
            },
        ] {
            assert!(!description.matches(&changed));
        }
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use crate::{cancellation::Cancellation, result::ResultManifest, store::Store};

    fn ingest(lease: &crate::store::OperationLease, bytes: &[u8]) -> ContentDigest {
        let pin = ContentDigest::sha256(bytes);
        lease
            .ingest(bytes, pin, bytes.len() as u64)
            .unwrap();
        pin
    }
    fn artifact(content: &[u8]) -> Vec<u8> {
        let mut bytes = crate::result::artifact::HEADER.to_vec();
        bytes.extend(1_u32.to_le_bytes());
        bytes.extend(4_u16.to_le_bytes());
        bytes.extend(b"data");
        bytes.push(0);
        bytes.extend((content.len() as u64).to_le_bytes());
        bytes.extend(content);
        bytes
    }
    fn fixture(lease: &crate::store::OperationLease) -> (Action, Receipt, ResultManifest) {
        let first = ingest(lease, &artifact(b"selected"));
        let second = ingest(lease, &artifact(b"sibling"));
        let logical = ContentDigest::sha256(b"logical identity without CAS object");
        let text = format!(
            "syrox-result-v2\n{{\"outputs\":{{\"data\":{{\"action\":\"{logical}\",\"output\":\"out\",\"artifact\":\"{first}\",\"files\":1}},\"sibling\":{{\"action\":\"{logical}\",\"output\":\"dev\",\"artifact\":\"{second}\",\"files\":1}}}},\"commands\":{{}}}}\n"
        );
        let manifest = ResultManifest::parse(text.as_bytes()).unwrap();
        let pin = ingest(lease, &manifest.encode().unwrap());
        let mut action = super::super::cache::tests::action();
        action.inputs.push(InputIdentity {
            origin: OutputOrigin::Imported {
                manifest: pin,
            },
            action: logical,
            artifact: first,
            output: "out".into(),
        });
        let receipt = Receipt::new(
            &action,
            ContentDigest::sha256(b"consumer result"),
            1,
        )
        .with_inputs(&action, manifest.references().unwrap())
        .unwrap();
        (action, receipt, manifest)
    }
    #[test]
    fn imported_inputs_verify_all_siblings_without_fabricated_build_records() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::initialize(temporary.path()).unwrap();
        let lease = store.operation().unwrap();
        let (action, receipt, manifest) = fixture(&lease);
        assert!(
            lease
                .verify(action.inputs[0].action)
                .unwrap()
                .is_none()
        );
        receipt
            .verify_inputs(&lease, &action, &Cancellation::default())
            .unwrap();
        assert_eq!(Action::parse(&action.encode()).unwrap(), action);
        let sibling = manifest.outputs()["sibling"].artifact.to_string();
        let path = temporary.path().join(format!(
            "objects/sha256/{}/{sibling}",
            &sibling[..2]
        ));
        std::fs::remove_file(&path).unwrap();
        assert!(
            receipt
                .verify_inputs(&lease, &action, &Cancellation::default())
                .is_err()
        );
        std::fs::write(&path, b"corrupt sibling").unwrap();
        assert!(
            receipt
                .verify_inputs(&lease, &action, &Cancellation::default())
                .is_err()
        );
    }
    #[test]
    fn imported_origin_pin_selection_and_exact_closure_are_authenticated() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::initialize(temporary.path()).unwrap();
        let lease = store.operation().unwrap();
        let (action, receipt, _) = fixture(&lease);
        for change in 0..4 {
            let mut changed = action.clone();
            match change {
                0 => {
                    changed.inputs[0].origin = OutputOrigin::Built {
                        receipt: origin_pin(&action.inputs[0].origin),
                    }
                }
                1 => {
                    changed.inputs[0].origin = OutputOrigin::Imported {
                        manifest: ContentDigest::sha256(b"wrong pin"),
                    }
                }
                2 => changed.inputs[0].output = "dev".into(),
                _ => changed.inputs[0].action = ContentDigest::sha256(b"wrong logical action"),
            }
            assert_ne!(action.digest(), changed.digest());
            assert!(
                receipt
                    .verify_inputs(&lease, &changed, &Cancellation::default())
                    .is_err()
            );
        }
        let mut extra = receipt.clone();
        extra
            .inputs
            .push(ContentDigest::sha256(b"unrelated"));
        extra.inputs.sort();
        assert!(
            extra
                .verify_inputs(&lease, &action, &Cancellation::default())
                .is_err()
        );
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            receipt.verify_inputs(&lease, &action, &cancel),
            Err(BuildError::Cancelled)
        ));
    }

    #[test]
    fn built_provider_keeps_its_transitive_imported_closure_authenticated() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::initialize(temporary.path()).unwrap();
        let lease = store.operation().unwrap();
        let (mut provider, _, manifest) = fixture(&lease);
        provider.program.profile = BuildProfile::Managed;
        provider.toolchain = None;
        provider.source = ingest(&lease, b"producer source");
        let provider_artifact = ingest(&lease, &artifact(b"producer output"));
        let receipt = Receipt::new(&provider, provider_artifact, 1)
            .with_inputs(&provider, manifest.references().unwrap())
            .unwrap();
        ingest(&lease, &provider.encode());
        let pin = ingest(&lease, &receipt.encode());
        let mut consumer = super::super::cache::tests::action();
        consumer.inputs.push(InputIdentity {
            origin: OutputOrigin::Built {
                receipt: pin,
            },
            action: provider.digest(),
            artifact: provider_artifact,
            output: "out".into(),
        });
        let result = Receipt::new(&consumer, ContentDigest::sha256(b"result"), 1)
            .with_inputs(&consumer, receipt.references())
            .unwrap();
        result
            .verify_inputs(&lease, &consumer, &Cancellation::default())
            .unwrap();
        let sibling = manifest.outputs()["sibling"].artifact.to_string();
        std::fs::remove_file(temporary.path().join(format!(
            "objects/sha256/{}/{sibling}",
            &sibling[..2]
        )))
        .unwrap();
        assert!(
            result
                .verify_inputs(&lease, &consumer, &Cancellation::default())
                .is_err()
        );
    }
}
