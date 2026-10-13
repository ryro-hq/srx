use super::{BuildError, BuildResources, relative_path};

pub const MAX_BUILD_PROGRAM_BYTES: usize = 256 * 1024;
const MAX_STEPS: usize = 512;
const MAX_WORD_PARTS: usize = 128;
const MAX_ARGUMENTS: usize = 512;
const MAX_ENV: usize = 128;
const MAX_TEXT: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildProfile {
    HostBootstrap,
    Managed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildSourceFormat {
    Gzip,
    Xz,
    Raw,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildPath {
    Host(String),
    Work(String),
    Source,
    Output {
        name: String,
        path: String,
    },
    Installed {
        name: String,
        path: String,
    },
    Input {
        index: u32,
        path: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildPart {
    Literal(String),
    Path(BuildPath),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildText(pub Vec<BuildPart>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildProcess {
    pub executable: BuildPath,
    pub arguments: Vec<BuildText>,
    pub directory: BuildPath,
    pub environment: Vec<(String, BuildText)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildStep {
    Run(BuildProcess),
    Write {
        path: BuildPath,
        text: BuildText,
        executable: bool,
    },
    Directory(BuildPath),
    Copy {
        source: BuildPath,
        destination: BuildPath,
    },
    Move {
        source: BuildPath,
        destination: BuildPath,
    },
    Extract(BuildPath),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildProgram {
    pub profile: BuildProfile,
    pub resources: BuildResources,
    pub source_format: BuildSourceFormat,
    pub outputs: Vec<String>,
    pub steps: Vec<BuildStep>,
}

impl BuildPath {
    fn valid(&self, outputs: &[String]) -> bool {
        let relative = |path: &str| path.is_empty() || relative_path(path);
        match self {
            Self::Host(path) => ["/usr/", "/bin/"].iter().any(|prefix| {
                path.strip_prefix(prefix)
                    .is_some_and(relative_path)
            }),
            Self::Work(path) => relative(path),
            Self::Source => true,
            Self::Output {
                name,
                path,
            }
            | Self::Installed {
                name,
                path,
            } => outputs.contains(name) && relative(path),
            Self::Input {
                index,
                path,
            } => *index < 64 && relative(path),
        }
    }
    fn writable(&self) -> bool {
        matches!(self, Self::Work(_) | Self::Output { .. })
    }
}

impl BuildProgram {
    pub fn validate(&self) -> Result<(), BuildError> {
        if self.outputs.is_empty()
            || self.outputs.len() > 9
            || !self.outputs.iter().any(|name| name == "out")
            || self
                .outputs
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.outputs.iter().any(|name| {
                name.is_empty()
                    || name.len() > 32
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || self.steps.is_empty()
            || self.steps.len() > MAX_STEPS
        {
            return Err(BuildError::InvalidRequest);
        }
        let path = |path: &BuildPath| {
            path.valid(&self.outputs)
                && (self.profile != BuildProfile::Managed || !matches!(path, BuildPath::Host(_)))
        };
        let writable = |value: &BuildPath| path(value) && value.writable();
        let text = |value: &BuildText| {
            value.0.len() <= MAX_WORD_PARTS
                && value.0.iter().all(|part| match part {
                    BuildPart::Literal(text) => text.len() <= MAX_TEXT && !text.contains('\0'),
                    BuildPart::Path(value) => path(value),
                })
        };
        for step in &self.steps {
            let valid = match step {
                BuildStep::Run(process) => {
                    path(&process.executable)
                        && path(&process.directory)
                        && process.arguments.len() <= MAX_ARGUMENTS
                        && process.arguments.iter().all(&text)
                        && process.environment.len() <= MAX_ENV
                        && process
                            .environment
                            .windows(2)
                            .all(|pair| pair[0].0 < pair[1].0)
                        && process
                            .environment
                            .iter()
                            .all(|(key, value)| valid_env(key) && text(value))
                }
                BuildStep::Write {
                    path,
                    text: value,
                    ..
                } => writable(path) && text(value),
                BuildStep::Directory(path) => writable(path),
                BuildStep::Copy {
                    source,
                    destination,
                } => path(source) && writable(destination),
                BuildStep::Move {
                    source,
                    destination,
                } => writable(source) && writable(destination),
                BuildStep::Extract(path) => {
                    writable(path) && self.source_format != BuildSourceFormat::Raw
                }
            };
            if !valid {
                return Err(BuildError::InvalidRequest);
            }
        }
        if self.encoded_size() > MAX_BUILD_PROGRAM_BYTES {
            return Err(BuildError::InvalidRequest);
        }
        Ok(())
    }

    pub(crate) fn encoded_size(&self) -> usize {
        fn path(path: &BuildPath) -> usize {
            match path {
                BuildPath::Source => 1,
                BuildPath::Host(text) | BuildPath::Work(text) => 5 + text.len(),
                BuildPath::Output {
                    name,
                    path,
                }
                | BuildPath::Installed {
                    name,
                    path,
                } => 9 + name.len() + path.len(),
                BuildPath::Input {
                    path,
                    ..
                } => 9 + path.len(),
            }
        }
        fn text(text: &BuildText) -> usize {
            text.0.iter().fold(4usize, |size, part| {
                size.saturating_add(
                    1 + match part {
                        BuildPart::Literal(value) => 4 + value.len(),
                        BuildPart::Path(value) => path(value),
                    },
                )
            })
        }
        let header = self.outputs.iter().fold(20usize, |size, name| {
            size.saturating_add(4 + name.len())
        });
        self.steps.iter().fold(header, |size, step| {
            size.saturating_add(
                1 + match step {
                    BuildStep::Run(process) => process
                        .arguments
                        .iter()
                        .fold(
                            path(&process.executable) + path(&process.directory) + 8,
                            |size, word| size.saturating_add(text(word)),
                        )
                        .saturating_add(
                            process
                                .environment
                                .iter()
                                .fold(0usize, |size, (key, word)| {
                                    size.saturating_add(4 + key.len() + text(word))
                                }),
                        ),
                    BuildStep::Write {
                        path: destination,
                        text: word,
                        ..
                    } => path(destination) + text(word) + 1,
                    BuildStep::Directory(value) | BuildStep::Extract(value) => path(value),
                    BuildStep::Copy {
                        source,
                        destination,
                    }
                    | BuildStep::Move {
                        source,
                        destination,
                    } => path(source) + path(destination),
                },
            )
        })
    }

    pub fn input_indices(&self) -> std::collections::BTreeSet<u32> {
        let mut inputs = std::collections::BTreeSet::new();
        self.visit_paths(|path| {
            if let BuildPath::Input {
                index,
                ..
            } = path
            {
                inputs.insert(*index);
            }
        });
        inputs
    }

    fn visit_paths<'a>(&'a self, mut visit: impl FnMut(&'a BuildPath)) {
        fn text<'a>(value: &'a BuildText, visit: &mut impl FnMut(&'a BuildPath)) {
            for part in &value.0 {
                if let BuildPart::Path(path) = part {
                    visit(path);
                }
            }
        }
        for step in &self.steps {
            match step {
                BuildStep::Run(process) => {
                    visit(&process.executable);
                    visit(&process.directory);
                    for word in &process.arguments {
                        text(word, &mut visit);
                    }
                    for (_, word) in &process.environment {
                        text(word, &mut visit);
                    }
                }
                BuildStep::Write {
                    path,
                    text: word,
                    ..
                } => {
                    visit(path);
                    text(word, &mut visit);
                }
                BuildStep::Directory(path) | BuildStep::Extract(path) => visit(path),
                BuildStep::Copy {
                    source,
                    destination,
                }
                | BuildStep::Move {
                    source,
                    destination,
                } => {
                    visit(source);
                    visit(destination);
                }
            }
        }
    }

    /// Canonical versioned encoding; graph-local IDs and resolved mount paths are absent.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Encoder(b"SRXBUILD\x02".to_vec());
        out.byte(match self.profile {
            BuildProfile::HostBootstrap => 0,
            BuildProfile::Managed => 1,
        });
        out.byte(match self.resources {
            BuildResources::Standard => 0,
            BuildResources::Large => 1,
        });
        out.byte(match self.source_format {
            BuildSourceFormat::Gzip => 0,
            BuildSourceFormat::Xz => 1,
            BuildSourceFormat::Raw => 2,
        });
        out.count(self.outputs.len());
        for name in &self.outputs {
            out.string(name);
        }
        out.count(self.steps.len());
        for step in &self.steps {
            match step {
                BuildStep::Run(process) => {
                    out.byte(0);
                    out.path(&process.executable);
                    out.path(&process.directory);
                    out.count(process.arguments.len());
                    for word in &process.arguments {
                        out.text(word);
                    }
                    out.count(process.environment.len());
                    for (key, word) in &process.environment {
                        out.string(key);
                        out.text(word);
                    }
                }
                BuildStep::Write {
                    path,
                    text,
                    executable,
                } => {
                    out.byte(1);
                    out.path(path);
                    out.text(text);
                    out.byte(u8::from(*executable));
                }
                BuildStep::Directory(path) => {
                    out.byte(2);
                    out.path(path);
                }
                BuildStep::Copy {
                    source,
                    destination,
                } => {
                    out.byte(3);
                    out.path(source);
                    out.path(destination);
                }
                BuildStep::Move {
                    source,
                    destination,
                } => {
                    out.byte(4);
                    out.path(source);
                    out.path(destination);
                }
                BuildStep::Extract(path) => {
                    out.byte(5);
                    out.path(path);
                }
            }
        }
        out.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BuildError> {
        if bytes.len() > MAX_BUILD_PROGRAM_BYTES {
            return Err(BuildError::InvalidRequest);
        }
        let mut input = Decoder(
            bytes
                .strip_prefix(b"SRXBUILD\x02")
                .ok_or(BuildError::InvalidRequest)?,
        );
        let profile = match input.byte()? {
            0 => BuildProfile::HostBootstrap,
            1 => BuildProfile::Managed,
            _ => return Err(BuildError::InvalidRequest),
        };
        let resources = match input.byte()? {
            0 => BuildResources::Standard,
            1 => BuildResources::Large,
            _ => return Err(BuildError::InvalidRequest),
        };
        let source_format = match input.byte()? {
            0 => BuildSourceFormat::Gzip,
            1 => BuildSourceFormat::Xz,
            2 => BuildSourceFormat::Raw,
            _ => return Err(BuildError::InvalidRequest),
        };
        let mut outputs = Vec::new();
        for _ in 0..input.count(9)? {
            outputs.push(input.string()?);
        }
        let mut steps = Vec::new();
        for _ in 0..input.count(MAX_STEPS)? {
            steps.push(match input.byte()? {
                0 => {
                    let executable = input.path()?;
                    let directory = input.path()?;
                    let mut arguments = Vec::new();
                    for _ in 0..input.count(MAX_ARGUMENTS)? {
                        arguments.push(input.text()?);
                    }
                    let mut environment = Vec::new();
                    for _ in 0..input.count(MAX_ENV)? {
                        environment.push((input.string()?, input.text()?));
                    }
                    BuildStep::Run(BuildProcess {
                        executable,
                        arguments,
                        directory,
                        environment,
                    })
                }
                1 => BuildStep::Write {
                    path: input.path()?,
                    text: input.text()?,
                    executable: match input.byte()? {
                        0 => false,
                        1 => true,
                        _ => return Err(BuildError::InvalidRequest),
                    },
                },
                2 => BuildStep::Directory(input.path()?),
                3 => BuildStep::Copy {
                    source: input.path()?,
                    destination: input.path()?,
                },
                4 => BuildStep::Move {
                    source: input.path()?,
                    destination: input.path()?,
                },
                5 => BuildStep::Extract(input.path()?),
                _ => return Err(BuildError::InvalidRequest),
            });
        }
        let program = Self {
            profile,
            resources,
            source_format,
            outputs,
            steps,
        };
        if !input.0.is_empty() {
            return Err(BuildError::InvalidRequest);
        }
        program.validate()?;
        Ok(program)
    }
}

fn valid_env(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

struct Encoder(Vec<u8>);
impl Encoder {
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    fn count(&mut self, value: usize) {
        self.0.extend(
            u32::try_from(value)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
    }
    fn string(&mut self, value: &str) {
        self.count(value.len());
        self.0.extend(value.as_bytes());
    }
    fn path(&mut self, path: &BuildPath) {
        match path {
            BuildPath::Host(value) => {
                self.byte(0);
                self.string(value);
            }
            BuildPath::Work(value) => {
                self.byte(1);
                self.string(value);
            }
            BuildPath::Source => self.byte(2),
            BuildPath::Output {
                name,
                path,
            } => {
                self.byte(3);
                self.string(name);
                self.string(path);
            }
            BuildPath::Installed {
                name,
                path,
            } => {
                self.byte(4);
                self.string(name);
                self.string(path);
            }
            BuildPath::Input {
                index,
                path,
            } => {
                self.byte(5);
                self.count(*index as usize);
                self.string(path);
            }
        }
    }
    fn text(&mut self, value: &BuildText) {
        self.count(value.0.len());
        for part in &value.0 {
            match part {
                BuildPart::Literal(value) => {
                    self.byte(0);
                    self.string(value);
                }
                BuildPart::Path(path) => {
                    self.byte(1);
                    self.path(path);
                }
            }
        }
    }
}
struct Decoder<'a>(&'a [u8]);
impl Decoder<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], BuildError> {
        let (head, tail) = self
            .0
            .split_at_checked(count)
            .ok_or(BuildError::InvalidRequest)?;
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, BuildError> {
        Ok(self.take(1)?[0])
    }
    fn count(&mut self, maximum: usize) -> Result<usize, BuildError> {
        let value = u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| BuildError::InvalidRequest)?,
        ) as usize;
        if value > maximum {
            return Err(BuildError::InvalidRequest);
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<String, BuildError> {
        let len = self.count(MAX_TEXT)?;
        Ok(std::str::from_utf8(self.take(len)?)
            .map_err(|_| BuildError::InvalidRequest)?
            .to_owned())
    }
    fn path(&mut self) -> Result<BuildPath, BuildError> {
        Ok(match self.byte()? {
            0 => BuildPath::Host(self.string()?),
            1 => BuildPath::Work(self.string()?),
            2 => BuildPath::Source,
            3 => BuildPath::Output {
                name: self.string()?,
                path: self.string()?,
            },
            4 => BuildPath::Installed {
                name: self.string()?,
                path: self.string()?,
            },
            5 => BuildPath::Input {
                index: u32::try_from(self.count(63)?).map_err(|_| BuildError::InvalidRequest)?,
                path: self.string()?,
            },
            _ => return Err(BuildError::InvalidRequest),
        })
    }
    fn text(&mut self) -> Result<BuildText, BuildError> {
        let mut parts = Vec::new();
        for _ in 0..self.count(MAX_WORD_PARTS)? {
            parts.push(match self.byte()? {
                0 => BuildPart::Literal(self.string()?),
                1 => BuildPart::Path(self.path()?),
                _ => return Err(BuildError::InvalidRequest),
            });
        }
        Ok(BuildText(parts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_program() -> BuildProgram {
        BuildProgram {
            profile: BuildProfile::HostBootstrap,
            resources: BuildResources::Standard,
            source_format: BuildSourceFormat::Raw,
            outputs: vec!["out".into()],
            steps: vec![BuildStep::Write {
                path: BuildPath::Output {
                    name: "out".into(),
                    path: "data".into(),
                },
                text: BuildText(vec![BuildPart::Literal("data".into())]),
                executable: false,
            }],
        }
    }

    #[test]
    fn program_decoder_refuses_truncation_unknown_versions_and_oversized_counts() {
        let bytes = data_program().encode();
        for end in 0..bytes.len() {
            assert!(BuildProgram::decode(&bytes[..end]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid[8] = 1;
        assert!(BuildProgram::decode(&invalid).is_err());
        invalid = bytes.clone();
        invalid[9] = 255;
        assert!(BuildProgram::decode(&invalid).is_err());
        invalid = bytes.clone();
        invalid[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(BuildProgram::decode(&invalid).is_err());
        invalid = bytes;
        invalid.push(0);
        assert!(BuildProgram::decode(&invalid).is_err());
        invalid.resize(MAX_BUILD_PROGRAM_BYTES + 1, 0);
        assert!(BuildProgram::decode(&invalid).is_err());
    }

    #[test]
    fn individually_valid_steps_cannot_evade_the_aggregate_program_budget() {
        let mut program = data_program();
        program.steps = vec![program.steps[0].clone(); MAX_STEPS];
        assert!(program.validate().is_ok());
        assert_eq!(program.encoded_size(), program.encode().len());
        program.steps.push(program.steps[0].clone());
        assert!(program.validate().is_err());
        program = data_program();
        let BuildStep::Write {
            text,
            ..
        } = &mut program.steps[0]
        else {
            unreachable!()
        };
        text.0 = vec![BuildPart::Literal("x".repeat(MAX_TEXT)); 16];
        assert!(program.encoded_size() > MAX_BUILD_PROGRAM_BYTES);
        assert!(program.validate().is_err());
        assert!(BuildProgram::decode(&program.encode()).is_err());
    }
    #[test]
    fn profiles_are_authenticated_and_managed_rejects_nested_host_paths() {
        let host = data_program();
        let mut managed = host.clone();
        managed.profile = BuildProfile::Managed;
        assert_eq!(
            BuildProgram::decode(&managed.encode()).unwrap(),
            managed
        );
        assert_eq!(managed.encoded_size(), managed.encode().len());
        assert_ne!(
            crate::store::ContentDigest::sha256(&host.encode()),
            crate::store::ContentDigest::sha256(&managed.encode())
        );
        let host_path = BuildPath::Host("/usr/bin/tool".into());
        let host_text = BuildText(vec![BuildPart::Path(host_path.clone())]);
        let process = BuildProcess {
            executable: BuildPath::Input {
                index: 0,
                path: "bin/tool".into(),
            },
            arguments: vec![],
            directory: BuildPath::Work(String::new()),
            environment: vec![],
        };
        let mut executable = process.clone();
        executable.executable = host_path.clone();
        let mut directory = process.clone();
        directory.directory = host_path.clone();
        let mut arguments = process.clone();
        arguments.arguments.push(host_text.clone());
        let mut environment = process;
        environment
            .environment
            .push(("VALUE".into(), host_text.clone()));
        for step in [
            BuildStep::Run(executable),
            BuildStep::Run(directory),
            BuildStep::Run(arguments),
            BuildStep::Run(environment),
            BuildStep::Write {
                path: BuildPath::Work("file".into()),
                text: host_text,
                executable: false,
            },
            BuildStep::Copy {
                source: host_path,
                destination: BuildPath::Work("file".into()),
            },
        ] {
            managed.steps = vec![step.clone()];
            assert!(managed.validate().is_err());
            assert!(BuildProgram::decode(&managed.encode()).is_err());
            let mut bootstrap = host.clone();
            bootstrap.steps = vec![step];
            bootstrap.validate().unwrap();
        }
    }
}
