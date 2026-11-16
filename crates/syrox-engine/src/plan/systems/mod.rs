//! Pure system and adoption contracts, separate from unprivileged consumers.

use super::{
    AuthenticatedStandardLibrary, CanonicalType, PlanConsumer, PlanConsumerKind, PlanError,
    PlanOutputRef, PrimitiveValue, ProjectionBudget, Value,
    consumers::{self, SelectionIndex},
    decode_nominal_string, decode_output_ref, exact_nominal,
};
use crate::system::{
    budget::BuildBudget,
    image::FileMetadata,
    storage::{FilesystemKind, StorageLayout},
};
use std::collections::BTreeSet;

mod kernel;
mod storage;
mod system;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemFile {
    pub output: PlanOutputRef,
    pub path: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemDirectory {
    pub path: String,
    pub metadata: FileMetadata,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemExposure {
    pub source: PlanSystemFile,
    pub destination: String,
    pub metadata: FileMetadata,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemLink {
    pub path: String,
    pub target: String,
    pub uid: u32,
    pub gid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemLayout {
    pub directories: Vec<PlanSystemDirectory>,
    pub exposures: Vec<PlanSystemExposure>,
    pub links: Vec<PlanSystemLink>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSysctl {
    pub name: String,
    pub value: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanKernelModule {
    pub name: String,
    pub parameters: Vec<(String, String)>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanKernelTristate {
    Disabled,
    Module,
    Builtin,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanKconfigValue {
    Boolean(bool),
    Tristate(PlanKernelTristate),
    Integer(i64),
    Hexadecimal(String),
    Text(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanKernelOption {
    pub symbol: String,
    pub value: PlanKconfigValue,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanKernel {
    pub image: PlanSystemFile,
    pub modules: PlanOutputRef,
    pub headers: PlanOutputRef,
    pub configuration: PlanSystemFile,
    pub release: String,
    pub kconfig: Vec<PlanKernelOption>,
    pub command_line: Vec<String>,
    pub load: Vec<PlanKernelModule>,
    pub sysctls: Vec<PlanSysctl>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanHostMount {
    pub filesystem_uuid: String,
    pub target: String,
    pub filesystem: FilesystemKind,
    pub read_only: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanHostConfiguration {
    pub name: String,
    pub sysctls: Vec<PlanSysctl>,
    pub modules: Vec<PlanKernelModule>,
    pub mounts: Vec<PlanHostMount>,
    pub services: PlanConsumer,
    pub kernel: Option<PlanKernel>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystem {
    pub name: String,
    pub kernel: PlanKernel,
    pub userspace: Vec<PlanOutputRef>,
    pub identity: PlanSystemIdentity,
    pub layout: PlanSystemLayout,
    pub storage: StorageLayout,
    pub root_a: String,
    pub root_b: String,
    pub esp: Vec<String>,
    pub persistent: Vec<PlanPersistentVolume>,
    pub boot: PlanSystemBoot,
    pub health: PlanSystemHealth,
    pub budget: BuildBudget,
    pub services: PlanConsumer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemIdentity {
    pub hostname: String,
    pub users: Vec<PlanSystemUser>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub authorized_keys: Vec<String>,
    /// Private credential lookup name, never a password or key payload.
    pub password_credential: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemBoot {
    pub signing_credential: String,
    pub attempts: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSystemHealth {
    pub timeout_seconds: u32,
    pub essential_services: Vec<String>,
    pub require_network: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanDataCompatibility {
    Shared,
    Versioned(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanPersistentVolume {
    pub filesystem: String,
    pub target: String,
    pub compatibility: PlanDataCompatibility,
}

pub(super) fn extract(
    components: &[super::recipes::Component<'_>],
    index: &SelectionIndex<'_>,
    standard: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<(Vec<PlanSystem>, Vec<PlanHostConfiguration>), PlanError> {
    let mut systems = Vec::new();
    let mut hosts = Vec::new();
    if standard.is_none() {
        return Ok((systems, hosts));
    }
    for component in components {
        budget.charge_work()?;
        if component.reference().is_some() || !component.belongs_to_plan() {
            continue;
        }
        let ty = component.ty();
        let is_system = exact_nominal(ty, &["std", "system", "System"]);
        let is_host = exact_nominal(ty, &["std", "system", "HostConfiguration"]);
        if !is_system && !is_host {
            continue;
        }
        let mut decoder = Decoder {
            name: component.name(),
            index,
            budget,
        };
        if is_system {
            decoder.budget.node::<PlanSystem>()?;
            systems.push(decoder.system(component)?);
        } else {
            decoder.budget.node::<PlanHostConfiguration>()?;
            hosts.push(decoder.host(component)?);
        }
    }
    systems.sort_by(|left, right| left.name.cmp(&right.name));
    hosts.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((systems, hosts))
}

struct Decoder<'a, 'b> {
    name: &'a str,
    index: &'a SelectionIndex<'b>,
    budget: &'a mut ProjectionBudget,
}
impl Decoder<'_, '_> {
    fn error(&self, field: &str, reason: impl Into<String>) -> PlanError {
        PlanError::InvalidSystem {
            root: self.name.into(),
            field: field.into(),
            reason: reason.into(),
        }
    }
    fn fields<'a>(
        &mut self,
        value: &'a Value,
        name: &str,
        names: &[&str],
    ) -> Result<&'a [(String, Value)], PlanError> {
        self.budget.charge_work()?;
        if let Value::Struct {
            ty,
            fields,
            ..
        } = value
            && exact_nominal(ty, &["std", "system", name])
            && fields
                .iter()
                .map(|(name, _)| name.as_str())
                .eq(names.iter().copied())
        {
            return Ok(fields);
        }
        Err(self.error(name, "unexpected contract fields"))
    }
    fn list<'a>(
        &mut self,
        value: &'a Value,
        field: &str,
        max: usize,
    ) -> Result<&'a [Value], PlanError> {
        self.budget.charge_work()?;
        if let Value::List {
            items,
            ..
        } = value
            && items.len() <= max
        {
            return Ok(items);
        }
        Err(self.error(field, "collection limit exceeded"))
    }
    fn string(&mut self, value: &Value, kind: &str) -> Result<String, PlanError> {
        let text = decode_nominal_string(value, &["std", "system", kind])
            .ok_or_else(|| self.error(kind, "expected a typed string"))?;
        if text.len() > 4096 || text.contains('\0') {
            return Err(self.error(kind, "invalid or oversized text"));
        }
        self.budget.string(text)
    }
    fn number(&mut self, value: &Value, kind: &str) -> Result<u64, PlanError> {
        self.budget.charge_work()?;
        if let Value::Nominal {
            ty,
            value: PrimitiveValue::Int(number),
            resource: false,
        } = value
            && exact_nominal(ty, &["std", "system", kind])
        {
            return u64::try_from(*number)
                .map_err(|_| self.error(kind, "expected a nonnegative integer"));
        }
        Err(self.error(kind, "expected a typed integer"))
    }
    fn u32(&mut self, value: &Value, kind: &str) -> Result<u32, PlanError> {
        let number = self.number(value, kind)?;
        u32::try_from(number).map_err(|_| self.error(kind, "integer exceeds u32"))
    }
    fn variant<'a>(
        &mut self,
        value: &'a Value,
        name: &str,
    ) -> Result<(u32, &'a [Value]), PlanError> {
        self.budget.charge_work()?;
        if let Value::Variant {
            ty,
            index,
            payload,
        } = value
            && exact_nominal(ty, &["std", "system", name])
        {
            return Ok((*index, payload));
        }
        Err(self.error(name, "expected a typed variant"))
    }
    fn boolean(&mut self, value: &Value) -> Result<bool, PlanError> {
        self.budget.charge_work()?;
        if let Value::Variant {
            ty,
            index,
            payload,
        } = value
            && exact_nominal(ty, &["std", "Bool"])
            && payload.is_empty()
        {
            return match index {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(self.error("Bool", "invalid boolean")),
            };
        }
        Err(self.error("Bool", "expected a typed boolean"))
    }
    fn optional<'a>(&mut self, value: &'a Value) -> Result<Option<&'a Value>, PlanError> {
        self.budget.charge_work()?;
        if let Value::Variant {
            ty,
            index,
            payload,
        } = value
            && matches!(ty.as_ref(), CanonicalType::Specialization { template, arguments } if template.domain() == syrox_lang::source::SourceDomainId::standard_library() && template.path() == ["std", "option", "Option"] && arguments.len() == 1)
        {
            return match (*index, payload.as_slice()) {
                (0, []) => Ok(None),
                (1, [value]) => Ok(Some(value)),
                _ => Err(self.error("Option", "unexpected variant")),
            };
        }
        Err(self.error("Option", "expected a typed option"))
    }
    fn output(&mut self, value: &Value) -> Result<PlanOutputRef, PlanError> {
        let (reference, name) = decode_output_ref(value)
            .ok_or_else(|| self.error("output", "expected a typed output reference"))?;
        let package = self
            .index
            .references
            .get(reference)
            .ok_or_else(|| self.error("output", "missing selected recipe"))?;
        if !self.index.builds.iter().any(|build| {
            build.package() == package
                && build
                    .program()
                    .outputs
                    .iter()
                    .any(|output| output == name)
        }) && !self
            .index
            .imports
            .iter()
            .any(|import| import.package() == package && import.outputs().contains_key(name))
        {
            return Err(self.error(
                "output",
                "output is not declared by the selected recipe",
            ));
        }
        self.budget.node::<PlanOutputRef>()?;
        Ok(PlanOutputRef {
            package: package.copy(self.budget)?,
            output: self.budget.string(name)?,
        })
    }
    fn file(&mut self, value: &Value) -> Result<PlanSystemFile, PlanError> {
        let fields = self.fields(value, "SystemFileSource", &["output", "path"])?;
        let output = self.output(&fields[0].1)?;
        let path = self.string(&fields[1].1, "SystemPath")?;
        if !relative(&path) {
            return Err(self.error(
                "source.path",
                "expected a canonical component-relative path",
            ));
        }
        Ok(PlanSystemFile {
            output,
            path,
        })
    }
    fn build_budget(&mut self, value: &Value) -> Result<BuildBudget, PlanError> {
        let fields = self.fields(
            value,
            "SystemBuildBudget",
            &[
                "memory_bytes",
                "cpu_percent",
                "processes",
                "descriptors",
                "scratch_bytes",
                "files",
                "output_bytes",
                "duration_seconds",
            ],
        )?;
        let budget = BuildBudget {
            memory_bytes: self.number(&fields[0].1, "SystemBytes")?,
            cpu_percent: self.u32(&fields[1].1, "SystemCount")?,
            processes: self.u32(&fields[2].1, "SystemCount")?,
            descriptors: self.u32(&fields[3].1, "SystemCount")?,
            scratch_bytes: self.number(&fields[4].1, "SystemBytes")?,
            files: self.number(&fields[5].1, "SystemCount")?,
            output_bytes: self.number(&fields[6].1, "SystemBytes")?,
            duration_seconds: self.u32(&fields[7].1, "SystemSeconds")?,
        };
        budget
            .validate()
            .map_err(|error| self.error("budget", error.to_string()))?;
        Ok(budget)
    }
    fn services(
        &mut self,
        component: &super::recipes::Component<'_>,
        value: &Value,
    ) -> Result<PlanConsumer, PlanError> {
        consumers::consumer(
            component.name(),
            component.identity(),
            PlanConsumerKind::Services,
            value,
            self.index,
            self.budget,
        )
    }
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.split('/').all(|part| {
            !part.is_empty() && !matches!(part, "." | "..") && !part.chars().any(char::is_control)
        })
}
fn absolute(path: &str) -> bool {
    path == "/" || path.strip_prefix('/').is_some_and(relative)
}
fn name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
