use super::{
    MAX_PLAN_DISPLAY_BYTES, Plan, PlanConsumerKind, PlanError, PlanPackageId, PlanType, PlanValue,
    fmt,
};

impl fmt::Display for Plan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.canonical_display_bytes > MAX_PLAN_DISPLAY_BYTES {
            return Err(fmt::Error);
        }
        let mut formatter = ByteLimitedWriter::new(formatter, self.canonical_display_bytes);
        display_plan(self, &mut formatter)
    }
}

fn display_plan<W: fmt::Write + ?Sized>(plan: &Plan, formatter: &mut W) -> fmt::Result {
    writeln!(formatter, "syrox plan")?;
    write!(formatter, "lock sha256 ")?;
    display_digest(formatter, &plan.lock_digest)?;
    writeln!(formatter)?;
    writeln!(formatter, "policy {}", plan.policy_identity)?;
    if let Some(standard) = &plan.standard_library {
        formatter.write_str("std sha256 ")?;
        display_digest(formatter, &standard.digest)?;
        writeln!(formatter)?;
    } else {
        writeln!(formatter, "std absent")?;
    }
    display_packages(plan, formatter)?;
    writeln!(
        formatter,
        "acquisitions {}",
        plan.acquisitions.len()
    )?;
    for acquisition in &plan.acquisitions {
        write!(formatter, "acquisition ")?;
        display_string(formatter, acquisition.package.as_str())?;
        writeln!(
            formatter,
            " sources {}",
            acquisition.sources.len()
        )?;
        display_node_line(formatter, &acquisition.package)?;
        for source in &acquisition.sources {
            formatter.write_str("  source ")?;
            display_string(formatter, &source.url)?;
            writeln!(
                formatter,
                " sha256 {} max {}",
                source.digest, source.maximum_bytes
            )?;
            if source.url.starts_with("project:")
                && let Some(owner) = source.owner
            {
                writeln!(formatter, "    project-domain {}", owner.as_u32())?;
            }
        }
    }
    writeln!(formatter, "builds {}", plan.builds.len())?;
    for build in &plan.builds {
        formatter.write_str("build ")?;
        display_string(formatter, build.package().as_str())?;
        writeln!(formatter, " protocol {}", build.protocol())?;
        display_node_line(formatter, build.package())?;
        formatter.write_str("  source-directory ")?;
        display_string(formatter, build.source_directory())?;
        writeln!(formatter, " timeout {}", build.timeout_seconds())?;
        writeln!(
            formatter,
            "  profile {}",
            match build.program().profile {
                crate::build::BuildProfile::HostBootstrap => "host-bootstrap",
                crate::build::BuildProfile::Managed => "managed",
            }
        )?;
        writeln!(
            formatter,
            "  program {} steps {} outputs {}",
            crate::store::ContentDigest::sha256(&build.program().encode()),
            build.program().steps.len(),
            build.program().outputs.join(" ")
        )?;
        for input in build.inputs() {
            formatter.write_str("  build-input ")?;
            display_string(formatter, input.package.as_str())?;
            write!(formatter, " {}", input.output)?;
            display_node_suffix(formatter, &input.package)?;
        }
    }

    display_imports(plan, formatter)?;
    display_commands(plan, formatter)?;
    display_consumers(plan, formatter)?;
    for root in &plan.roots {
        write!(formatter, "root {}:", root.domain)?;
        display_path(formatter, &root.path)?;
        writeln!(formatter, " ({})", root.name)?;
        writeln!(formatter, "  type: {}", DisplayType(&root.ty))?;
        writeln!(
            formatter,
            "  value: {}",
            DisplayValue(&root.value)
        )?;
        for claim in &root.claims {
            write!(
                formatter,
                "  claim: {} = {} @ {}:",
                DisplayType(&claim.ty),
                DisplayValue(&claim.value),
                claim.scope_root_domain
            )?;
            display_path(formatter, &claim.scope_root_path)?;
            if let Some(name) = &claim.scope_name {
                write!(formatter, "/{name}")?;
            }
            writeln!(formatter, "#{}", claim.boundary)?;
        }
    }
    Ok(())
}

fn display_imports<W: fmt::Write + ?Sized>(plan: &Plan, formatter: &mut W) -> fmt::Result {
    writeln!(formatter, "imports {}", plan.imports.len())?;
    for imported in &plan.imports {
        formatter.write_str("imported ")?;
        display_string(formatter, imported.package().as_str())?;
        display_node_suffix(formatter, imported.package())?;
        formatter.write_str("  root ")?;
        display_string(formatter, imported.root().as_str())?;
        writeln!(formatter, " manifest {}", imported.manifest())?;
        for (output, key) in imported.outputs() {
            formatter.write_str("  output ")?;
            display_string(formatter, output)?;
            formatter.write_str(" key ")?;
            display_string(formatter, key)?;
            writeln!(formatter)?;
        }
    }
    Ok(())
}

fn display_consumers<W: fmt::Write + ?Sized>(plan: &Plan, formatter: &mut W) -> fmt::Result {
    if plan.consumers.is_empty() {
        return Ok(());
    }
    writeln!(
        formatter,
        "consumers {} planned configuration",
        plan.consumers.len()
    )?;
    for consumer in &plan.consumers {
        formatter.write_str("consumer ")?;
        display_string(formatter, consumer.name())?;
        let kind = match consumer.kind() {
            PlanConsumerKind::Os => "Os",
            PlanConsumerKind::Shell => "Shell",
        };
        write!(formatter, " {kind} node {}:", consumer.domain())?;
        display_path(formatter, consumer.path())?;
        writeln!(formatter)?;
        for package in consumer.pkgs() {
            formatter.write_str("  package ")?;
            display_selection(formatter, package)?;
        }
        for service in consumer.services() {
            formatter.write_str("  service ")?;
            display_string(formatter, service.id())?;
            if service.commands().is_empty() && service.processes().is_empty() {
                writeln!(formatter, " configuration-only")?;
            } else {
                writeln!(formatter)?;
            }
            for secret in service.secrets() {
                writeln!(formatter, "    secret {secret}")?;
            }
            if service.state() == super::PlanServiceState::Session {
                writeln!(formatter, "    state session")?;
            }
            for package in service.pkgs() {
                formatter.write_str("    package ")?;
                display_selection(formatter, package)?;
            }
            for command in service.commands() {
                formatter.write_str("    configured command ")?;
                display_string(formatter, command.name())?;
                formatter.write_str(" recipe ")?;
                display_string(formatter, command.command().package.as_str())?;
                display_node_suffix(formatter, &command.command().package)?;
                formatter.write_str(" entry ")?;
                display_string(formatter, &command.command().name)?;
                if let Some(expose) = command.expose() {
                    formatter.write_str(" expose ")?;
                    display_string(formatter, expose)?;
                }
                writeln!(formatter)?;
                for argument in command.arguments() {
                    formatter.write_str("      argument ")?;
                    display_command_argument(formatter, argument)?;
                    writeln!(formatter)?;
                }
                for environment in command.environment() {
                    formatter.write_str("      environment ")?;
                    display_string(formatter, &environment.name)?;
                    formatter.write_str(" = ")?;
                    display_command_argument(formatter, &environment.value)?;
                    writeln!(formatter)?;
                }
            }
            for process in service.processes() {
                formatter.write_str("    process ")?;
                display_string(formatter, &process.id)?;
                formatter.write_str(" command ")?;
                display_string(formatter, &process.command)?;
                match process.restart() {
                    crate::execution::restart::ProcessRestart::Never => {
                        formatter.write_str(" restart never")?;
                    }
                    crate::execution::restart::ProcessRestart::OnFailure(limits) => write!(
                        formatter,
                        " restart on-failure delay {}s window {}s burst {} starts",
                        limits.delay_seconds(),
                        limits.window_seconds(),
                        limits.burst()
                    )?,
                }
                writeln!(formatter)?;
            }
            for validator in service.validators() {
                formatter.write_str("    validator ")?;
                display_string(formatter, validator)?;
                writeln!(formatter)?;
            }
            for file in service.files() {
                formatter.write_str("    planned file ")?;
                display_string(formatter, file.path())?;
                formatter.write_str(" text ")?;
                display_string(formatter, file.text())?;
                writeln!(formatter)?;
            }
        }
    }
    Ok(())
}

fn display_command_argument<W: fmt::Write + ?Sized>(
    formatter: &mut W,
    argument: &super::PlanCommandArgument,
) -> fmt::Result {
    match argument {
        super::PlanCommandArgument::SecretFile(name) => {
            formatter.write_str("secret-file ")?;
            display_string(formatter, name)
        }
        super::PlanCommandArgument::StateDirectory => formatter.write_str("state-directory"),
        super::PlanCommandArgument::Literal(value) => {
            formatter.write_str("literal ")?;
            display_string(formatter, value)
        }
        super::PlanCommandArgument::File(path) => {
            formatter.write_str("file ")?;
            display_string(formatter, path)
        }
    }
}

fn display_packages<W: fmt::Write + ?Sized>(plan: &Plan, formatter: &mut W) -> fmt::Result {
    writeln!(formatter, "package dependency graph")?;
    writeln!(
        formatter,
        "packages {} edges {}",
        plan.packages.len(),
        plan.package_edges
    )?;
    for package in &plan.packages {
        formatter.write_str("package ")?;
        display_string(formatter, package.id.as_str())?;
        if let Some(export) = &package.export {
            formatter.write_str(" export ")?;
            display_string(formatter, export)?;
        }
        writeln!(formatter)?;
        display_node_line(formatter, &package.id)?;
        for alias in &package.aliases {
            formatter.write_str("  alias ")?;
            display_string(formatter, alias)?;
            writeln!(formatter)?;
        }
        for dependency in &package.dependencies {
            formatter.write_str("  dependency ")?;
            display_string(formatter, dependency.as_str())?;
            display_node_suffix(formatter, dependency)?;
        }
    }
    Ok(())
}

fn display_selection<W: fmt::Write + ?Sized>(
    formatter: &mut W,
    selection: &super::PlanPackageSelection,
) -> fmt::Result {
    display_string(formatter, selection.package().as_str())?;
    formatter.write_str(" output ")?;
    display_string(formatter, &selection.output().output)?;
    formatter.write_str(" commands [")?;
    for (index, command) in selection.commands().iter().enumerate() {
        if index != 0 {
            formatter.write_str(", ")?;
        }
        display_string(formatter, command)?;
    }
    formatter.write_str("]")?;
    display_node_suffix(formatter, selection.package())
}

fn display_commands<W: fmt::Write + ?Sized>(plan: &Plan, formatter: &mut W) -> fmt::Result {
    writeln!(formatter, "commands {}", plan.commands.len())?;
    for command in &plan.commands {
        formatter.write_str("command ")?;
        display_string(formatter, command.package().as_str())?;
        formatter.write_str(" name ")?;
        display_string(formatter, command.name())?;
        formatter.write_str(" output ")?;
        display_string(formatter, command.output())?;
        formatter.write_str(" path ")?;
        display_string(formatter, command.path())?;
        display_node_suffix(formatter, command.package())?;
        if let Some(loader) = command.loader() {
            formatter.write_str("  loader ")?;
            display_string(formatter, loader.output.package.as_str())?;
            formatter.write_str(" output ")?;
            display_string(formatter, &loader.output.output)?;
            formatter.write_str(" path ")?;
            display_string(formatter, &loader.path)?;
            display_node_suffix(formatter, &loader.output.package)?;
        }
        for library in command.libraries() {
            formatter.write_str("  library ")?;
            display_string(formatter, library.package.as_str())?;
            formatter.write_str(" output ")?;
            display_string(formatter, &library.output)?;
            display_node_suffix(formatter, &library.package)?;
        }
    }

    Ok(())
}

fn display_digest<W: fmt::Write + ?Sized>(formatter: &mut W, digest: &[u8; 32]) -> fmt::Result {
    for byte in digest {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

fn display_node_suffix<W: fmt::Write + ?Sized>(
    formatter: &mut W,
    id: &PlanPackageId,
) -> fmt::Result {
    write!(formatter, " node {}:", id.domain())?;
    display_path(formatter, id.path())?;
    writeln!(formatter)
}

fn display_node_line<W: fmt::Write + ?Sized>(formatter: &mut W, id: &PlanPackageId) -> fmt::Result {
    formatter.write_str(" ")?;
    display_node_suffix(formatter, id)
}

struct DisplayType<'a>(&'a PlanType);

impl fmt::Display for DisplayType<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            PlanType::Unit => formatter.write_str("unit"),
            PlanType::Int => formatter.write_str("int"),
            PlanType::Str => formatter.write_str("str"),
            PlanType::Nominal {
                domain,
                path,
            } => {
                write!(formatter, "{domain}:")?;
                display_path(formatter, path)
            }
            PlanType::Specialization {
                domain,
                path,
                arguments,
            } => {
                write!(formatter, "{domain}:")?;
                display_path(formatter, path)?;
                formatter.write_str("<")?;
                for (index, argument) in arguments.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{}", DisplayType(argument))?;
                }
                formatter.write_str(">")
            }
            PlanType::List(item) => write!(formatter, "[{}]", DisplayType(item)),
        }
    }
}

struct DisplayValue<'a>(&'a PlanValue);

impl fmt::Display for DisplayValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            PlanValue::Reference {
                domain,
                path,
            } => {
                write!(formatter, "ref({domain}:{})", path.join("::"))
            }
            PlanValue::Unit => formatter.write_str("()"),
            PlanValue::Int(value) => write!(formatter, "{value}"),
            PlanValue::Str(value) => display_string(formatter, value),
            PlanValue::Nominal {
                ty,
                value,
                ..
            } => {
                write!(
                    formatter,
                    "{}({})",
                    DisplayType(ty),
                    DisplayValue(value)
                )
            }
            PlanValue::List {
                items,
                ..
            } => {
                formatter.write_str("[")?;
                display_values(formatter, items)?;
                formatter.write_str("]")
            }
            PlanValue::Struct {
                fields,
                ..
            } => {
                formatter.write_str("{")?;
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{name} = {}", DisplayValue(value))?;
                }
                formatter.write_str("}")
            }
            PlanValue::Variant {
                ty,
                index,
                payload,
            } => {
                write!(formatter, "{}::{index}", DisplayType(ty))?;
                if !payload.is_empty() {
                    formatter.write_str("(")?;
                    for (position, value) in payload.iter().enumerate() {
                        if position > 0 {
                            formatter.write_str(", ")?;
                        }
                        write!(formatter, "{}", DisplayValue(value))?;
                    }
                    formatter.write_str(")")?;
                }
                Ok(())
            }
        }
    }
}

fn display_values(formatter: &mut fmt::Formatter<'_>, values: &[PlanValue]) -> fmt::Result {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            formatter.write_str(", ")?;
        }
        write!(formatter, "{}", DisplayValue(value))?;
    }
    Ok(())
}

fn display_path<W: fmt::Write + ?Sized>(formatter: &mut W, path: &[String]) -> fmt::Result {
    for (index, component) in path.iter().enumerate() {
        if index > 0 {
            formatter.write_str("::")?;
        }
        formatter.write_str(component)?;
    }
    Ok(())
}

fn display_string<W: fmt::Write + ?Sized>(formatter: &mut W, value: &str) -> fmt::Result {
    formatter.write_char('"')?;
    for character in value.chars() {
        match character {
            '"' => formatter.write_str("\\\"")?,
            '\\' => formatter.write_str("\\\\")?,
            '\n' => formatter.write_str("\\n")?,
            '\r' => formatter.write_str("\\r")?,
            '\t' => formatter.write_str("\\t")?,
            character if character.is_control() => {
                for escaped in character.escape_default() {
                    formatter.write_char(escaped)?;
                }
            }
            character => formatter.write_char(character)?,
        }
    }
    formatter.write_char('"')
}

#[derive(Debug)]
struct ByteLimitedWriter<W> {
    inner: W,
    bytes: usize,
    limit: usize,
}

impl<W> ByteLimitedWriter<W> {
    const fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            bytes: 0,
            limit,
        }
    }
}

impl<W: fmt::Write> fmt::Write for ByteLimitedWriter<W> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(bytes) = self.bytes.checked_add(value.len()) else {
            return Err(fmt::Error);
        };
        if bytes > self.limit {
            return Err(fmt::Error);
        }
        self.inner.write_str(value)?;
        self.bytes = bytes;
        Ok(())
    }
}

#[derive(Debug)]
struct ByteCounter {
    bytes: usize,
    limit: usize,
}

impl fmt::Write for ByteCounter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(bytes) = self.bytes.checked_add(value.len()) else {
            return Err(fmt::Error);
        };
        if bytes > self.limit {
            return Err(fmt::Error);
        }
        self.bytes = bytes;
        Ok(())
    }
}

pub(super) fn canonical_display_bytes(plan: &Plan, limit: usize) -> Result<usize, PlanError> {
    let mut counter = ByteCounter {
        bytes: 0,
        limit,
    };
    display_plan(plan, &mut counter).map_err(|_| PlanError::DisplayBytesLimit {
        limit,
    })?;
    Ok(counter.bytes)
}
