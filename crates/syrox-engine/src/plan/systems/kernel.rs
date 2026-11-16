use super::{
    BTreeSet, Decoder, PlanError, PlanHostConfiguration, PlanHostMount, PlanKconfigValue,
    PlanKernel, PlanKernelModule, PlanKernelOption, PlanKernelTristate, PlanSysctl, PrimitiveValue,
    Value, absolute, exact_nominal,
};

impl Decoder<'_, '_> {
    pub(super) fn kernel(&mut self, value: &Value) -> Result<PlanKernel, PlanError> {
        let fields = self.fields(
            value,
            "Kernel",
            &[
                "image",
                "modules",
                "headers",
                "configuration",
                "release",
                "kconfig",
                "command_line",
                "load",
                "sysctls",
            ],
        )?;
        let image = self.file(&fields[0].1)?;
        let modules = self.output(&fields[1].1)?;
        let headers = self.output(&fields[2].1)?;
        let configuration = self.file(&fields[3].1)?;
        let release = self.string(&fields[4].1, "KernelRelease")?;
        if release.is_empty()
            || release.len() > 64
            || !release
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        {
            return Err(self.error("kernel.release", "invalid runtime release"));
        }
        let mut symbols = BTreeSet::new();
        let values = self.list(&fields[5].1, "kernel.kconfig", 65536)?;
        let mut kconfig = self
            .budget
            .collection::<PlanKernelOption>(values.len())?;
        for value in values {
            let option = self.fields(value, "KernelOption", &["symbol", "value"])?;
            let symbol = self.string(&option[0].1, "KernelSymbol")?;
            if !symbol.starts_with("CONFIG_")
                || symbol.len() <= 7
                || !symbol
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                || !symbols.insert(symbol.clone())
            {
                return Err(self.error(
                    "kernel.kconfig",
                    "expected unique CONFIG_ symbols",
                ));
            }
            let value = match self.variant(&option[1].1, "KconfigValue")? {
                (0, [value]) => PlanKconfigValue::Boolean(self.boolean(value)?),
                (1, [value]) => {
                    let value = match self.variant(value, "KernelTristate")? {
                        (0, []) => PlanKernelTristate::Disabled,
                        (1, []) => PlanKernelTristate::Module,
                        (2, []) => PlanKernelTristate::Builtin,
                        _ => return Err(self.error("kernel.kconfig", "invalid tristate")),
                    };
                    PlanKconfigValue::Tristate(value)
                }
                (
                    2,
                    [
                        Value::Nominal {
                            ty,
                            value: PrimitiveValue::Int(integer),
                            resource: false,
                        },
                    ],
                ) if exact_nominal(ty, &["std", "system", "KernelInteger"]) => {
                    PlanKconfigValue::Integer(*integer)
                }
                (3, [value]) => {
                    let hex = self.string(value, "SystemText")?;
                    if !hex.strip_prefix("0x").is_some_and(|text| {
                        !text.is_empty()
                            && text.len() <= 16
                            && text.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }) {
                        return Err(self.error(
                            "kernel.kconfig",
                            "expected a bounded 0x hexadecimal value",
                        ));
                    }
                    PlanKconfigValue::Hexadecimal(hex)
                }
                (4, [value]) => PlanKconfigValue::Text(self.string(value, "SystemText")?),
                _ => return Err(self.error("kernel.kconfig", "invalid Kconfig value")),
            };
            kconfig.push(PlanKernelOption {
                symbol,
                value,
            });
        }
        let values = self.list(&fields[6].1, "kernel.command_line", 256)?;
        let mut command_line = self.budget.collection::<String>(values.len())?;
        let mut length = 0;
        for value in values {
            let argument = self.string(value, "KernelArgument")?;
            let key = argument.split('=').next().unwrap_or("");
            if argument.is_empty()
                || key.is_empty()
                || key.starts_with('-')
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                || argument.chars().any(|ch| {
                    ch.is_whitespace() || ch.is_control() || matches!(ch, '\'' | '"' | '\\')
                })
                || [
                    "root",
                    "rootflags",
                    "rootfstype",
                    "ro",
                    "rw",
                    "roothash",
                    "dm",
                    "rd.luks",
                    "rd.lvm",
                    "rd.md",
                    "rd.verity",
                ]
                .contains(&key)
                || [
                    "rd.luks.",
                    "rd.lvm.",
                    "rd.md.",
                    "systemd.verity",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
            {
                return Err(self.error(
                    "kernel.command_line",
                    "invalid token or storage-derived argument",
                ));
            }
            length += argument.len() + 1;
            if length > 4096 {
                return Err(self.error(
                    "kernel.command_line",
                    "command line exceeds 4096 bytes",
                ));
            }
            command_line.push(argument);
        }
        let load = self.modules(&fields[7].1)?;
        let sysctls = self.sysctls(&fields[8].1)?;
        Ok(PlanKernel {
            image,
            modules,
            headers,
            configuration,
            release,
            kconfig,
            command_line,
            load,
            sysctls,
        })
    }

    pub(super) fn sysctls(&mut self, value: &Value) -> Result<Vec<PlanSysctl>, PlanError> {
        let values = self.list(value, "sysctls", 4096)?;
        let mut result = self
            .budget
            .collection::<PlanSysctl>(values.len())?;
        let mut names = BTreeSet::new();
        for value in values {
            let fields = self.fields(value, "SysctlSetting", &["name", "value"])?;
            let name = self.string(&fields[0].1, "SystemName")?;
            let value = self.string(&fields[1].1, "SystemText")?;
            if !name.contains('.')
                || name.len() > 255
                || !name.split('.').all(super::name)
                || !names.insert(name.clone())
                || value.is_empty()
                || value
                    .chars()
                    .any(|ch| ch.is_control() && ch != '\t')
            {
                return Err(self.error(
                    "sysctls",
                    "invalid or duplicate sysctl name/value",
                ));
            }
            result.push(PlanSysctl {
                name,
                value,
            });
        }
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }

    pub(super) fn modules(&mut self, value: &Value) -> Result<Vec<PlanKernelModule>, PlanError> {
        let values = self.list(value, "modules", 4096)?;
        let mut result = self
            .budget
            .collection::<PlanKernelModule>(values.len())?;
        let mut names = BTreeSet::new();
        for value in values {
            let fields = self.fields(value, "KernelModule", &["name", "parameters"])?;
            let name = self.string(&fields[0].1, "SystemName")?;
            if !super::name(&name) || !names.insert(name.replace('-', "_")) {
                return Err(self.error(
                    "modules",
                    "invalid or duplicate normalized module name",
                ));
            }
            let mut parameters = Vec::new();
            let mut keys = BTreeSet::new();
            for parameter in self.list(&fields[1].1, "module.parameters", 128)? {
                self.budget.node::<(String, String)>()?;
                let fields = self.fields(parameter, "ModuleParameter", &["name", "value"])?;
                let key = self.string(&fields[0].1, "SystemName")?;
                let value = self.string(&fields[1].1, "SystemText")?;
                if !super::name(&key)
                    // Linux parameter names treat '-' and '_' as equivalent.
                    || !keys.insert(key.replace('-', "_"))
                    || value.chars().any(char::is_control)
                {
                    return Err(self.error(
                        "module.parameters",
                        "invalid or duplicate module parameter",
                    ));
                }
                parameters.push((key, value));
            }
            parameters.sort();
            result.push(PlanKernelModule {
                name,
                parameters,
            });
        }
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }

    pub(super) fn host(
        &mut self,
        component: &super::super::recipes::Component<'_>,
    ) -> Result<PlanHostConfiguration, PlanError> {
        let fields = self.fields(
            component.value(),
            "HostConfiguration",
            &[
                "sysctls", "modules", "mounts", "services", "kernel",
            ],
        )?;
        let sysctls = self.sysctls(&fields[0].1)?;
        let modules = self.modules(&fields[1].1)?;
        let values = self.list(&fields[2].1, "mounts", 4096)?;
        let mut mounts = self
            .budget
            .collection::<PlanHostMount>(values.len())?;
        let mut targets = BTreeSet::new();
        for value in values {
            let fields = self.fields(
                value,
                "HostMount",
                &[
                    "filesystem_uuid",
                    "target",
                    "filesystem",
                    "read_only",
                ],
            )?;
            let filesystem_uuid = self.string(&fields[0].1, "SystemText")?;
            let target = self.string(&fields[1].1, "SystemPath")?;
            let filesystem = self.filesystem(&fields[2].1)?;
            let widths: &[usize] = match filesystem {
                super::FilesystemKind::Ext4 => &[8, 4, 4, 4, 12],
                super::FilesystemKind::Fat32 => &[4, 4],
            };
            let parts: Vec<_> = filesystem_uuid.split('-').collect();
            if parts.len() != widths.len()
                || !parts.iter().zip(widths).all(|(part, width)| {
                    part.len() == *width && part.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                || !absolute(&target)
                || target == "/"
                || !targets.insert(target.clone())
            {
                return Err(self.error(
                    "mounts",
                    "invalid UUID, target, or repeated mount",
                ));
            }
            mounts.push(PlanHostMount {
                filesystem_uuid,
                target,
                filesystem,
                read_only: self.boolean(&fields[3].1)?,
            });
        }
        let services = self.services(component, &fields[3].1)?;
        let kernel = self
            .optional(&fields[4].1)?
            .map(|value| self.kernel(value))
            .transpose()?;
        // Repeating kernel-level settings at the host level is ambiguous.
        if let Some(kernel) = &kernel
            && (sysctls.iter().any(|setting| {
                kernel
                    .sysctls
                    .iter()
                    .any(|other| other.name == setting.name)
            }) || modules.iter().any(|module| {
                kernel
                    .load
                    .iter()
                    .any(|other| other.name.replace('-', "_") == module.name.replace('-', "_"))
            }))
        {
            return Err(self.error("kernel", "kernel and host selections overlap"));
        }
        mounts.sort_by(|left, right| left.target.cmp(&right.target));
        Ok(PlanHostConfiguration {
            name: self.budget.string(component.name())?,
            sysctls,
            modules,
            mounts,
            services,
            kernel,
        })
    }
}
