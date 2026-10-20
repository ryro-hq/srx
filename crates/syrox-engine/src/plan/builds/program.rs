use super::super::{PlanError, ProjectionBudget, Value, decode_nominal_string, exact_nominal};
use crate::{
    build::BuildPart, build::BuildPath, build::BuildProcess, build::BuildProfile,
    build::BuildProgram, build::BuildResources, build::BuildSourceFormat, build::BuildStep,
    build::BuildText,
};

pub(super) fn decode(
    fields: &[(String, Value)],
    budget: &mut ProjectionBudget,
    invalid: &impl Fn(&'static str) -> PlanError,
) -> Result<BuildProgram, PlanError> {
    let mut decoder = Decoder {
        budget,
        invalid,
    };
    let profile = match decoder.variant(&fields[6].1, "BuildProfile")? {
        (0, []) => BuildProfile::HostBootstrap,
        (1, []) => BuildProfile::Managed,
        _ => return Err(invalid("invalid build profile")),
    };
    let resources = match decoder.variant(&fields[2].1, "BuildResources")? {
        (0, []) => BuildResources::Standard,
        (1, []) => BuildResources::Large,
        _ => return Err(invalid("invalid build resources")),
    };
    let source_format = match decoder.variant(&fields[3].1, "BuildSourceFormat")? {
        (0, []) => BuildSourceFormat::Gzip,
        (1, []) => BuildSourceFormat::Xz,
        (2, []) => BuildSourceFormat::Raw,
        _ => return Err(invalid("invalid build source format")),
    };
    let values = decoder.list(&fields[4].1, 9)?;
    let mut outputs = decoder
        .budget
        .collection::<String>(values.len())?;
    for value in values {
        outputs.push(decoder.string(value, "OutputName")?);
    }
    outputs.sort();
    let values = decoder.list(&fields[5].1, 512)?;
    let mut steps = decoder
        .budget
        .collection::<BuildStep>(values.len())?;
    for value in values {
        steps.push(decoder.step(value)?);
    }
    let program = BuildProgram {
        profile,
        resources,
        source_format,
        outputs,
        steps,
    };
    program
        .validate()
        .map_err(|_| invalid("invalid or oversized build program"))?;
    decoder.budget.bytes(program.encoded_size())?;
    Ok(program)
}

struct Decoder<'a, F> {
    budget: &'a mut ProjectionBudget,
    invalid: &'a F,
}
impl<F: Fn(&'static str) -> PlanError> Decoder<'_, F> {
    fn string(&mut self, value: &Value, name: &str) -> Result<String, PlanError> {
        let text = decode_nominal_string(value, &["std", "pkg", name])
            .ok_or_else(|| (self.invalid)("invalid build string"))?;
        if text.len() > 16 * 1024 {
            return Err((self.invalid)("build string limit exceeded"));
        }
        self.budget.string(text)
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
            && exact_nominal(ty, &["std", "pkg", name])
            && fields.len() == names.len()
            && fields
                .iter()
                .zip(names)
                .all(|((key, _), name)| key == name)
        {
            return Ok(fields);
        }
        Err((self.invalid)("invalid build struct"))
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
            && exact_nominal(ty, &["std", "pkg", name])
        {
            return Ok((*index, payload));
        }
        Err((self.invalid)("invalid build variant"))
    }
    fn list<'a>(&mut self, value: &'a Value, max: usize) -> Result<&'a [Value], PlanError> {
        self.budget.charge_work()?;
        if let Value::List {
            items,
            ..
        } = value
            && items.len() <= max
        {
            return Ok(items);
        }
        Err((self.invalid)("build collection limit exceeded"))
    }
    fn path(&mut self, value: &Value) -> Result<BuildPath, PlanError> {
        self.budget.node::<BuildPath>()?;
        Ok(match self.variant(value, "BuildPath")? {
            (0, [value]) => BuildPath::Host(self.string(value, "BuildHostPath")?),
            (1, [value]) => BuildPath::Work(self.string(value, "BuildRelativePath")?),
            (2, []) => BuildPath::Source,
            (3, [name, path]) => BuildPath::Output {
                name: self.string(name, "OutputName")?,
                path: self.string(path, "BuildRelativePath")?,
            },
            (4, [name, path]) => BuildPath::Installed {
                name: self.string(name, "OutputName")?,
                path: self.string(path, "BuildRelativePath")?,
            },
            (
                5,
                [
                    Value::Nominal {
                        ty,
                        value: syrox_lang::evaluator::PrimitiveValue::Int(index),
                        resource: false,
                    },
                    path,
                ],
            ) if exact_nominal(ty, &["std", "pkg", "BuildInputIndex"]) => BuildPath::Input {
                index: u32::try_from(*index)
                    .map_err(|_| (self.invalid)("invalid build input index"))?,
                path: self.string(path, "BuildRelativePath")?,
            },
            _ => return Err((self.invalid)("invalid build path")),
        })
    }
    fn text(&mut self, value: &Value) -> Result<BuildText, PlanError> {
        let fields = self.fields(value, "BuildText", &["parts"])?;
        let values = self.list(&fields[0].1, 128)?;
        let mut parts = self
            .budget
            .collection::<BuildPart>(values.len())?;
        for value in values {
            parts.push(match self.variant(value, "BuildPart")? {
                (0, [value]) => BuildPart::Literal(self.string(value, "BuildLiteral")?),
                (1, [value]) => BuildPart::Path(self.path(value)?),
                _ => return Err((self.invalid)("invalid build text")),
            });
        }
        Ok(BuildText(parts))
    }
    fn process(&mut self, value: &Value) -> Result<BuildProcess, PlanError> {
        let fields = self.fields(
            value,
            "BuildProcess",
            &[
                "executable",
                "arguments",
                "directory",
                "environment",
            ],
        )?;
        let executable = self.path(&fields[0].1)?;
        let directory = self.path(&fields[2].1)?;
        let values = self.list(&fields[1].1, 512)?;
        let mut arguments = self
            .budget
            .collection::<BuildText>(values.len())?;
        for value in values {
            arguments.push(self.text(value)?);
        }
        let values = self.list(&fields[3].1, 128)?;
        let mut environment = self
            .budget
            .collection::<(String, BuildText)>(values.len())?;
        for value in values {
            let fields = self.fields(value, "BuildEnv", &["name", "text"])?;
            environment.push((
                self.string(&fields[0].1, "BuildEnvName")?,
                self.text(&fields[1].1)?,
            ));
        }
        environment.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(BuildProcess {
            executable,
            arguments,
            directory,
            environment,
        })
    }
    fn step(&mut self, value: &Value) -> Result<BuildStep, PlanError> {
        self.budget.node::<BuildStep>()?;
        Ok(match self.variant(value, "BuildStep")? {
            (0, [value]) => BuildStep::Run(self.process(value)?),
            (1, [value]) => {
                let fields = self.fields(value, "BuildFile", &["path", "text", "mode"])?;
                let executable = match self.variant(&fields[2].1, "BuildFileMode")? {
                    (0, []) => false,
                    (1, []) => true,
                    _ => return Err((self.invalid)("invalid build file mode")),
                };
                BuildStep::Write {
                    path: self.path(&fields[0].1)?,
                    text: self.text(&fields[1].1)?,
                    executable,
                }
            }
            (2, [value]) => BuildStep::Directory(self.path(value)?),
            (3, [source, destination]) => BuildStep::Copy {
                source: self.path(source)?,
                destination: self.path(destination)?,
            },
            (4, [source, destination]) => BuildStep::Move {
                source: self.path(source)?,
                destination: self.path(destination)?,
            },
            (5, [value]) => BuildStep::Extract(self.path(value)?),
            (6, [value]) => BuildStep::ValidateStaticElf(self.path(value)?),
            (7, [path, expected, interpreter]) => BuildStep::ReplaceShebang {
                path: self.path(path)?,
                expected: self.string(expected, "BuildLiteral")?,
                interpreter: self.path(interpreter)?,
            },
            _ => return Err((self.invalid)("invalid build step")),
        })
    }
}
