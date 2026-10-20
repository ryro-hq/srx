//! Native configuration checks against the exact prepared runtime closure.

use std::collections::BTreeMap;
use std::ffi::OsString;

use super::{DeploymentError, PreparedConsumer};
use crate::{
    cancellation::Cancellation, deployment::shell::files::SessionFiles, plan::PlanCommandArgument,
    runtime::RuntimeConfiguration,
};

pub(super) fn validate(
    prepared: &PreparedConsumer,
    cancellation: &Cancellation,
) -> Result<(), DeploymentError> {
    if prepared
        .consumer()
        .services()
        .iter()
        .all(|service| service.validators().is_empty())
    {
        return Ok(());
    }
    let working_directory = tempfile::tempdir()?;
    let files = SessionFiles::new(prepared.consumer(), cancellation)?;
    let result = (|| {
        for service in prepared.consumer().services() {
            for validator in service.validators() {
                cancellation
                    .check()
                    .map_err(|_| crate::runtime::RuntimeError::Cancelled)?;
                let key = (Some(service.id().to_owned()), validator.clone());
                let invocation = &prepared.invocations()[&key];
                let arguments = invocation
                    .arguments()
                    .iter()
                    .map(|argument| render(argument, service.id()).map(OsString::from))
                    .collect::<Result<Vec<_>, _>>()?;
                let environment = invocation
                    .environment()
                    .iter()
                    .map(|entry| {
                        Ok((
                            entry.name.clone(),
                            render(&entry.value, service.id())?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, DeploymentError>>()?;
                let configuration = RuntimeConfiguration::new(
                    service.id().to_owned(),
                    files.service(service.id())?,
                    environment,
                )?;
                let status = crate::runtime::run_runtime_configured_with_cancellation(
                    invocation.closure(),
                    &arguments,
                    working_directory.path(),
                    &configuration,
                    cancellation,
                )?;
                if !status.success() {
                    return Err(DeploymentError::ConfigurationValidation {
                        service: service.id().to_owned(),
                        command: validator.clone(),
                    });
                }
            }
        }
        Ok(())
    })();
    let cleanup = files.close();
    result?;
    cleanup?;
    Ok(())
}

fn render(argument: &PlanCommandArgument, service: &str) -> Result<String, DeploymentError> {
    match argument {
        PlanCommandArgument::Literal(value) => Ok(value.clone()),
        PlanCommandArgument::File(path) => Ok(format!("/syrox/config/{service}/{path}")),
        _ => Err(DeploymentError::CommandNamespace(
            "validator depends on mutable state or secrets",
        )),
    }
}
