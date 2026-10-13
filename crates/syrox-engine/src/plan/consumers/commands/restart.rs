use super::{ErrorContext, PlanError, ProjectionBudget, Value, exact_nominal, fields};
use crate::plan::PrimitiveValue;
use crate::{execution::restart::ProcessRestart, execution::restart::RestartLimits};

pub(super) fn decode(
    value: &Value,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<ProcessRestart, PlanError> {
    budget.charge_work()?;
    let Value::Variant {
        ty,
        index,
        payload,
    } = value
    else {
        return context.invalid("expected authenticated ProcessRestart", budget);
    };
    if !exact_nominal(ty, &["std", "deployment", "ProcessRestart"]) {
        return context.invalid("expected authenticated ProcessRestart", budget);
    }
    match (*index, payload.as_slice()) {
        (0, []) => Ok(ProcessRestart::Never),
        (1, [limits]) => {
            let values = fields(
                limits,
                &["std", "deployment", "RestartLimits"],
                &[
                    "delay_seconds",
                    "window_seconds",
                    "burst",
                ],
                context,
                budget,
            )?;
            let mut numbers = [0; 3];
            for ((_, value), (number, nominal)) in values.iter().zip(numbers.iter_mut().zip([
                "RestartDelay",
                "RestartWindow",
                "RestartBurst",
            ])) {
                let Value::Nominal {
                    ty,
                    value: PrimitiveValue::Int(value),
                    resource: false,
                } = value
                else {
                    return context.invalid("expected authenticated restart limit", budget);
                };
                if !exact_nominal(ty, &["std", "deployment", nominal]) {
                    return context.invalid("expected authenticated restart limit", budget);
                }
                let Ok(value) = u32::try_from(*value) else {
                    return context.invalid("restart limit is outside its range", budget);
                };
                *number = value;
            }
            match RestartLimits::new(numbers[0], numbers[1], numbers[2]) {
                Ok(limits) => Ok(ProcessRestart::OnFailure(limits)),
                Err(_) => context.invalid(
                    "restart limits require delay 1..300, window 1..3600 >= delay, burst 1..100",
                    budget,
                ),
            }
        }
        _ => context.invalid("invalid ProcessRestart variant", budget),
    }
}
