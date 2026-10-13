use super::{
    Budget, Cancellation, Duration, SystemdError, SystemdManager, SystemdManagerIdentity,
    SystemdUnitName, UNIT_INTERFACE, strict_unit_path,
};

/// Pins a loaded unit's metadata against manager garbage collection.
///
/// This is neither process retention nor proof of ownership, successful execution,
/// or cgroup quiescence. The caller must authenticate the invocation separately.
/// Dropping this handle performs no IPC: release explicitly through the original
/// manager connection, or close that connection. Reconnection cannot adopt it.
#[derive(Debug)]
pub struct SystemdUnitReference {
    unit: SystemdUnitName,
    object: String,
    connection: u64,
    manager: SystemdManagerIdentity,
    release_attempted: bool,
}

impl SystemdUnitReference {
    pub(super) fn object_path(&self) -> &str {
        &self.object
    }
    pub fn unit(&self) -> &SystemdUnitName {
        &self.unit
    }

    pub fn manager_identity(&self) -> &SystemdManagerIdentity {
        &self.manager
    }

    fn check_connection(&self, connection: u64) -> Result<(), SystemdError> {
        if self.release_attempted {
            return Err(SystemdError::Invalid(
                "unit reference release already attempted",
            ));
        }
        if self.connection != connection {
            return Err(SystemdError::Invalid(
                "unit reference belongs to another connection",
            ));
        }
        Ok(())
    }
}

impl SystemdManager {
    /// Reference an existing unit without loading or starting it. A lost reply
    /// leaves the mutation uncertain and invalidates this connection for reuse.
    pub fn reference_unit(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdUnitReference, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let manager = self.observe_identity_with(&budget)?;
        let object = self.reference_object(unit, &budget)?;
        let reference = SystemdUnitReference {
            unit: unit.clone(),
            object,
            connection: self.connection,
            manager,
            release_attempted: false,
        };
        self.reference_call(&reference, "Ref", &budget)?;
        if let Err(error) = self.verify_reference_with(&reference, &budget) {
            return Err(self.uncertain_reference(unit, error));
        }
        Ok(reference)
    }

    /// Keep an inactive persistent unit loaded while its properties are read.
    pub(super) fn load_unit_reference(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<SystemdUnitReference, SystemdError> {
        let manager = self.observe_identity_with(budget)?;
        let mut call = self.bus.manager_method("LoadUnit")?;
        call.string(unit.as_str())?;
        let object = strict_unit_path(
            self.bus
                .call(call, budget)
                .and_then(|mut reply| reply.single_object()),
        )?
        .ok_or(SystemdError::Protocol("loaded unit is absent"))?;
        let reference = SystemdUnitReference {
            unit: unit.clone(),
            object,
            connection: self.connection,
            manager,
            release_attempted: false,
        };
        self.reference_call(&reference, "Ref", budget)?;
        if let Err(error) = self.verify_reference_with(&reference, budget) {
            return Err(self.uncertain_reference(unit, error));
        }
        Ok(reference)
    }

    /// Check connection, manager and loaded object identity. This does not
    /// authenticate an invocation or authorize stopping the unit.
    pub fn verify_unit_reference(
        &mut self,
        reference: &SystemdUnitReference,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        self.verify_reference_with(reference, &Budget::new(timeout, cancellation)?)
    }

    /// Release once on the original connection. A release attempted on the wire
    /// is never retried, including after a lost reply or a remote rejection.
    pub fn unreference_unit(
        &mut self,
        reference: &mut SystemdUnitReference,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        self.verify_reference_with(reference, &budget)?;
        let call = self.bus.method(
            reference.manager.owner(),
            &reference.object,
            UNIT_INTERFACE,
            "Unref",
        )?;
        budget.check()?;
        reference.release_attempted = true;
        let result = self
            .bus
            .call(call, &budget)
            .and_then(|reply| reply.expect_empty());
        self.reference_reply(&reference.unit, result)?;
        // Unref may immediately permit object collection: bracket only manager.
        match self.observe_identity_with(&budget) {
            Ok(identity) if identity == reference.manager => Ok(()),
            Ok(_) => Err(self.uncertain_reference(
                &reference.unit,
                SystemdError::Protocol("manager changed during unit release"),
            )),
            Err(error) => Err(self.uncertain_reference(&reference.unit, error)),
        }
    }

    fn reference_object(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<String, SystemdError> {
        let mut call = self.bus.manager_method("GetUnit")?;
        call.string(unit.as_str())?;
        let object = strict_unit_path(
            self.bus
                .call(call, budget)
                .and_then(|mut reply| reply.single_object()),
        )?
        .ok_or(SystemdError::Protocol(
            "referenced unit is absent",
        ))?;
        if self
            .bus
            .get_string(&object, UNIT_INTERFACE, "Id", budget)?
            != unit.as_str()
        {
            return Err(SystemdError::Protocol(
                "referenced unit identity differs",
            ));
        }
        Ok(object)
    }

    fn verify_reference_with(
        &mut self,
        reference: &SystemdUnitReference,
        budget: &Budget<'_>,
    ) -> Result<(), SystemdError> {
        reference.check_connection(self.connection)?;
        if self.observe_identity_with(budget)? != reference.manager
            || self.reference_object(&reference.unit, budget)? != reference.object
            || self.observe_identity_with(budget)? != reference.manager
        {
            return Err(SystemdError::Protocol(
                "unit reference identity changed",
            ));
        }
        budget.check()
    }

    fn reference_call(
        &mut self,
        reference: &SystemdUnitReference,
        member: &str,
        budget: &Budget<'_>,
    ) -> Result<(), SystemdError> {
        let call = self.bus.method(
            reference.manager.owner(),
            &reference.object,
            UNIT_INTERFACE,
            member,
        )?;
        budget.check()?;
        let result = self
            .bus
            .call(call, budget)
            .and_then(|reply| reply.expect_empty());
        self.reference_reply(&reference.unit, result)
    }

    fn reference_reply(
        &mut self,
        unit: &SystemdUnitName,
        result: Result<(), SystemdError>,
    ) -> Result<(), SystemdError> {
        match result {
            Ok(()) => Ok(()),
            Err(
                error @ SystemdError::Remote {
                    ..
                },
            ) => Err(error),
            Err(error) => Err(self.uncertain_reference(unit, error)),
        }
    }

    fn uncertain_reference(&mut self, unit: &SystemdUnitName, error: SystemdError) -> SystemdError {
        self.bus.invalidate();
        SystemdError::MutationUncertain {
            unit: unit.as_str().into(),
            source: Box::new(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::SystemdScope;

    fn reference() -> SystemdUnitReference {
        SystemdUnitReference {
            unit: SystemdUnitName::new("syrox-reference.service").unwrap(),
            object: "/org/freedesktop/systemd1/unit/syrox_2dreference_2eservice".into(),
            connection: 17,
            manager: SystemdManagerIdentity::new(
                SystemdScope::User {
                    bus_socket: "/run/user/1000/bus".into(),
                },
                "0123456789abcdef0123456789abcdef".into(),
                ":1.9".into(),
            )
            .unwrap(),
            release_attempted: false,
        }
    }

    #[test]
    fn reconnect_cannot_adopt_reference_even_with_same_manager_fingerprint() {
        let reference = reference();
        assert!(reference.check_connection(17).is_ok());
        assert!(matches!(
            reference.check_connection(18),
            Err(SystemdError::Invalid(_))
        ));
        assert_eq!(
            reference.unit().as_str(),
            "syrox-reference.service"
        );
        assert_eq!(reference.manager_identity(), &reference.manager);
    }

    #[test]
    fn attempted_release_is_terminal_even_on_original_connection() {
        let mut reference = reference();
        reference.release_attempted = true;
        assert!(matches!(
            reference.check_connection(17),
            Err(SystemdError::Invalid(_))
        ));
        assert!(matches!(
            reference.check_connection(18),
            Err(SystemdError::Invalid(_))
        ));
    }

    #[test]
    fn absent_and_malformed_objects_cannot_be_referenced() {
        assert!(strict_unit_path(Ok("/org/freedesktop/systemd1/unit/".into())).is_err());
        assert!(strict_unit_path(Ok("/org/freedesktop/systemd1/unit/a/b".into())).is_err());
        assert_eq!(
            strict_unit_path(Err(SystemdError::Remote {
                name: "org.freedesktop.systemd1.NoSuchUnit".into(),
                message: String::new(),
            }))
            .unwrap(),
            None
        );
        assert!(
            strict_unit_path(Err(SystemdError::Remote {
                name: "org.freedesktop.DBus.Error.AccessDenied".into(),
                message: String::new(),
            }))
            .is_err()
        );
    }
}
