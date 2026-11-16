//! Explicit build requests and administrator-owned admission ceilings.
//!
//! Admission is pure. Its token records the policy used to admit every resource;
//! executors must separately enforce the admitted limits and check real capacity.
//! Deserializing a request never grants execution authority or creates a token.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildBudget {
    pub memory_bytes: u64,
    pub cpu_percent: u32,
    pub processes: u32,
    pub descriptors: u32,
    /// Writable intermediate files, separately from final output space.
    pub scratch_bytes: u64,
    /// Inodes in writable build filesystems, including directories and symlinks.
    pub files: u64,
    pub output_bytes: u64,
    pub duration_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    MemoryBytes,
    CpuPercent,
    Processes,
    Descriptors,
    ScratchBytes,
    Files,
    OutputBytes,
    DurationSeconds,
}

impl std::fmt::Display for Resource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MemoryBytes => "memory_bytes",
            Self::CpuPercent => "cpu_percent",
            Self::Processes => "processes",
            Self::Descriptors => "descriptors",
            Self::ScratchBytes => "scratch_bytes",
            Self::Files => "files",
            Self::OutputBytes => "output_bytes",
            Self::DurationSeconds => "duration_seconds",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    #[error("build budget must declare a positive finite limit for {resource}")]
    Zero {
        resource: Resource,
    },
    #[error("combined scratch and output budget overflows u64")]
    StorageOverflow,
    #[error("build budget requests {requested} {resource}, above administrator limit {maximum}")]
    Denied {
        resource: Resource,
        requested: u64,
        maximum: u64,
    },
    #[error("observed capacity for {resource} is {available}, below requested {requested}")]
    Capacity {
        resource: Resource,
        requested: u64,
        available: u64,
    },
    #[error("observed shared scratch/output capacity is {available}, below requested {requested}")]
    StorageCapacity {
        requested: u64,
        available: u64,
    },
}

impl BuildBudget {
    pub fn validate(&self) -> Result<(), BudgetError> {
        for (resource, value) in self.resources() {
            if value == 0 {
                return Err(BudgetError::Zero {
                    resource,
                });
            }
        }
        self.storage_bytes()?;
        Ok(())
    }

    pub fn storage_bytes(&self) -> Result<u64, BudgetError> {
        self.scratch_bytes
            .checked_add(self.output_bytes)
            .ok_or(BudgetError::StorageOverflow)
    }

    fn resources(&self) -> [(Resource, u64); 8] {
        [
            (Resource::MemoryBytes, self.memory_bytes),
            (Resource::CpuPercent, u64::from(self.cpu_percent)),
            (Resource::Processes, u64::from(self.processes)),
            (Resource::Descriptors, u64::from(self.descriptors)),
            (Resource::ScratchBytes, self.scratch_bytes),
            (Resource::Files, self.files),
            (Resource::OutputBytes, self.output_bytes),
            (
                Resource::DurationSeconds,
                u64::from(self.duration_seconds),
            ),
        ]
    }
}

/// An explicit ceiling selected by the builder administrator, never by a recipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderLimits {
    maximum: BuildBudget,
}

impl BuilderLimits {
    pub fn new(maximum: BuildBudget) -> Result<Self, BudgetError> {
        maximum.validate()?;
        Ok(Self {
            maximum,
        })
    }

    pub const fn maximum(&self) -> &BuildBudget {
        &self.maximum
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"syrox-builder-limits-v1\n");
        for (_, value) in self.maximum.resources() {
            hasher.update(value.to_le_bytes());
        }
        hasher.finalize().into()
    }

    pub fn admit(&self, request: BuildBudget) -> Result<AdmittedBudget, BudgetError> {
        request.validate()?;
        for ((resource, requested), (_, maximum)) in request
            .resources()
            .into_iter()
            .zip(self.maximum.resources())
        {
            if requested > maximum {
                return Err(BudgetError::Denied {
                    resource,
                    requested,
                    maximum,
                });
            }
        }
        Ok(AdmittedBudget {
            request,
            policy: self.fingerprint(),
        })
    }
}

/// A current capacity observation, distinct from administrator permission.
/// CPU is a quota percentage; memory and file/inode counts are available amounts.
/// Storage capacity must cover scratch and output together when they share a volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderCapacity {
    pub memory_bytes: u64,
    pub cpu_percent: u32,
    pub processes: u32,
    pub descriptors: u32,
    pub files: u64,
    pub shared_storage_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedBudget {
    request: BuildBudget,
    policy: [u8; 32],
}

impl AdmittedBudget {
    pub const fn request(&self) -> &BuildBudget {
        &self.request
    }
    pub const fn policy_fingerprint(&self) -> &[u8; 32] {
        &self.policy
    }

    /// Recheck observations immediately before allocating work, not only while
    /// planning. The executor remains responsible for kernel-enforced limits.
    pub fn check_capacity(&self, available: BuilderCapacity) -> Result<(), BudgetError> {
        for (resource, requested, available) in [
            (
                Resource::MemoryBytes,
                self.request.memory_bytes,
                available.memory_bytes,
            ),
            (
                Resource::CpuPercent,
                u64::from(self.request.cpu_percent),
                u64::from(available.cpu_percent),
            ),
            (
                Resource::Processes,
                u64::from(self.request.processes),
                u64::from(available.processes),
            ),
            (
                Resource::Descriptors,
                u64::from(self.request.descriptors),
                u64::from(available.descriptors),
            ),
            (
                Resource::Files,
                self.request.files,
                available.files,
            ),
        ] {
            if requested > available {
                return Err(BudgetError::Capacity {
                    resource,
                    requested,
                    available,
                });
            }
        }
        let requested = self.request.storage_bytes()?;
        if requested > available.shared_storage_bytes {
            return Err(BudgetError::StorageCapacity {
                requested,
                available: available.shared_storage_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BuildBudget {
        BuildBudget {
            memory_bytes: 4 * 1024 * 1024 * 1024,
            cpu_percent: 200,
            processes: 512,
            descriptors: 4096,
            scratch_bytes: 16 * 1024 * 1024 * 1024,
            files: 1_000_000,
            output_bytes: 8 * 1024 * 1024 * 1024,
            duration_seconds: 7200,
        }
    }

    fn change(budget: &mut BuildBudget, resource: Resource, value: u64) {
        match resource {
            Resource::MemoryBytes => budget.memory_bytes = value,
            Resource::CpuPercent => budget.cpu_percent = value.try_into().unwrap(),
            Resource::Processes => budget.processes = value.try_into().unwrap(),
            Resource::Descriptors => budget.descriptors = value.try_into().unwrap(),
            Resource::ScratchBytes => budget.scratch_bytes = value,
            Resource::Files => budget.files = value,
            Resource::OutputBytes => budget.output_bytes = value,
            Resource::DurationSeconds => budget.duration_seconds = value.try_into().unwrap(),
        }
    }

    #[test]
    fn every_resource_requires_explicit_positive_limits_and_is_admitted_independently() {
        let requested = request();
        let limits = BuilderLimits::new(requested).unwrap();
        assert_eq!(
            *limits.admit(requested).unwrap().request(),
            requested
        );
        for (resource, value) in requested.resources() {
            let mut invalid = requested;
            change(&mut invalid, resource, 0);
            assert_eq!(
                invalid.validate(),
                Err(BudgetError::Zero {
                    resource
                })
            );
            assert!(BuilderLimits::new(invalid).is_err());
            let mut excessive = requested;
            change(&mut excessive, resource, value + 1);
            assert_eq!(
                limits.admit(excessive),
                Err(BudgetError::Denied {
                    resource,
                    requested: value + 1,
                    maximum: value
                })
            );
        }
    }

    #[test]
    fn policy_identity_binds_every_limit_but_not_the_smaller_request() {
        let maximum = request();
        let limits = BuilderLimits::new(maximum).unwrap();
        for (resource, value) in maximum.resources() {
            let mut smaller = maximum;
            change(&mut smaller, resource, value - 1);
            let admission = limits.admit(smaller).unwrap();
            assert_eq!(
                admission.policy_fingerprint(),
                &limits.fingerprint()
            );
            assert_ne!(
                limits.fingerprint(),
                BuilderLimits::new(smaller).unwrap().fingerprint()
            );
        }
    }

    #[test]
    fn declared_storage_cannot_overflow_or_double_count_shared_available_space() {
        let mut invalid = request();
        invalid.scratch_bytes = u64::MAX;
        assert_eq!(
            invalid.validate(),
            Err(BudgetError::StorageOverflow)
        );
        let admission = BuilderLimits::new(request())
            .unwrap()
            .admit(request())
            .unwrap();
        let available = BuilderCapacity {
            memory_bytes: u64::MAX,
            cpu_percent: u32::MAX,
            processes: u32::MAX,
            descriptors: u32::MAX,
            files: u64::MAX,
            shared_storage_bytes: request()
                .scratch_bytes
                .max(request().output_bytes),
        };
        assert!(matches!(
            admission.check_capacity(available),
            Err(BudgetError::StorageCapacity { .. })
        ));
        let enough = BuilderCapacity {
            shared_storage_bytes: request().storage_bytes().unwrap(),
            ..available
        };
        admission.check_capacity(enough).unwrap();
        for (resource, limited) in [
            (
                Resource::MemoryBytes,
                BuilderCapacity {
                    memory_bytes: request().memory_bytes - 1,
                    ..enough
                },
            ),
            (
                Resource::CpuPercent,
                BuilderCapacity {
                    cpu_percent: request().cpu_percent - 1,
                    ..enough
                },
            ),
            (
                Resource::Processes,
                BuilderCapacity {
                    processes: request().processes - 1,
                    ..enough
                },
            ),
            (
                Resource::Descriptors,
                BuilderCapacity {
                    descriptors: request().descriptors - 1,
                    ..enough
                },
            ),
            (
                Resource::Files,
                BuilderCapacity {
                    files: request().files - 1,
                    ..enough
                },
            ),
        ] {
            assert!(
                matches!(admission.check_capacity(limited), Err(BudgetError::Capacity { resource: observed, .. }) if observed == resource)
            );
        }
    }

    #[test]
    fn serialized_requests_require_all_fields_and_reject_unknown_fields() {
        let value = serde_json::to_value(request()).unwrap();
        assert_eq!(
            serde_json::from_value::<BuildBudget>(value.clone()).unwrap(),
            request()
        );
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("files");
        assert!(serde_json::from_value::<BuildBudget>(missing).is_err());
        let mut unknown = value;
        unknown["unlimited"] = true.into();
        assert!(serde_json::from_value::<BuildBudget>(unknown).is_err());
    }
}
