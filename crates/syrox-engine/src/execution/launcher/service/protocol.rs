use super::{ServiceWorkerError, binding, invalid};
use crate::execution::journal::{AttemptBinding, AttemptId, SessionId};
use crate::store::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceLaunchHello {
    pub session: SessionId,
    pub role: ContentDigest,
    pub generation: ContentDigest,
    pub command: ContentDigest,
    pub binding: AttemptBinding,
    pub owner: AttemptBinding,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceLaunchRequest {
    pub session: SessionId,
    pub role: ContentDigest,
    pub attempt: AttemptId,
    pub generation: ContentDigest,
    pub command: ContentDigest,
    pub binding: AttemptBinding,
    pub owner: AttemptBinding,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceAttemptChallenge {
    pub role: ContentDigest,
    pub attempt: AttemptId,
    pub binding: AttemptBinding,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Hello,
    Request,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    kind: Kind,
    session: String,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<String>,
    generation: String,
    command: String,
    unit: String,
    invocation: [u8; 16],
    owner_unit: String,
    owner_invocation: [u8; 16],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRecord {
    version: u32,
    role: String,
    attempt: String,
    unit: String,
    invocation: [u8; 16],
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, ServiceWorkerError> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid("cannot encode service envelope"))?;
    if bytes.len() > crate::execution::transport::MAX_BYTES {
        return Err(invalid("service envelope exceeded bound"));
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ServiceWorkerError> {
    if bytes.len() > crate::execution::transport::MAX_BYTES {
        return Err(invalid("service envelope exceeded bound"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid("malformed service envelope"))
}
impl ServiceLaunchHello {
    fn record(&self, kind: Kind, attempt: Option<String>) -> Record {
        Record {
            version: 2,
            kind,
            session: self.session.to_string(),
            role: self.role.to_string(),
            attempt,
            generation: self.generation.to_string(),
            command: self.command.to_string(),
            unit: self.binding.unit().as_str().into(),
            invocation: *self.binding.invocation(),
            owner_unit: self.owner.unit().as_str().into(),
            owner_invocation: *self.owner.invocation(),
        }
    }
    fn from_record(record: &Record) -> Result<Self, ServiceWorkerError> {
        if record.version != 2 {
            return Err(invalid("unsupported service request"));
        }
        let hello = Self {
            session: SessionId::parse(&record.session)
                .map_err(|_| invalid("invalid service session"))?,
            role: record
                .role
                .parse()
                .map_err(|_| invalid("invalid role pin"))?,
            generation: record
                .generation
                .parse()
                .map_err(|_| invalid("invalid generation pin"))?,
            command: record
                .command
                .parse()
                .map_err(|_| invalid("invalid command pin"))?,
            binding: binding(&record.unit, record.invocation)?,
            owner: binding(&record.owner_unit, record.owner_invocation)?,
        };
        if hello.binding.unit() == hello.owner.unit() {
            return Err(invalid("service cannot own itself"));
        }
        Ok(hello)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ServiceWorkerError> {
        encode(&self.record(Kind::Hello, None))
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ServiceWorkerError> {
        let record: Record = decode(bytes)?;
        if record.kind != Kind::Hello || record.attempt.is_some() {
            return Err(invalid("expected service hello"));
        }
        let hello = Self::from_record(&record)?;
        if hello.encode()? != bytes {
            return Err(invalid("noncanonical service hello"));
        }
        Ok(hello)
    }
    pub(crate) fn challenged(
        &self,
        challenge: &ServiceAttemptChallenge,
    ) -> Result<ServiceLaunchRequest, ServiceWorkerError> {
        if challenge.role != self.role || challenge.binding != self.binding {
            return Err(invalid("service challenge differs"));
        }
        Ok(ServiceLaunchRequest {
            session: self.session.clone(),
            role: self.role,
            attempt: challenge.attempt.clone(),
            generation: self.generation,
            command: self.command,
            binding: self.binding.clone(),
            owner: self.owner.clone(),
        })
    }
}
impl ServiceLaunchRequest {
    pub(crate) fn hello(&self) -> ServiceLaunchHello {
        ServiceLaunchHello {
            session: self.session.clone(),
            role: self.role,
            generation: self.generation,
            command: self.command,
            binding: self.binding.clone(),
            owner: self.owner.clone(),
        }
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ServiceWorkerError> {
        encode(
            &self
                .hello()
                .record(Kind::Request, Some(self.attempt.to_string())),
        )
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ServiceWorkerError> {
        let record: Record = decode(bytes)?;
        if record.kind != Kind::Request {
            return Err(invalid("expected challenged service request"));
        }
        let hello = ServiceLaunchHello::from_record(&record)?;
        let attempt = AttemptId::parse(
            record
                .attempt
                .as_deref()
                .ok_or_else(|| invalid("missing service attempt"))?,
        )
        .map_err(|_| invalid("invalid service attempt"))?;
        let request = hello.challenged(&ServiceAttemptChallenge {
            role: hello.role,
            attempt,
            binding: hello.binding.clone(),
        })?;
        if request.encode()? != bytes {
            return Err(invalid("noncanonical service request"));
        }
        Ok(request)
    }
}
impl ServiceAttemptChallenge {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ServiceWorkerError> {
        encode(&ChallengeRecord {
            version: 2,
            role: self.role.to_string(),
            attempt: self.attempt.to_string(),
            unit: self.binding.unit().as_str().into(),
            invocation: *self.binding.invocation(),
        })
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ServiceWorkerError> {
        let record: ChallengeRecord = decode(bytes)?;
        if record.version != 2 {
            return Err(invalid("unsupported service challenge"));
        }
        let challenge = Self {
            role: record
                .role
                .parse()
                .map_err(|_| invalid("invalid role pin"))?,
            attempt: AttemptId::parse(&record.attempt)
                .map_err(|_| invalid("invalid service attempt"))?,
            binding: binding(&record.unit, record.invocation)?,
        };
        if challenge.encode()? != bytes {
            return Err(invalid("noncanonical service challenge"));
        }
        Ok(challenge)
    }
}
