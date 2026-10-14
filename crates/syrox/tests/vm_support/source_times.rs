//! Preserve Cargo freshness only for byte-identical inputs from the last attempt.
//! Changed or reverted inputs retain their fresh capture time. Persist before
//! every attempt, including failed/cancelled builds, to prevent stale reversions.
use super::{Result, common, snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, FileTimes};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct InputTime {
    pin: String,
    seconds: u64,
    nanos: u32,
}

pub fn reuse(compilation: &Path, sources: &Path, pins: &BTreeMap<String, String>) -> Result<()> {
    let record = compilation.join(".source-times.json");
    let old: BTreeMap<String, InputTime> = match fs::read(&record) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error.into()),
    };
    let mut current = BTreeMap::new();
    for (name, pin) in pins {
        let relative = Path::new(name);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("source timestamp path escapes capture".into());
        }
        let path = sources.join(relative);
        if snapshot::digest(&path)? != *pin {
            return Err("source bytes changed before preparation".into());
        }
        if let Some(previous) = old
            .get(name)
            .filter(|previous| previous.pin == *pin)
        {
            if previous.nanos >= 1_000_000_000 {
                return Err("invalid cached source timestamp".into());
            }
            let time = UNIX_EPOCH + Duration::new(previous.seconds, previous.nanos);
            File::open(&path)?.set_times(FileTimes::new().set_modified(time))?;
        }
        let time = fs::metadata(&path)?
            .modified()?
            .duration_since(UNIX_EPOCH)?;
        current.insert(
            name.clone(),
            InputTime {
                pin: pin.clone(),
                seconds: time.as_secs(),
                nanos: time.subsec_nanos(),
            },
        );
    }
    common::save(&record, &current)
}
