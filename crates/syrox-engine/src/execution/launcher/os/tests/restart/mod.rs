use super::*;
use crate::deployment::os::activation::ActivationJournal;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
mod fixture;
mod observation;
use fixture::Fixture;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    io::Error::other(message).into()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn check(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

#[test]
#[ignore = "real systemd/user namespaces; explicit SYROX_RESTART_{WORKER,PAYLOAD} and _SHA256, SYROX_RESTART_PARENT, SYROX_RESTART_UNITS, SYROX_SYSTEMD_USER_BUS; retains evidence"]
fn automatic_restart_reopens_pins_limits_attempts_and_refuses_revoked_payload() {
    let configuration = fixture::Inputs::read().unwrap();
    for revoke in [false, true] {
        let mut fixture = Fixture::prepare(&configuration, revoke).unwrap();
        // Cleanup is attempted even if an assertion or API fails after publication.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&mut fixture, revoke)
        }));
        let cleanup = fixture.cleanup();
        match result {
            Ok(result) => {
                result.unwrap();
                cleanup.unwrap();
            }
            Err(panic) => {
                eprintln!("restart gate cleanup: {cleanup:?}");
                std::panic::resume_unwind(panic);
            }
        }
    }
}
fn run(fixture: &mut Fixture, revoke: bool) -> Result<()> {
    fixture.apply()?;
    let first = fixture.wait_payload(1)?;
    fixture.verify_retention()?;
    if revoke {
        fixture.revoke()?;
    }
    fixture.release(1)?;
    if revoke {
        let denied = fixture.wait_failed(78, "exit-code")?;
        check(
            denied != first,
            "denial was not a distinct restart invocation",
        )?;
        check(
            !fixture.cwd.join("witness.2").exists(),
            "revoked payload executed",
        )?;
        check(
            fixture.attempts()?.len() == 1,
            "revoked start was admitted",
        )?;
    } else {
        let second = fixture.wait_payload(2)?;
        check(
            first != second,
            "restart reused invocation identity",
        )?;
        fixture.verify_retention()?;
        fixture.release(2)?;
        fixture.wait_start_limited()?;
        check(
            !fixture.cwd.join("witness.3").exists(),
            "rate limit admitted third payload",
        )?;
        check(
            fixture.attempts()?.len() == 2,
            "unexpected admitted attempts",
        )?;
    }
    fixture.verify_retention()?;
    Ok(())
}
