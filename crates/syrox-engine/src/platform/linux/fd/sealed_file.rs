use std::fs::File;
use std::io;

pub(crate) use syrox_system::descriptor::sealed::{MAX_SECRET_BYTES, validate_secret as validate};

pub(crate) fn snapshot(
    source: File,
    cancel: &crate::cancellation::Cancellation,
    maximum: u64,
) -> io::Result<File> {
    syrox_system::descriptor::sealed::snapshot_secret(source, maximum, || {
        cancel
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())
    })
}
