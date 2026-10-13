use std::time::Instant;

#[derive(Clone, Copy)]
struct Sample {
    cpu_us: u64,
    peak_rss_kb: u64,
    read_bytes: u64,
    write_bytes: u64,
}

fn usage(who: libc::c_int) -> Option<libc::rusage> {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: getrusage initializes the pointed-to rusage on success; it is
    // never read on failure. No descriptor or global state is transferred.
    (unsafe { libc::getrusage(who, value.as_mut_ptr()) } == 0)
        .then(|| unsafe { value.assume_init() })
}

fn micros(value: libc::timeval) -> u64 {
    u64::try_from(value.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        + u64::try_from(value.tv_usec).unwrap_or(0)
}

fn cpu(usage: &libc::rusage) -> u64 {
    micros(usage.ru_utime).saturating_add(micros(usage.ru_stime))
}

fn sample() -> Option<Sample> {
    let own = usage(libc::RUSAGE_SELF)?;
    let children = usage(libc::RUSAGE_CHILDREN)?;
    let io = std::fs::read_to_string("/proc/self/io").ok()?;
    let counter = |name: &str| {
        io.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse::<u64>().ok())
    };
    Some(Sample {
        cpu_us: cpu(&own).saturating_add(cpu(&children)),
        peak_rss_kb: u64::try_from(own.ru_maxrss).unwrap_or(0),
        read_bytes: counter("read_bytes:")?,
        write_bytes: counter("write_bytes:")?,
    })
}

/// Print one line per completed phase only when explicitly requested. Peak RSS
/// is process-wide, while CPU includes reaped children (not live workers).
pub(crate) struct PhaseProfiler {
    previous: Option<(Instant, Sample)>,
}

impl PhaseProfiler {
    pub(crate) fn new() -> Self {
        Self {
            previous: std::env::var_os("SYROX_PROFILE_PHASES")
                .and_then(|_| sample().map(|sample| (Instant::now(), sample))),
        }
    }

    pub(crate) fn mark(&mut self, phase: &str) {
        let Some((since, previous)) = self.previous else {
            return;
        };
        let now = Instant::now();
        if let Some(current) = sample() {
            eprintln!(
                "syrox-phase name={phase} wall_us={} cpu_us={} peak_rss_kb={} read_bytes={} write_bytes={}",
                now.duration_since(since).as_micros(),
                current.cpu_us.saturating_sub(previous.cpu_us),
                current.peak_rss_kb,
                current
                    .read_bytes
                    .saturating_sub(previous.read_bytes),
                current
                    .write_bytes
                    .saturating_sub(previous.write_bytes),
            );
            self.previous = Some((now, current));
        } else {
            self.previous = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_counters_are_available_for_linux_phase_measurements() {
        let before = sample().expect("getrusage and /proc/self/io are required by the Linux gate");
        let after = sample().unwrap();
        assert!(after.cpu_us >= before.cpu_us);
        assert!(after.read_bytes >= before.read_bytes);
        assert!(after.write_bytes >= before.write_bytes);
    }
}
