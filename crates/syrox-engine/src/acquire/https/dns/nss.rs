use std::io::Read as _;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{Cancellation, HttpsError, MAX_CONFIG, check_cancellation};

const MAX_SERVICES: usize = 16;

pub(super) struct Files<'a> {
    pub hosts: &'a Path,
    pub nss: &'a Path,
    pub resolv: &'a Path,
    pub machines: &'a Path,
    pub hostname: &'a Path,
    pub resolved: &'a Path,
}

impl Files<'static> {
    pub(super) fn system() -> Self {
        Self {
            hosts: Path::new("/etc/hosts"),
            nss: Path::new("/etc/nsswitch.conf"),
            resolv: Path::new("/etc/resolv.conf"),
            machines: Path::new("/run/systemd/machines"),
            hostname: Path::new("/proc/sys/kernel/hostname"),
            resolved: Path::new("/run/systemd/resolve/io.systemd.Resolve"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    Success,
    NotFound,
    Unavailable,
    TryAgain,
}

impl Status {
    fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::NotFound => 1,
            Self::Unavailable => 2,
            Self::TryAgain => 3,
        }
    }
}

#[derive(Debug)]
pub(super) struct Lookup {
    pub status: Status,
    pub addresses: Vec<SocketAddr>,
}

impl Lookup {
    pub(super) fn failure(status: Status) -> Self {
        Self {
            status,
            addresses: Vec::new(),
        }
    }
    pub(super) fn addresses(addresses: Vec<SocketAddr>) -> Self {
        Self {
            status: if addresses.is_empty() {
                Status::NotFound
            } else {
                Status::Success
            },
            addresses,
        }
    }
    fn finish(self) -> Result<Vec<SocketAddr>, HttpsError> {
        match self.status {
            Status::Success => Ok(self.addresses),
            Status::NotFound => Err(HttpsError::Resolution("host has no address")),
            Status::Unavailable => Err(HttpsError::Resolution(
                "configured resolver is unavailable",
            )),
            Status::TryAgain => Err(HttpsError::Resolution(
                "temporary resolver failure",
            )),
        }
    }
}

#[derive(Debug)]
struct Service<'a> {
    name: &'a str,
    returns: [bool; 4],
}

fn unsupported(reason: &'static str) -> HttpsError {
    HttpsError::UnsupportedResolverPolicy(reason)
}

fn policy(text: &str) -> Result<Vec<Service<'_>>, HttpsError> {
    let mut found = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        if let Some((database, value)) = line.split_once(':')
            && database.trim() == "hosts"
            && found.replace(value).is_some()
        {
            return Err(unsupported("duplicate NSS hosts database"));
        }
    }
    let mut remaining = found.unwrap_or("files dns").trim();
    let mut result: Vec<Service<'_>> = Vec::new();
    while !remaining.is_empty() {
        if let Some(actions) = remaining.strip_prefix('[') {
            let (actions, rest) = actions
                .split_once(']')
                .ok_or_else(|| unsupported("unterminated NSS action"))?;
            let service = result
                .last_mut()
                .ok_or_else(|| unsupported("NSS action without a service"))?;
            if actions.trim().is_empty() {
                return Err(unsupported("empty NSS action"));
            }
            for action in actions.split_whitespace() {
                set_action(service, action)?;
            }
            remaining = rest.trim_start();
        } else {
            let end = remaining
                .find(|c: char| c.is_whitespace() || c == '[')
                .unwrap_or(remaining.len());
            let name = &remaining[..end];
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || result.len() == MAX_SERVICES
            {
                return Err(unsupported(
                    "invalid or excessive NSS service list",
                ));
            }
            result.push(Service {
                name,
                returns: [true, false, false, false],
            });
            remaining = remaining[end..].trim_start();
        }
    }
    if result.is_empty() || result.iter().any(|service| !service.returns[0]) {
        return Err(unsupported(
            "empty NSS policy or SUCCESS=continue/merge",
        ));
    }
    Ok(result)
}

fn set_action(service: &mut Service<'_>, action: &str) -> Result<(), HttpsError> {
    let (status, action) = action
        .split_once('=')
        .ok_or_else(|| unsupported("invalid NSS action"))?;
    let (negated, status) = status
        .strip_prefix('!')
        .map_or((false, status), |status| (true, status));
    let status = match status.to_ascii_uppercase().as_str() {
        "SUCCESS" => Status::Success,
        "NOTFOUND" => Status::NotFound,
        "UNAVAIL" => Status::Unavailable,
        "TRYAGAIN" => Status::TryAgain,
        _ => return Err(unsupported("unknown NSS status")),
    };
    let returns = match action.to_ascii_lowercase().as_str() {
        "return" => true,
        "continue" => false,
        _ => return Err(unsupported("unknown NSS action")),
    };
    for (index, value) in service.returns.iter_mut().enumerate() {
        if (index == status.index()) != negated {
            *value = returns;
        }
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<Option<String>, HttpsError> {
    // Follow ordinary system config symlinks, but never wait on a FIFO/device.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(HttpsError::Resolution(
                "cannot read resolver configuration",
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|_| HttpsError::Resolution("cannot stat resolver configuration"))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG {
        return Err(unsupported(
            "resolver configuration must be a regular file of at most 16 KiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HttpsError::Resolution("cannot read resolver configuration"))?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err(unsupported("configuration exceeds 16 KiB"));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| unsupported("resolver configuration is not UTF-8"))
}

pub(super) async fn resolve(
    host: &str,
    files: &Files<'_>,
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<Vec<SocketAddr>, HttpsError> {
    check(cancellation, start, deadline)?;
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, 0)]);
    }
    let requested_host = host;
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(HttpsError::Resolution("invalid hostname"));
    }
    let text = read_config(files.nss)?.unwrap_or_default();
    let services = policy(&text)?;
    let mut last = Lookup::failure(Status::Unavailable);
    for service in services {
        check(cancellation, start, deadline)?;
        let result = match service.name {
            "files" => match read_config(files.hosts)? {
                Some(text) => Lookup::addresses(super::hosts(&text, host)?),
                None => Lookup::failure(Status::Unavailable),
            },
            "resolve" => {
                // Keep the root dot: resolved owns search domains and routing.
                super::resolved::lookup(
                    requested_host,
                    files.resolved,
                    cancellation,
                    start,
                    deadline,
                )
                .await?
            }
            "mymachines" => machines(host, files.machines)?,
            "myhostname" => myhostname(host, files.hostname)?,
            "dns" => match read_config(files.resolv)? {
                None => Lookup::failure(Status::Unavailable),
                Some(text) => {
                    let config = super::nameservers(&text, requested_host)?;
                    let response = super::resolve_dns(
                        requested_host,
                        &config.servers,
                        cancellation,
                        start,
                        deadline,
                    )
                    .await;
                    match config.finish(response) {
                        Ok(addresses) => Lookup::addresses(addresses),
                        Err(HttpsError::Transport) => Lookup::failure(Status::TryAgain),
                        Err(error) => return Err(error),
                    }
                }
            },
            _ => return Err(unsupported("unsupported NSS hosts service")),
        };
        check(cancellation, start, deadline)?;
        if service.returns[result.status.index()] {
            return result.finish();
        }
        last = result;
    }
    last.finish()
}

fn check(
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<(), HttpsError> {
    check_cancellation(cancellation)?;
    if start.elapsed() >= deadline {
        Err(HttpsError::Deadline)
    } else {
        Ok(())
    }
}

fn machines(host: &str, directory: &Path) -> Result<Lookup, HttpsError> {
    // nss-mymachines first checks this registry via sd_machine_get_class. A
    // missing name is UNAVAIL; a registered name must not leak into public DNS.
    match std::fs::symlink_metadata(directory.join(host)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Lookup::failure(Status::Unavailable))
        }
        Ok(_) => Err(unsupported("registered local machine hostname")),
        Err(_) => Err(HttpsError::Resolution(
            "cannot inspect local machine registry",
        )),
    }
}

fn myhostname(host: &str, hostname: &Path) -> Result<Lookup, HttpsError> {
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "localhost.localdomain"
    ) || lower.ends_with(".localhost")
        || lower.ends_with(".localhost.localdomain")
    {
        return Ok(Lookup::addresses(vec![
            "127.0.0.1:0".parse().expect("literal"),
            "[::1]:0".parse().expect("literal"),
        ]));
    }
    let local = read_config(hostname)?.ok_or(HttpsError::Resolution(
        "cannot determine local hostname",
    ))?;
    if matches!(lower.as_str(), "_gateway" | "_outbound") || host.eq_ignore_ascii_case(local.trim())
    {
        return Err(unsupported(
            "local hostname/interface address synthesis",
        ));
    }
    Ok(Lookup::failure(Status::NotFound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture(tempfile::TempDir);

    impl Fixture {
        fn new(policy: &str) -> Self {
            let this = Self(tempfile::tempdir().unwrap());
            fs::write(this.0.path().join("nsswitch.conf"), policy).unwrap();
            fs::write(
                this.0.path().join("hosts"),
                "192.0.2.10 service.example\n",
            )
            .unwrap();
            fs::write(this.0.path().join("hostname"), "local-machine\n").unwrap();
            fs::create_dir(this.0.path().join("machines")).unwrap();
            this
        }

        fn resolve(&self, name: &str) -> Result<Vec<SocketAddr>, HttpsError> {
            let root = self.0.path();
            let files = Files {
                hosts: &root.join("hosts"),
                nss: &root.join("nsswitch.conf"),
                resolv: &root.join("resolv.conf"),
                hostname: &root.join("hostname"),
                machines: &root.join("machines"),
                resolved: &root.join("resolve.sock"),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(resolve(
                    name,
                    &files,
                    &Cancellation::default(),
                    Instant::now(),
                    Duration::from_secs(2),
                ))
        }
    }

    #[test]
    fn policy_preserves_order_negated_actions_and_explicit_failure_returns() {
        let services = policy(
            "hosts : mymachines resolve [!UNAVAIL=return] files [NOTFOUND=return] dns # comment",
        )
        .unwrap();
        assert_eq!(
            services
                .iter()
                .map(|service| service.name)
                .collect::<Vec<_>>(),
            ["mymachines", "resolve", "files", "dns"]
        );
        assert_eq!(services[1].returns, [true, true, false, true]);
        assert_eq!(services[2].returns, [true, true, false, false]);
        assert_eq!(policy("passwd: files").unwrap().len(), 2);
        for invalid in [
            "hosts:",
            "hosts: [UNAVAIL=return] files",
            "hosts: files [broken] dns",
            "hosts: files [NOTFOUND=return",
            "hosts: files []",
            "hosts: files [SUCCESS=merge] dns",
            "hosts: files [SUCCESS=continue] dns",
            "hosts: files\nhosts: dns",
            "hosts: files [UNKNOWN=return]",
            "hosts: files [UNAVAIL=unknown]",
        ] {
            assert!(policy(invalid).is_err(), "{invalid}");
        }
        assert!(
            policy(&format!(
                "hosts: {}",
                "files ".repeat(MAX_SERVICES + 1)
            ))
            .is_err()
        );
    }

    #[test]
    fn absent_systemd_providers_follow_unavailable_rules_without_changing_host_configuration() {
        let fixture =
            Fixture::new("hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns");
        assert_eq!(
            fixture.resolve("service.example").unwrap(),
            ["192.0.2.10:0".parse().unwrap()]
        );
        fs::write(
            fixture.0.path().join("nsswitch.conf"),
            "hosts: resolve [UNAVAIL=return] files",
        )
        .unwrap();
        assert!(matches!(
            fixture.resolve("service.example"),
            Err(HttpsError::Resolution(
                "configured resolver is unavailable"
            ))
        ));
        fs::write(
            fixture.0.path().join("nsswitch.conf"),
            "hosts: files [NOTFOUND=return] resolve",
        )
        .unwrap();
        assert!(matches!(
            fixture.resolve("missing.example"),
            Err(HttpsError::Resolution("host has no address"))
        ));
    }

    #[test]
    fn active_resolver_precedence_and_negative_answers_obey_nss_instead_of_bypassing_it() {
        use super::super::resolved::tests::serve;
        for (response, expected) in [
            (
                r#"{"parameters":{"addresses":[{"family":2,"address":[192,0,2,20]}],"name":"service.example","flags":0}}"#,
                Some("192.0.2.20:0"),
            ),
            (
                r#"{"error":"io.systemd.Resolve.DNSSECValidationFailed","parameters":{"result":"failed"}}"#,
                None,
            ),
            (
                r#"{"error":"io.systemd.Resolve.QueryTimedOut"}"#,
                None,
            ),
            (
                r#"{"error":"org.varlink.service.MethodNotFound"}"#,
                Some("192.0.2.10:0"),
            ),
        ] {
            let fixture = Fixture::new("hosts: resolve [!UNAVAIL=return] files");
            let server = serve(
                &fixture.0.path().join("resolve.sock"),
                format!("{response}\0").into_bytes(),
            );
            let result = fixture.resolve("service.example");
            server.join().unwrap();
            match expected {
                Some(ip) => assert_eq!(
                    result.unwrap(),
                    [ip.parse::<SocketAddr>().unwrap()]
                ),
                None => assert!(matches!(result, Err(HttpsError::Resolution(_)))),
            }
        }
        let fixture = Fixture::new("hosts: resolve files");
        let server = serve(
            &fixture.0.path().join("resolve.sock"),
            b"{\"error\":\"io.systemd.Resolve.NoSuchResourceRecord\"}\0".to_vec(),
        );
        assert_eq!(
            fixture.resolve("service.example.").unwrap(),
            ["192.0.2.10:0".parse().unwrap()]
        );
        assert_eq!(server.join().unwrap(), "service.example.");
    }

    #[test]
    fn local_names_unknown_providers_and_invalid_config_never_silently_fall_through() {
        let fixture = Fixture::new("hosts: mymachines myhostname files dns");
        assert_eq!(
            fixture.resolve("service.example").unwrap(),
            ["192.0.2.10:0".parse().unwrap()]
        );
        for name in [
            "local-machine",
            "LOCAL-MACHINE.",
            "_gateway",
            "_outbound",
        ] {
            assert!(matches!(
                fixture.resolve(name),
                Err(HttpsError::UnsupportedResolverPolicy(_))
            ));
        }
        assert_eq!(fixture.resolve("LOCALHOST.").unwrap().len(), 2);
        fs::write(
            fixture.0.path().join("machines/service.example"),
            "CLASS=container\n",
        )
        .unwrap();
        assert!(matches!(
            fixture.resolve("service.example"),
            Err(HttpsError::UnsupportedResolverPolicy(
                "registered local machine hostname"
            ))
        ));
        fs::write(
            fixture.0.path().join("nsswitch.conf"),
            "hosts: mdns files",
        )
        .unwrap();
        assert!(matches!(
            fixture.resolve("service.example"),
            Err(HttpsError::UnsupportedResolverPolicy(_))
        ));
        fs::write(
            fixture.0.path().join("nsswitch.conf"),
            vec![b'x'; usize::try_from(MAX_CONFIG).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            fixture.resolve("service.example"),
            Err(HttpsError::UnsupportedResolverPolicy(_))
        ));
        fs::remove_file(fixture.0.path().join("nsswitch.conf")).unwrap();
        std::os::unix::fs::symlink(
            "/dev/zero",
            fixture.0.path().join("nsswitch.conf"),
        )
        .unwrap();
        assert!(matches!(
            fixture.resolve("service.example"),
            Err(HttpsError::UnsupportedResolverPolicy(_))
        ));
        // Literals need no resolver policy/configuration and still honor cancellation.
        assert_eq!(
            fixture.resolve("[::1]").unwrap(),
            ["[::1]:0".parse().unwrap()]
        );
        for invalid in [
            "service.example..",
            "../escape",
            "",
            ".",
            "a\nb",
        ] {
            assert!(fixture.resolve(invalid).is_err());
        }
    }
}
