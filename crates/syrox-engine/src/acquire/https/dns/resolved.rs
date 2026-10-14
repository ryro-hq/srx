use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::nss::{Lookup, Status};
use super::{Cancellation, HttpsError, MAX_ANSWERS, wait_for};

const MAX_REPLY: usize = 16 * 1024;

#[derive(Deserialize)]
struct Reply {
    parameters: Option<Parameters>,
    error: Option<String>,
    continues: Option<bool>,
}

#[derive(Deserialize)]
struct Parameters {
    addresses: Option<Vec<ResolvedAddress>>,
    name: Option<String>,
    flags: Option<u64>,
}

#[derive(Deserialize)]
struct ResolvedAddress {
    family: u32,
    address: Vec<u8>,
    ifindex: Option<u32>,
}

pub(super) async fn lookup(
    host: &str,
    socket: &Path,
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<Lookup, HttpsError> {
    match exchange(host, socket, cancellation, start, deadline).await {
        Ok(reply) => decode(&reply),
        // IPC unavailability is distinct from a negative/failed resolver reply.
        // The NSS caller decides whether UNAVAIL permits another provider.
        Err(HttpsError::Transport) => Ok(Lookup::failure(Status::Unavailable)),
        Err(error) => Err(error),
    }
}

async fn exchange(
    host: &str,
    socket: &Path,
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<Vec<u8>, HttpsError> {
    let mut stream = wait_for(
        tokio::net::UnixStream::connect(socket),
        cancellation,
        start,
        deadline,
    )
    .await?;
    let mut request = serde_json::to_vec(&serde_json::json!({
        "method": "io.systemd.Resolve.ResolveHostname",
        "parameters": { "name": host, "flags": 0, "ifindex": 0 }
    }))
    .map_err(|_| invalid())?;
    request.push(0);
    wait_for(
        stream.write_all(&request),
        cancellation,
        start,
        deadline,
    )
    .await?;
    let mut reply = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let count = wait_for(
            stream.read(&mut buffer),
            cancellation,
            start,
            deadline,
        )
        .await?;
        if count == 0 {
            return Err(HttpsError::Transport);
        }
        if reply.len() + count > MAX_REPLY {
            return Err(invalid());
        }
        if let Some(end) = buffer[..count].iter().position(|byte| *byte == 0) {
            if end + 1 != count {
                return Err(invalid());
            }
            reply.extend_from_slice(&buffer[..end]);
            return Ok(reply);
        }
        reply.extend_from_slice(&buffer[..count]);
    }
}

fn invalid() -> HttpsError {
    HttpsError::Resolution("invalid or oversized systemd-resolved reply")
}

fn decode(bytes: &[u8]) -> Result<Lookup, HttpsError> {
    if bytes.len() > MAX_REPLY {
        return Err(invalid());
    }
    let reply: Reply = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if reply.continues == Some(true) {
        return Err(invalid());
    }
    if let Some(error) = reply.error {
        if reply
            .parameters
            .as_ref()
            .is_some_and(|p| p.addresses.is_some())
        {
            return Err(invalid());
        }
        let status = match error.as_str() {
            "org.varlink.service.InterfaceNotFound"
            | "org.varlink.service.MethodNotFound"
            | "org.varlink.service.MethodNotImplemented"
            | "io.systemd.Disconnected"
            | "io.systemd.TimedOut"
            | "io.systemd.Protocol" => Status::Unavailable,
            "io.systemd.Resolve.NoNameServers"
            | "io.systemd.Resolve.QueryTimedOut"
            | "io.systemd.Resolve.MaxAttemptsReached"
            | "io.systemd.Resolve.NetworkDown" => Status::TryAgain,
            _ if error.starts_with("io.systemd.Resolve.") => Status::NotFound,
            _ => return Err(invalid()),
        };
        return Ok(Lookup::failure(status));
    }
    let parameters = reply.parameters.ok_or_else(invalid)?;
    if parameters.flags.is_none()
        || parameters
            .name
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.len() > 254)
    {
        return Err(invalid());
    }
    let addresses = parameters.addresses.ok_or_else(invalid)?;
    if addresses.len() > MAX_ANSWERS {
        return Err(invalid());
    }
    let mut result = Vec::new();
    for entry in addresses {
        if entry
            .ifindex
            .is_some_and(|index| index > i32::MAX as u32)
        {
            return Err(invalid());
        }
        let address = match (entry.family, entry.address.as_slice()) {
            (2, [a, b, c, d]) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)), 0),
            (10, bytes) if bytes.len() == 16 => {
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).map_err(|_| invalid())?);
                let scope = if ip.is_unicast_link_local() {
                    entry.ifindex.unwrap_or(0)
                } else {
                    0
                };
                SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, scope))
            }
            _ => return Err(invalid()),
        };
        if !result.contains(&address) {
            result.push(address);
        }
    }
    Ok(Lookup::addresses(result))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    pub(crate) fn serve(path: &Path, response: Vec<u8>) -> std::thread::JoinHandle<String> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(&[0]) {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 2048);
            }
            let request: serde_json::Value =
                serde_json::from_slice(&request[..request.len() - 1]).unwrap();
            assert_eq!(
                request["method"],
                "io.systemd.Resolve.ResolveHostname"
            );
            assert_eq!(request["parameters"]["flags"], 0);
            assert_eq!(request["parameters"]["ifindex"], 0);
            // Fragment the stream, including framing, independently of read boundaries.
            for chunk in response.chunks(7) {
                if stream.write_all(chunk).is_err() {
                    break;
                }
            }
            request["parameters"]["name"]
                .as_str()
                .unwrap()
                .to_owned()
        })
    }

    #[test]
    fn bounded_typed_reply_preserves_family_scope_and_classifies_errors() {
        let result = decode(br#"{"parameters":{"addresses":[{"family":2,"address":[192,0,2,1]}, {"family":10,"address":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"ifindex":9}],"flags":0}}"#).unwrap();
        assert_eq!(result.status, Status::Success);
        assert_eq!(
            result.addresses,
            [
                "192.0.2.1:0".parse().unwrap(),
                "[fe80::1%9]:0".parse().unwrap()
            ]
        );
        for (error, status) in [
            (
                "io.systemd.Resolve.NoSuchResourceRecord",
                Status::NotFound,
            ),
            (
                "io.systemd.Resolve.DNSSECValidationFailed",
                Status::NotFound,
            ),
            ("io.systemd.Resolve.NetworkDown", Status::TryAgain),
            (
                "org.varlink.service.InterfaceNotFound",
                Status::Unavailable,
            ),
        ] {
            assert_eq!(
                decode(format!("{{\"error\":\"{error}\"}}").as_bytes())
                    .unwrap()
                    .status,
                status
            );
        }
        for invalid in [
            b"{}".as_slice(), br#"{"continues":true,"parameters":{"addresses":[],"flags":0}}"#,
            br#"{"parameters":{"addresses":[{"family":2,"address":[256,0,0,1]}],"flags":0}}"#,
            br#"{"parameters":{"addresses":[{"family":2,"address":[127,0,0]}],"flags":0}}"#,
            br#"{"parameters":{"addresses":[{"family":2,"family":10,"address":[127,0,0,1]}],"flags":0}}"#,
            br#"{"error":"io.systemd.Resolve.NoSuchResourceRecord","parameters":{"addresses":[]}}"#,
            br#"{"parameters":{"addresses":[],"flags":0},"parameters":{"addresses":[],"flags":0}}"#,
        ] { assert!(decode(invalid).is_err()); }
        let many = serde_json::json!({"parameters":{"addresses":vec![serde_json::json!({"family":2,"address":[127,0,0,1]}); MAX_ANSWERS + 1],"flags":0}});
        assert!(decode(&serde_json::to_vec(&many).unwrap()).is_err());
    }

    #[test]
    fn fragmented_ipc_reply_is_bounded_and_has_no_background_resolver() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (reply, success) in [
            (b"{\"parameters\":{\"addresses\":[{\"family\":2,\"address\":[192,0,2,22]}],\"flags\":0}}\0".to_vec(), true),
            (vec![b' '; MAX_REPLY + 1], false),
            (b"{broken}\0".to_vec(), false),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("resolve.sock");
            let server = serve(&path, reply);
            let result = runtime.block_on(lookup("service.example", &path, &Cancellation::default(), Instant::now(), Duration::from_secs(2)));
            server.join().unwrap();
            if success { assert_eq!(result.unwrap().addresses, ["192.0.2.22:0".parse().unwrap()]); }
            else { assert!(matches!(result, Err(HttpsError::Resolution(_)))); }
        }
    }

    #[test]
    fn cancellation_and_absolute_deadline_close_pending_ipc_before_return() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for cancel in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("resolve.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let cancellation = Cancellation::default();
            let token = cancellation.clone();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut byte = [1];
                while byte[0] != 0 {
                    stream.read_exact(&mut byte).unwrap();
                }
                if cancel {
                    token.cancel();
                }
                assert_eq!(
                    stream.read(&mut byte).unwrap(),
                    0,
                    "cancelled operation must close its socket"
                );
            });
            let start = Instant::now();
            let result = runtime.block_on(lookup(
                "service.example",
                &path,
                &cancellation,
                start,
                Duration::from_millis(100),
            ));
            assert!(if cancel {
                matches!(result, Err(HttpsError::Cancelled))
            } else {
                matches!(result, Err(HttpsError::Deadline))
            });
            assert!(start.elapsed() < Duration::from_secs(1));
            server.join().unwrap();
        }
    }
}
