use std::future::Future;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::{HttpsError, check_cancellation};
use crate::cancellation::Cancellation;

const MAX_CONFIG: u64 = 16 * 1024;
const MAX_ANSWERS: usize = 64;

mod nss;
mod resolved;

fn hosts(contents: &str, host: &str) -> Result<Vec<SocketAddr>, HttpsError> {
    let mut result = Vec::new();
    for line in contents.lines() {
        let mut words = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace();
        if let Some(ip) = words
            .next()
            .and_then(|word| word.parse::<IpAddr>().ok())
            && words.any(|word| word.eq_ignore_ascii_case(host))
        {
            let address = SocketAddr::new(ip, 0);
            if !result.contains(&address) {
                if result.len() == MAX_ANSWERS {
                    return Err(HttpsError::Resolution(
                        "too many hosts-file addresses",
                    ));
                }
                result.push(address);
            }
        }
    }
    Ok(result)
}

struct DnsConfiguration {
    servers: Vec<SocketAddr>,
    needs_search: bool,
}

impl DnsConfiguration {
    fn finish(
        &self,
        result: Result<Vec<SocketAddr>, HttpsError>,
    ) -> Result<Vec<SocketAddr>, HttpsError> {
        let may_search = match &result {
            Ok(addresses) => addresses.is_empty(),
            Err(HttpsError::Transport) => true,
            Err(_) => false,
        };
        if may_search && self.needs_search {
            return Err(HttpsError::UnsupportedResolverPolicy(
                "search domains after an unsuccessful DNS query",
            ));
        }
        result
    }
}

fn nameservers(contents: &str, host: &str) -> Result<DnsConfiguration, HttpsError> {
    let mut result = Vec::new();
    let mut needs_search = false;
    for line in contents.lines() {
        let mut words = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace();
        match words.next() {
            None => {}
            Some("nameserver") => {
                let ip = words.next().and_then(|s| s.parse().ok()).ok_or(
                    HttpsError::UnsupportedResolverPolicy("invalid nameserver"),
                )?;
                if words.next().is_some() || result.len() >= 3 {
                    return Err(HttpsError::UnsupportedResolverPolicy(
                        "invalid nameserver list",
                    ));
                }
                result.push(SocketAddr::new(ip, 53));
            }
            Some("search" | "domain") => {
                needs_search = words.next().is_some() && !host.ends_with('.');
                if needs_search && !host.contains('.') {
                    return Err(HttpsError::UnsupportedResolverPolicy(
                        "search domains for short names",
                    ));
                }
            }
            Some("options") => {
                for option in words {
                    if !matches!(
                        option,
                        "edns0" | "single-request" | "single-request-reopen"
                    ) {
                        return Err(HttpsError::UnsupportedResolverPolicy(
                            "resolv.conf option",
                        ));
                    }
                }
            }
            Some("sortlist") => {
                return Err(HttpsError::UnsupportedResolverPolicy("sortlist"));
            }
            Some(_) => {
                return Err(HttpsError::UnsupportedResolverPolicy(
                    "resolv.conf directive",
                ));
            }
        }
    }
    if result.is_empty() {
        return Err(HttpsError::UnsupportedResolverPolicy(
            "no DNS nameserver",
        ));
    }
    Ok(DnsConfiguration {
        servers: result,
        needs_search,
    })
}

pub(super) async fn resolve_host(
    host: &str,
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<Vec<SocketAddr>, HttpsError> {
    nss::resolve(
        host,
        &nss::Files::system(),
        cancellation,
        start,
        deadline,
    )
    .await
}

fn encode_query(host: &str, kind: u16, id: u16) -> Result<Vec<u8>, HttpsError> {
    let mut packet = vec![0; 12];
    packet[0..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1; // recursion desired
    packet[5] = 1; // one question
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return Err(HttpsError::Transport);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(HttpsError::Transport);
        }
        packet.push(u8::try_from(label.len()).map_err(|_| HttpsError::Transport)?);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0]);
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes()); // IN
    Ok(packet)
}

fn decode_name(packet: &[u8], position: &mut usize) -> Result<String, HttpsError> {
    let mut cursor = *position;
    let mut jumped = false;
    let mut labels = Vec::new();
    for _ in 0..128 {
        let size = *packet.get(cursor).ok_or(HttpsError::Transport)?;
        if size & 0xc0 == 0xc0 {
            let low = *packet
                .get(cursor + 1)
                .ok_or(HttpsError::Transport)?;
            let offset = (usize::from(size & 0x3f) << 8) | usize::from(low);
            if offset >= cursor {
                return Err(HttpsError::Transport);
            }
            if !jumped {
                *position = cursor + 2;
                jumped = true;
            }
            cursor = offset;
        } else if size == 0 {
            if !jumped {
                *position = cursor + 1;
            }
            return Ok(labels.join(".").to_ascii_lowercase());
        } else if size & 0xc0 == 0 && size <= 63 {
            let end = cursor + 1 + usize::from(size);
            let label = packet
                .get(cursor + 1..end)
                .ok_or(HttpsError::Transport)?;
            if !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
                || labels
                    .iter()
                    .map(|label: &&str| label.len() + 1)
                    .sum::<usize>()
                    + label.len()
                    > 253
            {
                return Err(HttpsError::Transport);
            }
            labels.push(std::str::from_utf8(label).map_err(|_| HttpsError::Transport)?);
            cursor = end;
        } else {
            return Err(HttpsError::Transport);
        }
    }
    Err(HttpsError::Transport)
}

fn word(bytes: &[u8], offset: usize) -> Result<u16, HttpsError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(HttpsError::Transport)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn parse_response(
    packet: &[u8],
    host: &str,
    kind: u16,
    id: u16,
) -> Result<(Vec<IpAddr>, Option<String>), HttpsError> {
    if packet.len() < 12
        || word(packet, 0)? != id
        || packet[2] & 0xfa != 0x80
        || packet[3] & 0x40 != 0
        || !matches!(packet[3] & 0x0f, 0 | 3)
    {
        return Err(HttpsError::Transport);
    }
    if word(packet, 4)? != 1 || word(packet, 6)? > 64 {
        return Err(HttpsError::Transport);
    }
    let mut cursor = 12;
    let question = decode_name(packet, &mut cursor)?;
    if question != host.trim_end_matches('.').to_ascii_lowercase()
        || word(packet, cursor)? != kind
        || word(packet, cursor + 2)? != 1
    {
        return Err(HttpsError::Transport);
    }
    cursor += 4;
    if packet[3] & 0x0f == 3 {
        // NXDOMAIN is a completed negative lookup, not an unavailable server.
        return Ok((Vec::new(), None));
    }
    let mut records = Vec::new();
    let mut aliases = Vec::new();
    for _ in 0..word(packet, 6)? {
        let owner = decode_name(packet, &mut cursor)?;
        let rr_type = word(packet, cursor)?;
        let class = word(packet, cursor + 2)?;
        let length = usize::from(word(packet, cursor + 8)?);
        cursor += 10;
        let data = packet
            .get(cursor..cursor + length)
            .ok_or(HttpsError::Transport)?;
        if class == 1 {
            match (rr_type, length) {
                (1, 4) if kind == 1 => records.push((
                    owner,
                    IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                )),
                (28, 16) if kind == 28 => {
                    let raw: [u8; 16] = data
                        .try_into()
                        .map_err(|_| HttpsError::Transport)?;
                    records.push((owner, IpAddr::V6(Ipv6Addr::from(raw))));
                }
                (5, _) => {
                    let mut position = cursor;
                    let target = decode_name(packet, &mut position)?;
                    if position != cursor + length {
                        return Err(HttpsError::Transport);
                    }
                    aliases.push((owner, target));
                }
                _ => {}
            }
        }
        cursor += length;
    }
    let mut current = host.trim_end_matches('.').to_ascii_lowercase();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        if !seen.insert(current.clone()) {
            return Err(HttpsError::Transport);
        }
        let addresses = records
            .iter()
            .filter(|(name, _)| name == &current)
            .map(|(_, ip)| *ip)
            .collect::<Vec<_>>();
        if !addresses.is_empty() {
            return Ok((addresses, None));
        }
        let Some((_, next)) = aliases.iter().find(|(name, _)| name == &current) else {
            break;
        };
        if current == *next {
            return Err(HttpsError::Transport);
        }
        current.clone_from(next);
    }
    Ok((
        Vec::new(),
        (current != host.trim_end_matches('.').to_ascii_lowercase()).then_some(current),
    ))
}

async fn wait_for<T>(
    future: impl Future<Output = std::io::Result<T>>,
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<T, HttpsError> {
    tokio::pin!(future);
    loop {
        check_cancellation(cancellation)?;
        let remaining = deadline
            .checked_sub(start.elapsed())
            .ok_or(HttpsError::Deadline)?;
        if remaining.is_zero() {
            return Err(HttpsError::Deadline);
        }
        if let Ok(result) = tokio::time::timeout(
            remaining.min(Duration::from_millis(25)),
            &mut future,
        )
        .await
        {
            return result.map_err(|_| HttpsError::Transport);
        }
    }
}

async fn resolve_dns(
    host: &str,
    servers: &[SocketAddr],
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<Vec<SocketAddr>, HttpsError> {
    let mut output = Vec::new();
    let mut failed = servers.is_empty();
    for kind in [1, 28] {
        let mut current = host.to_owned();
        let mut seen = std::collections::BTreeSet::new();
        for depth in 0..8 {
            if !seen.insert(current.to_ascii_lowercase()) {
                return Err(HttpsError::Resolution("DNS alias loop"));
            }
            let mut response = None;
            for server in servers {
                // A silent server gets at most one second before trying the next.
                let attempt = deadline.min(start.elapsed() + Duration::from_secs(1));
                match query_server(
                    &current,
                    kind,
                    *server,
                    cancellation,
                    start,
                    attempt,
                )
                .await
                {
                    Ok(parsed) => {
                        response = Some(parsed);
                        break;
                    }
                    Err(HttpsError::Deadline) if start.elapsed() < deadline => {}
                    Err(HttpsError::Transport) => {}
                    Err(error) => return Err(error),
                }
            }
            let Some((ips, alias)) = response else {
                failed = true;
                break;
            };
            for ip in ips {
                let address = SocketAddr::new(ip, 0);
                if !output.contains(&address) {
                    if output.len() == MAX_ANSWERS {
                        return Err(HttpsError::Resolution("too many DNS addresses"));
                    }
                    output.push(address);
                }
            }
            if let Some(next) = alias {
                if depth == 7 {
                    return Err(HttpsError::Resolution("DNS alias limit exceeded"));
                }
                current = next;
            } else {
                break;
            }
        }
    }
    check_cancellation(cancellation)?;
    if start.elapsed() >= deadline {
        return Err(HttpsError::Deadline);
    }
    if output.is_empty() && failed {
        Err(HttpsError::Transport)
    } else {
        Ok(output)
    }
}

async fn query_server(
    host: &str,
    kind: u16,
    server: SocketAddr,
    cancellation: &Cancellation,
    start: Instant,
    deadline: Duration,
) -> Result<(Vec<IpAddr>, Option<String>), HttpsError> {
    let mut id = [0; 2];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut id))
        .map_err(|_| HttpsError::Transport)?;
    let id = u16::from_be_bytes(id);
    let query = encode_query(host, kind, id)?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = wait_for(
        tokio::net::UdpSocket::bind(bind),
        cancellation,
        start,
        deadline,
    )
    .await?;
    wait_for(
        socket.connect(server),
        cancellation,
        start,
        deadline,
    )
    .await?;
    wait_for(socket.send(&query), cancellation, start, deadline).await?;
    let mut buffer = [0; 4096];
    let len = wait_for(
        socket.recv(&mut buffer),
        cancellation,
        start,
        deadline,
    )
    .await?;
    parse_response(&buffer[..len], host, kind, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn hosts_and_resolver_policy_are_explicit() {
        assert_eq!(
            hosts(
                "127.0.0.1 localhost alias # comment\n::1 localhost",
                "LOCALHOST"
            )
            .unwrap()
            .len(),
            2
        );
        assert!(matches!(
            nameservers(
                "search vpn.example\nnameserver 10.0.0.1",
                "service"
            ),
            Err(HttpsError::UnsupportedResolverPolicy(_))
        ));
        assert_eq!(
            nameservers("nameserver 10.0.0.1", "example.org")
                .unwrap()
                .servers
                .len(),
            1
        );
        assert_eq!(
            nameservers(
                "search corp.example\nnameserver 10.0.0.1",
                "example.org"
            )
            .unwrap()
            .servers
            .len(),
            1
        );
        let mut many = String::new();
        for index in 1..=65 {
            writeln!(many, "192.0.2.{index} service.example").unwrap();
        }
        assert!(hosts(&many, "service.example").is_err());
    }

    #[test]
    fn dns_search_policy_cannot_be_skipped_after_a_negative_absolute_lookup() {
        let text = "search corp.example\nnameserver 10.0.0.1";
        let config = nameservers(text, "service.example").unwrap();
        assert_eq!(
            config
                .finish(Ok(vec!["192.0.2.1:0".parse().unwrap()]))
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            config.finish(Ok(Vec::new())),
            Err(HttpsError::UnsupportedResolverPolicy(_))
        ));
        for absolute in ["service.", "service.example."] {
            assert!(
                nameservers(text, absolute)
                    .unwrap()
                    .finish(Ok(Vec::new()))
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(
            nameservers("nameserver 10.0.0.1", "service.example")
                .unwrap()
                .finish(Ok(Vec::new()))
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            config.finish(Err(HttpsError::Transport)),
            Err(HttpsError::UnsupportedResolverPolicy(_))
        ));
        assert!(matches!(
            config.finish(Err(HttpsError::Cancelled)),
            Err(HttpsError::Cancelled)
        ));
        assert!(matches!(
            config.finish(Err(HttpsError::Deadline)),
            Err(HttpsError::Deadline)
        ));
    }

    #[test]
    fn dns_answer_must_match_query_and_reject_truncation() {
        let query = encode_query("example.org", 1, 0x1234).unwrap();
        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 1;
        answer.extend_from_slice(&[
            0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1,
        ]);
        assert_eq!(
            parse_response(&answer, "example.org", 1, 0x1234)
                .unwrap()
                .0,
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert!(parse_response(&answer, "other.org", 1, 0x1234).is_err());
        answer[2] |= 2;
        assert!(parse_response(&answer, "example.org", 1, 0x1234).is_err());
        let mut negative = query;
        negative[2] = 0x81;
        negative[3] = 0x83;
        assert_eq!(
            parse_response(&negative, "example.org", 1, 0x1234).unwrap(),
            (Vec::new(), None)
        );
        assert!(parse_response(&negative, "other.org", 1, 0x1234).is_err());
        negative[2] |= 0x08; // Wrong opcode must not be treated as a negative lookup.
        assert!(parse_response(&negative, "example.org", 1, 0x1234).is_err());
        let mut forged = negative[..12].to_vec();
        forged[2] = 0x81;
        // An embedded dot in one label must not impersonate two query labels.
        forged.extend_from_slice(b"\x0bexample.org\0\0\x01\0\x01");
        assert!(parse_response(&forged, "example.org", 1, 0x1234).is_err());
    }

    #[test]
    fn dns_retries_an_unavailable_server_and_keeps_a_successful_address_family() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let unavailable = closed.local_addr().unwrap();
        drop(closed);
        let responder = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 1024];
                let (len, peer) = server.recv_from(&mut buffer).unwrap();
                let mut reply = buffer[..len].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                if reply[len - 4..len - 2] == [0, 1] {
                    reply[7] = 1;
                    reply.extend_from_slice(&[
                        0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 24,
                    ]);
                } else {
                    reply[3] = 0x82;
                } // IPv6 SERVFAIL cannot discard working IPv4.
                server.send_to(&reply, peer).unwrap();
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(resolve_dns(
                "example.org",
                &[unavailable, address],
                &Cancellation::default(),
                Instant::now(),
                Duration::from_secs(3),
            ))
            .unwrap();
        responder.join().unwrap();
        assert_eq!(result, ["192.0.2.24:0".parse().unwrap()]);
    }

    #[test]
    fn completed_negative_dns_answers_are_distinct_from_transport_failure() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 1024];
                let (len, peer) = server.recv_from(&mut buffer).unwrap();
                buffer[2] = 0x81;
                buffer[3] = 0x83;
                server.send_to(&buffer[..len], peer).unwrap();
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(resolve_dns(
                "example.org",
                &[address],
                &Cancellation::default(),
                Instant::now(),
                Duration::from_secs(2),
            ))
            .unwrap();
        responder.join().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn dns_queries_are_resolved_over_udp_without_host_lookup() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 1024];
                let (len, peer) = server.recv_from(&mut buffer).unwrap();
                let mut reply = buffer[..len].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                if reply[len - 4..len - 2] == [0, 1] {
                    reply[7] = 1;
                    reply.extend_from_slice(&[
                        0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 2,
                    ]);
                }
                server.send_to(&reply, peer).unwrap();
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(resolve_dns(
                "example.org",
                &[address],
                &Cancellation::default(),
                Instant::now(),
                Duration::from_secs(2),
            ))
            .unwrap();
        responder.join().unwrap();
        assert_eq!(result, vec!["192.0.2.2:0".parse().unwrap()]);
    }

    #[test]
    fn pending_dns_io_can_be_cancelled_and_has_an_absolute_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        {
            let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = server.local_addr().unwrap();
            let cancellation = Cancellation::default();
            let start = Instant::now();
            let result = std::thread::scope(|scope| {
                scope.spawn(|| {
                    std::thread::sleep(Duration::from_millis(50));
                    cancellation.cancel();
                });
                runtime.block_on(resolve_dns(
                    "example.org",
                    &[address],
                    &cancellation,
                    start,
                    Duration::from_secs(2),
                ))
            });
            assert!(matches!(result, Err(HttpsError::Cancelled)));
            assert!(start.elapsed() < Duration::from_secs(1));
            let start = Instant::now();
            assert!(matches!(
                runtime.block_on(resolve_dns(
                    "example.org",
                    &[address],
                    &Cancellation::default(),
                    start,
                    Duration::from_millis(90)
                )),
                Err(HttpsError::Deadline)
            ));
        }
    }
}
