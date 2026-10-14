use crate::runtime::command_proxy::wire::CommandProxyExit;
use serde::{Deserialize, Serialize};
use std::io;

const DOMAIN: &[u8] = b"syrox-command-guardian-v2\n";
const MAX_BYTES: usize = 512;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Event {
    Prepared {
        terminal: bool,
    },
    RelayReady,
    NamespaceSettled,
    Drained,
    Restored,
    StopPreparing {
        pause: u64,
        signal: i32,
    },
    RelayPaused {
        pause: u64,
    },
    StopReady {
        pause: u64,
        signal: i32,
    },
    Resume {
        pause: u64,
    },
    ResumeReady {
        pause: u64,
    },
    Abandoned {
        pause: u64,
    },
    Finished(CommandProxyExit),
    Abort,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    sequence: u64,
    event: Event,
}
pub(crate) fn encode(sequence: u64, event: &Event) -> io::Result<Vec<u8>> {
    validate(event)?;
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(
        serde_json::to_vec(&Frame {
            sequence,
            event: event.clone(),
        })
        .map_err(|_| invalid())?,
    );
    bytes.push(b'\n');
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8], expected: u64) -> io::Result<Event> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    let frame: Frame = serde_json::from_slice(bytes.strip_prefix(DOMAIN).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    if frame.sequence != expected || encode(expected, &frame.event)? != bytes {
        return Err(invalid());
    }
    Ok(frame.event)
}
fn validate(event: &Event) -> io::Result<()> {
    match event {
        Event::StopPreparing {
            pause,
            signal,
        }
        | Event::StopReady {
            pause,
            signal,
        } => {
            if *pause == 0
                || !matches!(
                    *signal,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                )
            {
                return Err(invalid());
            }
        }
        Event::RelayPaused {
            pause,
        }
        | Event::Resume {
            pause,
        }
        | Event::ResumeReady {
            pause,
        }
        | Event::Abandoned {
            pause,
        } if *pause == 0 => {
            return Err(invalid());
        }
        Event::Finished(CommandProxyExit::Signaled(signal)) if !(1..=64).contains(signal) => {
            return Err(invalid());
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn descriptor_count(event: &Event) -> usize {
    match event {
        Event::Prepared {
            terminal,
        } => 1 + usize::from(*terminal),
        _ => 0,
    }
}
fn invalid() -> io::Error {
    io::Error::other("invalid local guardian record")
}

#[cfg(test)]
mod tests {
    use super::{CommandProxyExit, Event, decode, encode};
    #[test]
    fn canonical_local_records_preserve_signal_and_settlement_boundaries() {
        for event in [
            Event::NamespaceSettled,
            Event::Restored,
            Event::StopReady {
                pause: 1,
                signal: libc::SIGTSTP,
            },
            Event::Finished(CommandProxyExit::Signaled(9)),
            Event::Finished(CommandProxyExit::Exited(137)),
        ] {
            let bytes = encode(7, &event).unwrap();
            assert_eq!(decode(&bytes, 7).unwrap(), event);
            assert!(decode(&bytes, 8).is_err());
            assert!(decode(&bytes[..bytes.len() - 1], 7).is_err());
        }
        assert!(decode(b"", 0).is_err());
        assert!(decode(&vec![b' '; 513], 0).is_err());
        assert!(
            encode(
                0,
                &Event::StopReady {
                    pause: 1,
                    signal: 0
                }
            )
            .is_err()
        );
        assert!(
            encode(
                0,
                &Event::Finished(CommandProxyExit::Signaled(65))
            )
            .is_err()
        );
    }
    #[test]
    fn pause_ids_stop_signals_and_descriptor_contract_are_strict() {
        for signal in [
            libc::SIGSTOP,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ] {
            for event in [
                Event::StopPreparing {
                    pause: 1,
                    signal,
                },
                Event::StopReady {
                    pause: 1,
                    signal,
                },
            ] {
                assert_eq!(
                    decode(&encode(0, &event).unwrap(), 0).unwrap(),
                    event
                );
            }
        }
        for signal in [0, libc::SIGKILL, libc::SIGTERM, 65] {
            assert!(
                encode(
                    0,
                    &Event::StopPreparing {
                        pause: 1,
                        signal
                    }
                )
                .is_err()
            );
        }
        assert!(
            encode(
                0,
                &Event::Finished(CommandProxyExit::Signaled(libc::SIGKILL))
            )
            .is_ok()
        );
        for event in [
            Event::RelayPaused {
                pause: 0,
            },
            Event::Resume {
                pause: 0,
            },
            Event::ResumeReady {
                pause: 0,
            },
            Event::Abandoned {
                pause: 0,
            },
        ] {
            assert!(encode(0, &event).is_err());
        }
        let bytes = encode(0, &Event::RelayReady).unwrap();
        let old = String::from_utf8(bytes)
            .unwrap()
            .replace("guardian-v2", "guardian-v1");
        assert!(decode(old.as_bytes(), 0).is_err());
        assert_eq!(
            super::descriptor_count(&Event::Prepared {
                terminal: false
            }),
            1
        );
        assert_eq!(
            super::descriptor_count(&Event::Prepared {
                terminal: true
            }),
            2
        );
        assert_eq!(
            super::descriptor_count(&Event::RelayPaused {
                pause: 1
            }),
            0
        );
    }
}
