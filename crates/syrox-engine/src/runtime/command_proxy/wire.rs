use std::io;

use serde::{Deserialize, Serialize};

const MAX_FRAME: usize = 4096;

/// A signal remains a signal across the proxy, rather than becoming exit 128+n.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CommandProxyExit {
    Exited(u8),
    Signaled(i32),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frame {
    version: u32,
    sequence: u64,
    message: Message,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Message {
    Accepted {
        invocation: String,
    },
    NamespacePrepared {
        terminal: bool,
    },
    Commit,
    ExecAcknowledged,
    Signal(i32),
    Stopped(i32),
    Continued,
    Exited(CommandProxyExit),
    NamespaceSettled,
    RestoreRequested,
    Restored,
    Finished,
    Abort,
}

impl Frame {
    pub(crate) fn new(sequence: u64, message: Message) -> io::Result<Self> {
        let frame = Self {
            version: 1,
            sequence,
            message,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub(crate) fn message(&self) -> &Message {
        &self.message
    }

    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME {
            return Err(invalid());
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8], expected_sequence: u64) -> io::Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(invalid());
        }
        let frame: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if frame.sequence != expected_sequence || frame.encode()? != bytes {
            return Err(invalid());
        }
        Ok(frame)
    }

    fn validate(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(invalid());
        }
        match &self.message {
            Message::Accepted {
                invocation,
            } => {
                let id = crate::execution::journal::SessionId::parse(invocation)
                    .map_err(|_| invalid())?;
                if id.to_string() != *invocation {
                    return Err(invalid());
                }
            }
            Message::Signal(signal)
            | Message::Stopped(signal)
            | Message::Exited(CommandProxyExit::Signaled(signal))
                if !(1..=64).contains(signal) =>
            {
                return Err(invalid());
            }
            _ => {}
        }
        Ok(())
    }
}

fn invalid() -> io::Error {
    io::Error::other("invalid command proxy control record")
}

#[cfg(test)]
mod tests {
    use super::{CommandProxyExit, Frame, Message};

    #[test]
    fn signal_status_survives_without_becoming_an_exit_code() {
        for message in [
            Message::Exited(CommandProxyExit::Exited(137)),
            Message::Exited(CommandProxyExit::Signaled(9)),
        ] {
            let frame = Frame::new(17, message.clone()).unwrap();
            let bytes = frame.encode().unwrap();
            assert_eq!(
                Frame::decode(&bytes, 17).unwrap().message(),
                &message
            );
            assert!(Frame::decode(&bytes, 16).is_err());
        }
    }

    #[test]
    fn malformed_or_noncanonical_control_never_advances_sequence() {
        for signal in [0, -1, 65] {
            assert!(Frame::new(0, Message::Signal(signal)).is_err());
        }
        let frame = Frame::new(0, Message::Commit)
            .unwrap()
            .encode()
            .unwrap();
        let mut spaced = vec![b' '];
        spaced.extend_from_slice(&frame);
        assert!(Frame::decode(&spaced, 0).is_err());
        assert!(Frame::decode(&vec![b' '; 4097], 0).is_err());
        assert!(
            Frame::decode(
                b"{\"version\":2,\"sequence\":0,\"message\":\"Commit\"}\n",
                0
            )
            .is_err()
        );
    }
}
