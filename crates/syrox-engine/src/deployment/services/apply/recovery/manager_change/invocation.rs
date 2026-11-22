use super::Result;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObservedInvocation {
    Historical([u8; 16]),
    Reloaded,
}
impl ObservedInvocation {
    pub(super) fn select(current: &[u8], candidates: &BTreeMap<String, String>) -> Result<Self> {
        if current.is_empty() {
            // systemd encodes null InvocationID as an empty array.
            return Ok(Self::Reloaded);
        }
        let invocation: [u8; 16] = current
            .try_into()
            .map_err(|source| super::failure_with("invalid current invocation", source))?;
        if invocation.iter().all(|byte| *byte == 0)
            || !candidates.contains_key(&encode(&invocation))
        {
            return Err(super::failure(
                "current invocation was not admitted",
            ));
        }
        Ok(Self::Historical(invocation))
    }
    pub(super) fn verify(self, current: &[u8]) -> Result<()> {
        let matches = match self {
            Self::Historical(expected) => current == expected,
            Self::Reloaded => current.is_empty(),
        };
        if matches {
            Ok(())
        } else {
            Err(super::failure("selected invocation changed"))
        }
    }
}
pub(super) fn encode(invocation: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in invocation {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{ObservedInvocation, encode};
    use std::collections::BTreeMap;

    #[test]
    fn selection_is_membership_not_order_and_never_accepts_foreign_nonzero() {
        let candidates = BTreeMap::from([
            (encode(&[7; 16]), "later-id".into()),
            (encode(&[9; 16]), "earlier-id".into()),
        ]);
        for id in [[7; 16], [9; 16]] {
            let selected = ObservedInvocation::select(&id, &candidates).unwrap();
            assert_eq!(selected, ObservedInvocation::Historical(id));
            selected.verify(&id).unwrap();
            assert!(selected.verify(&[]).is_err());
            assert!(selected.verify(&[8; 16]).is_err());
        }
        for invalid in [
            vec![8; 16],
            vec![0; 16],
            vec![7; 15],
            vec![7; 17],
        ] {
            assert!(ObservedInvocation::select(&invalid, &candidates).is_err());
        }
    }
    #[test]
    fn reloaded_is_only_an_observation_and_cannot_change_to_a_running_invocation() {
        let selected = ObservedInvocation::select(&[], &BTreeMap::new()).unwrap();
        assert_eq!(selected, ObservedInvocation::Reloaded);
        selected.verify(&[]).unwrap();
        assert!(selected.verify(&[0; 16]).is_err());
        assert!(selected.verify(&[7; 16]).is_err());
    }
}
