use super::properties::{Property, Value};
use super::{MAX_TEXT, SystemdError};
pub(super) const MAX_FRAME: usize = 1024 * 1024;
const MAX_HEADER: usize = 16 * 1024;
fn invalid() -> SystemdError {
    SystemdError::Protocol("malformed D-Bus frame")
}
#[derive(Debug, Default)]
pub(super) struct Writer(pub Vec<u8>);
impl Writer {
    pub fn align(&mut self, n: usize) {
        self.0
            .resize((self.0.len() + n - 1) & !(n - 1), 0);
    }
    pub fn u32(&mut self, n: u32) {
        self.align(4);
        self.0.extend(n.to_le_bytes());
    }
    pub fn sig(&mut self, value: &str) -> Result<(), SystemdError> {
        self.0
            .push(u8::try_from(value.len()).map_err(|_| invalid())?);
        self.0.extend(value.bytes());
        self.0.push(0);
        Ok(())
    }
    pub fn string(&mut self, value: &str) -> Result<(), SystemdError> {
        super::text(value)?;
        self.u32(u32::try_from(value.len()).map_err(|_| invalid())?);
        self.0.extend(value.bytes());
        self.0.push(0);
        Ok(())
    }
    pub(super) fn array(
        &mut self,
        alignment: usize,
        body: impl FnOnce(&mut Self) -> Result<(), SystemdError>,
    ) -> Result<(), SystemdError> {
        self.align(4);
        let length = self.0.len();
        self.u32(0);
        self.align(alignment);
        let start = self.0.len();
        body(self)?;
        let bytes = u32::try_from(self.0.len() - start).map_err(|_| invalid())?;
        self.0[length..length + 4].copy_from_slice(&bytes.to_le_bytes());
        Ok(())
    }
    pub(super) fn strings(&mut self, values: &[String]) -> Result<(), SystemdError> {
        self.array(4, |w| {
            for s in values {
                w.string(s)?;
            }
            Ok(())
        })
    }
    pub fn properties(&mut self, properties: &[Property]) -> Result<(), SystemdError> {
        self.array(8, |w| {
            for (name, value) in properties {
                w.align(8);
                w.string(name)?;
                w.sig(value.signature())?;
                match value {
                    Value::String(s) => w.string(s)?,
                    Value::Bool(v) => w.u32(u32::from(*v)),
                    Value::U32(v) => w.u32(*v),
                    Value::U64(v) => {
                        w.align(8);
                        w.0.extend(v.to_le_bytes());
                    }
                    Value::Strings(v) => w.strings(v)?,
                    Value::ExitStatuses {
                        codes,
                        signals,
                    } => {
                        w.align(8);
                        for values in [codes, signals] {
                            w.array(4, |w| {
                                for value in values {
                                    w.u32(u32::from_ne_bytes(value.to_ne_bytes()));
                                }
                                Ok(())
                            })?;
                        }
                    }
                    Value::Exec {
                        executable,
                        argv,
                    } => w.array(8, |w| {
                        w.align(8);
                        w.string(executable)?;
                        w.strings(argv)?;
                        w.strings(&["no-env-expand".into()])
                    })?,
                }
            }
            Ok(())
        })
    }
    pub fn empty_array(&mut self, element: &str) -> Result<(), SystemdError> {
        if element != "(sa(sv))" {
            return Err(invalid());
        }
        self.array(8, |_| Ok(()))
    }
}
#[derive(Debug)]
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pub pos: usize,
    little: bool,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], little: bool) -> Self {
        Self {
            bytes,
            pos: 0,
            little,
        }
    }
    pub fn align(&mut self, n: usize) -> Result<(), SystemdError> {
        let end = (self.pos + n - 1) & !(n - 1);
        if end > self.bytes.len() || self.bytes[self.pos..end].iter().any(|b| *b != 0) {
            return Err(invalid());
        }
        self.pos = end;
        Ok(())
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], SystemdError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|n| *n <= self.bytes.len())
            .ok_or_else(invalid)?;
        let v = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(v)
    }
    pub fn u32(&mut self) -> Result<u32, SystemdError> {
        self.align(4)?;
        let b = self.take(4)?.try_into().map_err(|_| invalid())?;
        Ok(if self.little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    pub fn u64(&mut self) -> Result<u64, SystemdError> {
        self.align(8)?;
        let bytes = self.take(8)?.try_into().map_err(|_| invalid())?;
        Ok(if self.little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }
    pub fn array_end(&mut self, alignment: usize) -> Result<usize, SystemdError> {
        let bytes = usize::try_from(self.u32()?).map_err(|_| invalid())?;
        self.align(alignment)?;
        self.pos
            .checked_add(bytes)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(invalid)
    }
    pub fn sig(&mut self) -> Result<&'a str, SystemdError> {
        let n = usize::from(self.take(1)?[0]);
        self.text(n)
    }
    fn text(&mut self, n: usize) -> Result<&'a str, SystemdError> {
        if n > MAX_TEXT {
            return Err(invalid());
        }
        let b = self.take(n)?;
        if b.contains(&0) || self.take(1)? != [0] {
            return Err(invalid());
        }
        std::str::from_utf8(b).map_err(|_| invalid())
    }
    pub fn string(&mut self) -> Result<&'a str, SystemdError> {
        let n = usize::try_from(self.u32()?).map_err(|_| invalid())?;
        self.text(n)
    }
    pub fn end(&self) -> Result<(), SystemdError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, SystemdError> {
        let n = usize::try_from(self.u32()?).map_err(|_| invalid())?;
        if n > 16 {
            return Err(invalid());
        }
        Ok(self.take(n)?.to_vec())
    }
}
#[derive(Debug)]
pub(super) struct Frame {
    pub kind: u8,
    pub reply: u32,
    pub sender: String,
    pub path: String,
    pub interface: String,
    pub member: String,
    pub error: String,
    pub signature: String,
    pub body: Vec<u8>,
    pub little: bool,
}
impl Frame {
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.body, self.little)
    }
}
pub(super) fn frame_size(bytes: &[u8]) -> Result<usize, SystemdError> {
    if bytes.len() < 16 {
        return Err(invalid());
    }
    if !matches!(bytes[0], b'l' | b'B') || !matches!(bytes[1], 1..=4) || bytes[3] != 1 {
        return Err(invalid());
    }
    let mut r = Reader::new(bytes, bytes[0] == b'l');
    r.pos = 4;
    let body = usize::try_from(r.u32()?).map_err(|_| invalid())?;
    if r.u32()? == 0 {
        return Err(invalid());
    }
    let header = usize::try_from(r.u32()?).map_err(|_| invalid())?;
    if header > MAX_HEADER || body > MAX_FRAME {
        return Err(invalid());
    }
    let total = ((16 + header + 7) & !7) + body;
    if total > MAX_FRAME {
        return Err(invalid());
    }
    Ok(total)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Frame, SystemdError> {
    if frame_size(bytes)? != bytes.len() {
        return Err(invalid());
    }
    let mut r = Reader::new(bytes, bytes[0] == b'l');
    r.pos = 12;
    let header = usize::try_from(r.u32()?).map_err(|_| invalid())?;
    let end = 16 + header;
    let mut f = Frame {
        kind: bytes[1],
        reply: 0,
        sender: String::new(),
        path: String::new(),
        interface: String::new(),
        member: String::new(),
        error: String::new(),
        signature: String::new(),
        body: Vec::new(),
        little: r.little,
    };
    let mut seen = [false; 256];
    while r.pos < end {
        r.align(8)?;
        let id = usize::from(r.take(1)?[0]);
        if id == 0 || seen[id] {
            return Err(invalid());
        }
        seen[id] = true;
        let sig = r.sig()?;
        match (id, sig) {
            (1, "o") => f.path = r.string()?.into(),
            (2, "s") => f.interface = r.string()?.into(),
            (3, "s") => f.member = r.string()?.into(),
            (4, "s") => f.error = r.string()?.into(),
            (5, "u") => f.reply = r.u32()?,
            (6, "s") => {
                r.string()?;
            }
            (7, "s") => f.sender = r.string()?.into(),
            (8, "g") => f.signature = r.sig()?.into(),
            (9, "u") => {
                if r.u32()? != 0 {
                    return Err(SystemdError::Protocol(
                        "descriptor-bearing D-Bus message",
                    ));
                }
            }
            // Narrow client rejects extensions it cannot validate, never skips untrusted lengths.
            (1..=9, _) => return Err(invalid()),
            (_, "s" | "o") => {
                r.string()?;
            }
            (_, "g") => {
                r.sig()?;
            }
            (_, "u") => {
                r.u32()?;
            }
            _ => return Err(invalid()),
        }
        if r.pos > end {
            return Err(invalid());
        }
    }
    if r.pos != end {
        return Err(invalid());
    }
    r.align(8)?;
    f.body = r.take(bytes.len() - r.pos)?.to_vec();
    if f.sender.is_empty()
        || f.sender.len() > 255
        || (matches!(f.kind, 2 | 3) && f.reply == 0)
        || (f.kind == 3 && f.error.is_empty())
        || (f.kind == 4 && (f.path.is_empty() || f.interface.is_empty() || f.member.is_empty()))
        || (f.body.is_empty() != f.signature.is_empty())
    {
        return Err(invalid());
    }
    validate_body(&f.signature, &f.body, f.little)?;
    Ok(f)
}
pub(super) fn encode(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    signature: &str,
    body: &[u8],
) -> Result<Vec<u8>, SystemdError> {
    let mut w = Writer(vec![b'l', 1, 2, 1]);
    w.u32(u32::try_from(body.len()).map_err(|_| invalid())?);
    w.u32(serial);
    w.u32(0);
    for (id, sig, value) in [
        (1, "o", path),
        (2, "s", interface),
        (3, "s", member),
        (6, "s", destination),
        (8, "g", signature),
    ] {
        if id == 8 && signature.is_empty() {
            continue;
        }
        w.align(8);
        w.0.push(id);
        w.sig(sig)?;
        if sig == "g" {
            w.sig(value)?;
        } else {
            w.string(value)?;
        }
    }
    let n = u32::try_from(w.0.len() - 16).map_err(|_| invalid())?;
    w.0[12..16].copy_from_slice(&n.to_le_bytes());
    w.align(8);
    w.0.extend(body);
    if w.0.len() > MAX_FRAME {
        return Err(invalid());
    }
    Ok(w.0)
}

#[derive(Debug)]
enum Type {
    Basic(u8),
    Array(Box<Type>),
    Group(Vec<Type>),
    Variant,
}
impl Type {
    fn alignment(&self) -> usize {
        match self {
            Self::Basic(b'y' | b'g') | Self::Variant => 1,
            Self::Basic(b'n' | b'q') => 2,
            Self::Basic(b'x' | b't' | b'd') | Self::Group(_) => 8,
            _ => 4,
        }
    }
}
fn parse_type(sig: &[u8], pos: &mut usize, depth: usize, dict: bool) -> Result<Type, SystemdError> {
    if depth > 32 {
        return Err(invalid());
    }
    let b = *sig.get(*pos).ok_or_else(invalid)?;
    *pos += 1;
    match b {
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' => {
            Ok(Type::Basic(b))
        }
        b'v' => Ok(Type::Variant),
        b'a' => Ok(Type::Array(Box::new(parse_type(
            sig,
            pos,
            depth + 1,
            true,
        )?))),
        b'(' | b'{' if b == b'(' || dict => {
            let end = if b == b'(' {
                b')'
            } else {
                b'}'
            };
            let mut types = Vec::new();
            while sig.get(*pos) != Some(&end) {
                types.push(parse_type(sig, pos, depth + 1, false)?);
            }
            *pos += 1;
            if types.is_empty()
                || (b == b'{' && (types.len() != 2 || !matches!(types[0], Type::Basic(_))))
            {
                return Err(invalid());
            }
            Ok(Type::Group(types))
        }
        _ => Err(invalid()),
    }
}
fn skip(r: &mut Reader<'_>, ty: &Type, depth: usize) -> Result<(), SystemdError> {
    if depth > 32 {
        return Err(invalid());
    }
    r.align(ty.alignment())?;
    match ty {
        Type::Basic(b'y') => {
            r.take(1)?;
        }
        Type::Basic(b'n' | b'q') => {
            r.take(2)?;
        }
        Type::Basic(b'i' | b'u') => {
            r.u32()?;
        }
        Type::Basic(b'b') => {
            if r.u32()? > 1 {
                return Err(invalid());
            }
        }
        Type::Basic(b'x' | b't' | b'd') => {
            r.take(8)?;
        }
        Type::Basic(b's' | b'o') => {
            let value = r.string()?;
            if matches!(ty, Type::Basic(b'o')) && !object_path(value) {
                return Err(invalid());
            }
        }
        Type::Basic(b'g') => {
            let sig = r.sig()?;
            let mut pos = 0;
            while pos < sig.len() {
                parse_type(sig.as_bytes(), &mut pos, depth + 1, false)?;
            }
        }
        Type::Array(element) => {
            let n = usize::try_from(r.u32()?).map_err(|_| invalid())?;
            r.align(element.alignment())?;
            let end = r
                .pos
                .checked_add(n)
                .filter(|end| *end <= r.bytes.len())
                .ok_or_else(invalid)?;
            while r.pos < end {
                skip(r, element, depth + 1)?;
            }
            if r.pos != end {
                return Err(invalid());
            }
        }
        Type::Group(types) => {
            for ty in types {
                skip(r, ty, depth + 1)?;
            }
        }
        Type::Variant => {
            let sig = r.sig()?;
            let mut pos = 0;
            let ty = parse_type(sig.as_bytes(), &mut pos, depth + 1, false)?;
            if pos != sig.len() {
                return Err(invalid());
            }
            skip(r, &ty, depth + 1)?;
        }
        Type::Basic(_) => return Err(invalid()),
    }
    Ok(())
}
fn object_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && path[1..].split('/').all(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }))
}
fn validate_body(signature: &str, bytes: &[u8], little: bool) -> Result<(), SystemdError> {
    let mut pos = 0;
    let mut r = Reader::new(bytes, little);
    while pos < signature.len() {
        let ty = parse_type(signature.as_bytes(), &mut pos, 0, false)?;
        skip(&mut r, &ty, 0)?;
    }
    r.end()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exit_status_properties_encode_separate_aligned_code_and_signal_arrays() {
        let mut writer = Writer::default();
        writer
            .properties(&[
                (
                    "RestartPreventExitStatus",
                    Value::ExitStatuses {
                        codes: vec![78],
                        signals: vec![],
                    },
                ),
                (
                    "SuccessExitStatus",
                    Value::ExitStatuses {
                        codes: vec![],
                        signals: vec![15],
                    },
                ),
                (
                    "RestartForceExitStatus",
                    Value::ExitStatuses {
                        codes: vec![],
                        signals: vec![],
                    },
                ),
            ])
            .unwrap();
        validate_body("a(sv)", &writer.0, true).unwrap();
        let mut reader = Reader::new(&writer.0, true);
        let end = reader.array_end(8).unwrap();
        for (name, codes, signals) in [
            ("RestartPreventExitStatus", vec![78], vec![]),
            ("SuccessExitStatus", vec![], vec![15]),
            ("RestartForceExitStatus", vec![], vec![]),
        ] {
            reader.align(8).unwrap();
            assert_eq!(reader.string().unwrap(), name);
            assert_eq!(reader.sig().unwrap(), "(aiai)");
            reader.align(8).unwrap();
            for expected in [codes, signals] {
                let array_end = reader.array_end(4).unwrap();
                let mut actual = Vec::new();
                while reader.pos < array_end {
                    actual.push(reader.u32().unwrap());
                }
                assert_eq!(actual, expected);
                assert_eq!(reader.pos, array_end);
            }
        }
        assert_eq!(reader.pos, end);
        reader.end().unwrap();
    }
    fn reply(signature: &str, body: &[u8]) -> Vec<u8> {
        let mut w = Writer(vec![b'l', 2, 0, 1]);
        w.u32(u32::try_from(body.len()).unwrap());
        w.u32(1);
        w.u32(0);
        w.align(8);
        w.0.push(5);
        w.sig("u").unwrap();
        w.u32(7);
        w.align(8);
        w.0.push(7);
        w.sig("s").unwrap();
        w.string(":1.2").unwrap();
        w.align(8);
        w.0.push(8);
        w.sig("g").unwrap();
        w.sig(signature).unwrap();
        let len = u32::try_from(w.0.len() - 16).unwrap();
        w.0[12..16].copy_from_slice(&len.to_le_bytes());
        w.align(8);
        w.0.extend(body);
        w.0
    }
    #[test]
    fn transient_body_and_alignment_round_trip() {
        let service = super::super::SystemdService::new(
            super::super::SystemdUnitName::new("syrox-wire.service").unwrap(),
            "/usr/bin/true".into(),
        );
        let mut w = Writer::default();
        w.string(service.unit.as_str()).unwrap();
        w.string("fail").unwrap();
        w.properties(&super::super::properties::service(&service).unwrap())
            .unwrap();
        w.empty_array("(sa(sv))").unwrap();
        validate_body("ssa(sv)a(sa(sv))", &w.0, true).unwrap();
        assert!(validate_body("ssa(sv)a(sa(sv))", &w.0[..w.0.len() - 1], true).is_err());
        let bytes = encode(
            7,
            ":1.2",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            &w.0,
        )
        .unwrap();
        assert_eq!(frame_size(&bytes).unwrap(), bytes.len());
    }
    #[test]
    fn reply_lengths_types_padding_and_duplicates_are_rejected() {
        let mut body = Writer::default();
        body.string("hello").unwrap();
        let bytes = reply("s", &body.0);
        let f = decode(&bytes).unwrap();
        assert_eq!(f.reply, 7);
        assert_eq!(f.reader().string().unwrap(), "hello");
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err());
        }
        let mut bad = bytes.clone();
        bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[1] = 255;
        assert!(decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[24] = 5;
        assert!(decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[37] = 1;
        assert!(decode(&bad).is_err());
        let mut bad = bytes;
        *bad.last_mut().unwrap() = 1;
        assert!(decode(&bad).is_err());
    }
    #[test]
    fn big_endian_values_and_nested_bounds_are_checked() {
        let mut r = Reader::new(&[0, 0, 0, 42], false);
        assert_eq!(r.u32().unwrap(), 42);
        assert!(validate_body("b", &[2, 0, 0, 0], true).is_err());
        assert!(validate_body("h", &[0; 4], true).is_err());
        assert!(validate_body("v", &[2, b's', b's', 0], true).is_err());
        assert!(validate_body(&format!("{}u", "a".repeat(40)), &[], true).is_err());
        assert!(validate_body("ay", &[255, 255, 255, 255], true).is_err());
        assert!(validate_body("a{}", &[0; 8], true).is_err());
        assert!(validate_body("o", &[2, 0, 0, 0, b'/', b'/', 0], true).is_err());
    }
    #[test]
    fn frame_and_property_payload_limits_are_enforced() {
        let mut fixed = [0; 16];
        fixed[..4].copy_from_slice(&[b'l', 2, 0, 1]);
        fixed[4..8].copy_from_slice(&u32::try_from(MAX_FRAME).unwrap().to_le_bytes());
        fixed[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(frame_size(&fixed).is_err());
        let mut w = Writer::default();
        assert!(w.string(&"x".repeat(MAX_TEXT + 1)).is_err());
        assert!(decode(&reply("s", &[255, 255, 255, 255])).is_err());
    }
}
