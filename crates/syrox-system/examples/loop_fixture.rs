//! Emit offline Ignition fixtures for the static loop/ext4 qualification probe.
//! The fixture targets a disposable QEMU disk boot; it exposes no host share.

use base64::Engine as _;
use sha2::{Digest as _, Sha512};
use std::io::{self, Read as _, Write as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = std::env::args_os().skip(1).collect::<Vec<_>>();
    if paths == ["--disk"] {
        return disk_fixture(false, false);
    }
    if paths == ["--disk-isolated"] {
        return disk_fixture(true, false);
    }
    if paths == ["--disk-helper"] {
        return disk_fixture(false, true);
    }
    if !matches!(paths.len(), 1 | 3) {
        return Err(
            "expected --disk, --disk-isolated, --disk-helper or probe path with optional mke2fs/e2fsck paths"
                .into(),
        );
    }
    let mut files = vec![
        embedded_file(
            std::path::Path::new(&paths[0]),
            "/usr/local/bin/srx-loop-probe",
        )?,
        serde_json::json!({ "path": "/etc/srx-disposable-vm", "mode": 384,
            "contents": { "source": "data:,srx-loop-fixture-v1%0A" } }),
    ];
    if paths.len() == 3 {
        files.push(embedded_file(
            std::path::Path::new(&paths[1]),
            "/usr/local/libexec/srx-probe/mke2fs",
        )?);
        files.push(embedded_file(
            std::path::Path::new(&paths[2]),
            "/usr/local/libexec/srx-probe/e2fsck",
        )?);
    }
    let unit = concat!(
        "[Unit]\nDescription=SRX disposable loop primitive probe\nAfter=local-fs.target\n",
        "[Service]\nType=oneshot\nExecStartPre=/usr/sbin/modprobe loop max_part=0\n",
        "ExecStart=/usr/local/bin/srx-loop-probe --disposable-vm\n",
        "ExecStopPost=/usr/bin/systemctl --no-block poweroff\n",
        "StandardOutput=journal+console\nStandardError=journal+console\nTimeoutStartSec=240\n",
        "[Install]\nWantedBy=multi-user.target\n",
    );
    let unit = if paths.len() == 3 {
        unit.replace(" --disposable-vm\n", " --disposable-vm --ext4\n")
    } else {
        unit.to_owned()
    };
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "ignition": { "version": "3.5.0" },
            "storage": { "files": files },
            "systemd": { "units": [
                { "name": "srx-loop-probe.service", "enabled": true, "contents": unit },
                { "name": "zincati.service", "mask": true }
            ] }
        }),
    )?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}

fn disk_fixture(isolated: bool, helper: bool) -> Result<(), Box<dyn std::error::Error>> {
    // /usr/local resolves to /var/usrlocal in this fixed Fedora CoreOS fixture.
    // The mount unit uses the canonical destination; the existing probe paths
    // remain valid through that distribution-owned link.
    let name = r"var-usrlocal-libexec-srx\x2dprobe.mount";
    let mount = concat!(
        "[Unit]\nDescription=SRX read-only probe payload\n",
        "[Mount]\nWhat=/dev/disk/by-id/virtio-srx-probe-tools\n",
        "Where=/var/usrlocal/libexec/srx-probe\nType=ext4\n",
        "Options=ro,nosuid,nodev,context=system_u:object_r:bin_t:s0\n"
    );
    let service = format!(
        concat!(
            "[Unit]\nDescription=SRX disposable ext4 probe\n",
            "Requires={name}\nAfter=local-fs.target {name}\n",
            "[Service]\nType=oneshot\nExecStartPre=/usr/sbin/modprobe loop max_part=0\n",
            "ExecStart=/usr/local/libexec/srx-probe/srx-loop-probe --disposable-vm --ext4\n",
            "ExecStopPost=/usr/bin/journalctl --no-pager -u srx-loop-probe.service\n",
            "ExecStopPost=/usr/bin/systemctl --no-block poweroff\n",
            "StandardOutput=journal+console\nStandardError=journal+console\nTimeoutStartSec=240\n",
            "[Install]\nWantedBy=multi-user.target\n"
        ),
        name = name
    );
    let service = if helper {
        service.replace(
            "/srx-loop-probe --disposable-vm --ext4",
            "/srx-helper-probe --disposable-vm",
        )
        .replace("ExecStopPost=/usr/bin/systemctl", "ExecStopPost=/usr/bin/journalctl --no-pager -u syrox-system-helper@*\nExecStopPost=/usr/bin/systemctl")
    } else if isolated {
        service.replace(" --ext4\n", " --ext4-isolated\n")
    } else {
        service
    };
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "ignition": { "version": "3.5.0" },
            "storage": { "files": [
                { "path": "/etc/srx-disposable-vm", "mode": 384,
                  "contents": { "source": "data:,srx-loop-fixture-v1%0A" } }
            ] },
            "systemd": { "units": [
                { "name": name, "contents": mount },
                { "name": "srx-loop-probe.service", "enabled": true, "contents": service },
                { "name": "zincati.service", "mask": true }
            ] }
        }),
    )?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}

fn embedded_file(
    path: &std::path::Path,
    target: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 || !bytes.starts_with(b"\x7fELF") {
        return Err("fixture executable must be an ELF file of at most 8 MiB".into());
    }
    let digest = format!(
        "sha512-{}",
        syrox_encoding::hex(&Sha512::digest(&bytes))
    );
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    compressed.write_all(&bytes)?;
    let contents = format!(
        "data:application/octet-stream;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(compressed.finish()?)
    );
    Ok(serde_json::json!({ "path": target, "mode": 493,
        "contents": { "source": contents, "compression": "gzip", "verification": { "hash": digest } } }))
}
