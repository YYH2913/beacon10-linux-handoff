#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a small PROBE-ONLY SquashFS; never installs it on a device.

Keep both signed HLOS images unchanged. This filesystem demonstrates the
stock /sbin/init integration and read-only module probe; it cannot jump to QSDK.
Do not flash this diagnostic image over the production rootfs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess


def static_arm64(path):
    b = path.read_bytes()
    if b[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", b, 18)[0] != 183:
        raise ValueError("Expected little-endian ARM64 ELF BusyBox")
    at = struct.unpack_from("<Q", b, 32)[0]
    stride, count = struct.unpack_from("<HH", b, 54)
    if at + stride*count > len(b) or stride != 56:
        raise ValueError("Invalid BusyBox ELF headers")
    if any(struct.unpack_from("<I", b, at+i*stride)[0] in (2, 3) for i in range(count)):
        raise ValueError("Bootstrap BusyBox must be static: no dynamic segment/interpreter")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--busybox", type=Path, required=True, help="Static ARM64 BusyBox")
    p.add_argument("--probe-build", type=Path, required=True)
    p.add_argument("--mksquashfs", default="mksquashfs")
    p.add_argument("--out", type=Path, required=True, help="NEW output directory")
    a = p.parse_args()
    static_arm64(a.busybox)
    probe = a.probe_build / "beacon10-handoff-probe.ko"
    validation = json.loads((a.probe_build / "probe-validation.json").read_text())
    if hashlib.sha256(probe.read_bytes()).hexdigest() != validation["probe_sha256"] or \
       validation["handoff_implemented"] or not validation["all_imports_verified_in_stock_exports"]:
        p.error("Expected the exact ABI-checked, read-only stock probe")
    a.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    root = a.out / "rootfs"
    for name in ("bin", "sbin", "dev", "proc", "sys", "tmp", "etc", "lib/modules/5.4.164"):
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(a.busybox, root / "bin/busybox")
    (root / "bin/busybox").chmod(0o755)
    for name in ("sh", "cat", "echo", "printf", "true", "false", "test", "[", "mkdir", "mknod",
                 "mount", "umount", "sleep", "sync", "insmod", "ls", "uname", "readlink", "dmesg", "sha256sum", "ps", "kill"):
        (root / "bin" / name).symlink_to("busybox")
    init = Path(__file__).with_name("bootstrap-probe") / "init"
    shutil.copyfile(init, root / "sbin/init")
    (root / "sbin/init").chmod(0o755)
    shutil.copyfile(probe, root / "lib/modules/5.4.164/beacon10-handoff-probe.ko")
    (root / "etc/probe.sha256").write_text(validation["probe_sha256"] + "  lib/modules/5.4.164/beacon10-handoff-probe.ko\n")
    image = a.out / "bootstrap-probe.squashfs"
    subprocess.run([a.mksquashfs, str(root), str(image), "-noappend", "-comp", "xz",
                    "-b", "262144", "-all-root", "-no-xattrs", "-processors", "4",
                    "-p", "dev/console c 0600 0 0 5 1", "-p", "dev/null c 0666 0 0 1 3"], check=True)
    if image.stat().st_size > 6 << 20:
        raise ValueError("Bootstrap exceeds capsule snapshot allowance")
    report = {"layout": "stock-linux-v1", "probe_only": True, "production_bootstrap": False,
              "installation_enabled": False, "qsdk_handoff_implemented": False,
              "hardware_validated": False, "performed_hardware_writes": False,
              "bytes": image.stat().st_size, "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
              "slot_bytes": 8 << 20, "snapshot_max_bytes": 6 << 20,
              "local_output": str(image.resolve())}
    (a.out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
