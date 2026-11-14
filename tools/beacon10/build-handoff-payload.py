#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a bounded B10LINUX Image+DTB boot partition payload (not a GPT image)."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel", required=True, type=Path)
    p.add_argument("--dtb", required=True, type=Path)
    dest = p.add_mutually_exclusive_group(required=True)
    dest.add_argument("--out", type=Path, help="NEW output directory")
    dest.add_argument("--image-out", type=Path, help="Kernel build pipeline output, atomically replaced")
    a = p.parse_args()
    kernel, dtb = a.kernel.read_bytes(), a.dtb.read_bytes()
    if not 64 <= len(kernel) <= 32 << 20 or kernel[56:60] != b"ARMd":
        p.error("Expected a bounded uncompressed ARM64 Image")
    text_offset, image_size, flags = struct.unpack_from("<QQQ", kernel, 8)
    load = 0x42000000
    if not len(kernel) <= image_size <= 64 << 20 or flags & 1 or (load-text_offset) % (2 << 20):
        p.error("ARM64 Image memory size, endianness or text-offset mismatch")
    if not 40 <= len(dtb) <= 2 << 20:
        p.error("Unbounded DTB")
    spec = importlib.util.spec_from_file_location("profile", Path(__file__).with_name("stock-kernel-profile.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    prop = lambda node, name: module.fit_property(dtb, node, name)
    if b"nokia,beacon10" not in prop("/", "compatible").rstrip(b"\0").split(b"\0"):
        p.error("Wrong DT board")
    for key, expected in (("cpu_type", b"\x02\x02\0\0"), ("soc_version_major", b"\x01\0\0\0"),
                          ("soc_version_minor", b"\x01\0\0\0")):
        if prop("/", key) != expected:
            p.error("Missing supported SoC LE property: " + key)
    args = prop("/chosen", "bootargs").rstrip(b"\0").decode().split()
    if [s for s in args if s.startswith("root=")] != ["root=/dev/mmcblk0p30"] or \
       "beacon10.handoff=stock-linux-v1" not in args:
        p.error("Wrong target root or handoff ABI")
    dtb_offset = (4096 + len(kernel) + 4095) & ~4095
    total = dtb_offset + len(dtb)
    if total > 32 << 20:
        p.error("Boot payload including header and DTB exceeds P29")
    header = bytearray(4096)
    struct.pack_into("<8sII8Q", header, 0, b"B10LINUX", 1, 4096, len(kernel), image_size,
                     len(dtb), 4096, dtb_offset, total, load, 0x58000000)
    header[80:112] = hashlib.sha256(kernel).digest()
    header[112:144] = hashlib.sha256(dtb).digest()
    header[176:176+len(b"stock-linux-v1")] = b"stock-linux-v1"
    header[144:176] = hashlib.sha256(header).digest()
    payload = bytes(header) + kernel + bytes(dtb_offset-4096-len(kernel)) + dtb
    report = {"layout": "stock-linux-v1", "boot_method": "stock Linux handoff",
              "handoff_protocol":"stock-linux-v1",
              "storage_layout":next((s.split('=',1)[1] for s in args if s.startswith('beacon10.storage=')),None),
              "kernel_load": load, "kernel_memory_bytes": image_size, "dtb_load": 0x58000000,
              "target_root": "/dev/mmcblk0p30", "overlay_partition": 36,
              "hardware_validated": False, "flashable_image": False, "boot_partition_format": "B10LINUX-v1",
              "handoff_module_included": False,
              "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        for name, data in (("Image", kernel), ("beacon10.dtb", dtb), ("boot.bin", payload))}}
    if a.image_out:
        temporary = a.image_out.with_name(a.image_out.name + ".b10tmp")
        with temporary.open("xb") as f:
            f.write(payload)
        os.replace(temporary, a.image_out)
        print(json.dumps(report, indent=2))
        return
    a.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    (a.out / "Image").write_bytes(kernel)
    (a.out / "beacon10.dtb").write_bytes(dtb)
    (a.out / "boot.bin").write_bytes(payload)
    (a.out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
