#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
"""Offline-only Beacon10 GPT inspection/planning. Never opens a block device.

Plans stock-linux-v2 storage: retain signed HLOS and two small bootstrap roots.
Builds NEW metadata files, not a flashable full-disk image or live installer.
The factory backup GPT is known to be missing; the primary must pass both CRCs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import uuid
import zlib

LAYOUT = json.loads(Path(__file__).with_name("layout.json").read_text())
LINUX_DATA = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le


def regular_file(path):
    path = Path(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Only regular offline image files are accepted")
    return path


def parse_primary(header, table, sectors):
    if len(header) != 512 or header[:8] != b"EFI PART":
        raise ValueError("Missing primary GPT")
    revision, size, crc = struct.unpack_from("<III", header, 8)
    if revision != 0x10000 or not 92 <= size <= 512:
        raise ValueError("Unsupported GPT revision/header size")
    copy = bytearray(header[:size])
    copy[16:20] = bytes(4)
    if zlib.crc32(copy) != crc:
        raise ValueError("Invalid primary GPT header CRC")
    current, alternate, first, last = struct.unpack_from("<QQQQ", header, 24)
    lba, count, stride, entries_crc = struct.unpack_from("<QIII", header, 72)
    if (current, alternate, first, last, lba, stride) != (
            1, sectors - 1, 34, sectors - 34, 2, 128) or count not in (36, 128):
        raise ValueError("Unexpected GPT geometry")
    if len(table) < count * stride or zlib.crc32(table[:count * stride]) != entries_crc:
        raise ValueError("Invalid GPT partition-array CRC")
    result = {}
    for index in range(count):
        raw = table[index * stride:(index + 1) * stride]
        if raw[:16] == bytes(16):
            continue
        start, end = struct.unpack_from("<QQ", raw, 32)
        name = raw[56:128].decode("utf-16le").split("\0", 1)[0]
        if not first <= start <= end <= last:
            raise ValueError("Partition outside usable media")
        result[index + 1] = {"number": index + 1, "name": name,
                             "start": start, "size": end - start + 1, "raw": raw}
    extents = sorted(result.values(), key=lambda p: p["start"])
    for a, b in zip(extents, extents[1:]):
        if a["start"] + a["size"] > b["start"]:
            raise ValueError("Overlapping partitions")
    if len({p["name"] for p in extents}) != len(extents):
        raise ValueError("Duplicate partition labels")
    return result


def read_image(path):
    path = regular_file(path)
    if path.stat().st_size != LAYOUT["disk_sectors"] * 512:
        raise ValueError("Unsupported media size (expected the observed 1,954,545,664 bytes)")
    with path.open("rb") as f:
        mbr, header, table = f.read(512), f.read(512), f.read(16384)
        f.seek(-512, 2)
        tail = f.read(512)
    parts = parse_primary(header, table, LAYOUT["disk_sectors"])
    return mbr, header, parts, tail[:8] == b"EFI PART"


def validate_factory(parts):
    expected = {p["number"]: (p["name"], p["start"], p["size"])
                for p in LAYOUT["factory"]}
    actual = {n: (p["name"], p["start"], p["size"]) for n, p in parts.items()}
    if actual != expected:
        raise ValueError("Not the observed Beacon10 factory GPT; refusing to infer a layout")


def make_table(header, parts):
    validate_factory(parts)
    table = bytearray(16384)
    for p in LAYOUT["preserved"]:
        n = p["number"]
        table[(n - 1) * 128:n * 128] = parts[n]["raw"]
    for p in LAYOUT["relocated"] + LAYOUT["resized"]:
        n = p["number"]
        raw = bytearray(parts[n]["raw"])
        struct.pack_into("<QQ", raw, 32, p["start"], p["start"] + p["size"] - 1)
        table[(n - 1) * 128:n * 128] = raw
    disk_guid = header[56:72]
    for p in LAYOUT["volumes"]:
        n, start, size = p["number"], p["start"], p["size"]
        raw = bytearray(128)
        raw[:16] = LINUX_DATA
        identity = bytearray(hashlib.sha256(disk_guid + ('beacon10-'+LAYOUT['id']+'/').encode() + p["name"].encode()).digest()[:16])
        identity[7] = (identity[7] & 15) | 0x40
        identity[8] = (identity[8] & 63) | 0x80
        raw[16:32] = identity
        struct.pack_into("<QQQ", raw, 32, start, start + size - 1, 0)
        name = p["name"].encode("utf-16le")
        raw[56:56 + len(name)] = name
        table[(n - 1) * 128:n * 128] = raw
    return bytes(table)


def make_header(original, table, backup=False):
    header = bytearray(original)
    end = LAYOUT["disk_sectors"] - 1
    struct.pack_into("<QQ", header, 24, end if backup else 1, 1 if backup else end)
    struct.pack_into("<Q", header, 72, end - 32 if backup else 2)
    # Factory advertises only 36 entries inside a full 32-sector reserved area.
    # stock-linux-v1 needs P37. Expand to 128 entries without moving P1-P25.
    struct.pack_into("<II", header, 80, 128, 128)
    struct.pack_into("<I", header, 88, zlib.crc32(table))
    size = struct.unpack_from("<I", header, 12)[0]
    header[16:20] = bytes(4)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:size]))
    return bytes(header)


def plan(parts, backup_present):
    validate_factory(parts)
    spans = sorted(LAYOUT["preserved"] + LAYOUT["resized"] + LAYOUT["relocated"] + LAYOUT["volumes"], key=lambda p: p["start"])
    cursor = LAYOUT["first_usable_lba"]
    for p in spans:
        if p["start"] != cursor:
            raise ValueError("Layout contains overlap or unused sectors")
        cursor += p["size"]
    if cursor != LAYOUT["last_usable_lba"] + 1:
        raise ValueError("Layout fails to use all usable sectors")
    writable = sum(p["size"] * 512 for p in LAYOUT["volumes"]
                   if p["name"] == "rootfs_data")
    return {"layout": LAYOUT, "writable_bytes_before_filesystem_overhead": writable,
            "unallocated_usable_sectors": 0, "source_backup_header_present": backup_present,
            "preserved_prefix_entries_byte_identical": True, "relocated_identity_guids_preserved": True, "changes_source_image": False,
            "factory_userspace_and_configuration_will_be_replaced": True,
            "signed_factory_hlos_preserved": True, "stock_bootcmd_preserved": True,
            "environment_bytes_preserved_during_relocation": True,
            "boot_success_counter_ack_required": True,
            "bootstrap_rootfs_guids_preserved": True,
            "migration_engine_provided": False, "automatic_installation_available": False,
            "installation_blocker": "Stock Linux handoff and RAM migration installer require hardware validation",
            "requires_on_device_install_transaction": True, "hardware_validated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path, help="Create a NEW directory containing GPT metadata only")
    args = parser.parse_args()
    mbr, header, parts, backup_present = read_image(args.image)
    report = plan(parts, backup_present)
    if args.out:
        # Do all parsing and construction before creating the output directory.
        table = make_table(header, parts)
        primary = make_header(header, table)
        parse_primary(primary, table, LAYOUT["disk_sectors"])
        files = {"gpt-primary-34-sectors.bin": mbr + primary + table,
                 "gpt-backup-33-sectors.bin": table + make_header(header, table, True)}
        args.out.mkdir(parents=False, exist_ok=False)
        for name, data in files.items():
            (args.out / name).write_bytes(data)
        report["metadata_files"] = {name: {"bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()}
        (args.out / "plan.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
