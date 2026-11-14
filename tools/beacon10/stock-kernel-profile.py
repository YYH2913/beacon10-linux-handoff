#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Extract a SHA-bound stock kernel profile for a read-only handoff probe.

Reads only a regular backup file. Never reads ART/RI/environment records or
opens a block device. Output includes owner-local kernel bytes, not redistributable
firmware. The probe checks function addresses/bytes and never calls shutdown.
"""
import argparse
import ctypes as C
import ctypes.util
import gzip
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct

STOCK_APPSBL_SHA256 = "8a11218e58def68f59b4d9c63c90adcf23b31716c825e1da4815e4aabfd5f1a8"
STOCK_KERNEL_SHA256 = "ea0d53e08791abcb2fdf8536be9e7f791891ef348c5ba79f0cdb309b47be4c44"
KERNEL_VA_BASE = 0xffffffc010080000
REQUIRED = ("kallsyms_lookup_name", "kernel_restart_prepare", "migrate_to_reboot_cpu",
            "machine_shutdown", "__freeze_secondary_cpus", "__flush_dcache_area", "__flush_icache_range",
            "cpu_hotplug_enable", "cpus_are_stuck_in_kernel", "syscore_shutdown",
            "__dev_get_by_name", "__dev_get_by_index", "dev_close", "device_shutdown",
            "__usermodehelper_disable")


def symbols(image):
    anchor = struct.pack("<Q", KERNEL_VA_BASE)
    if image.count(anchor) != 1:
        raise ValueError("Unknown relative kallsyms anchor")
    base_at = image.index(anchor)
    count = struct.unpack_from("<I", image, base_at + 8)[0]
    if not 10000 < count < 100000:
        raise ValueError("Unknown kallsyms count")
    offsets = base_at - ((count * 4 + 7) & ~7)
    pos = base_at + 16
    rows = []
    for i in range(count):
        size = image[pos]
        body = image[pos + 1:pos + 1 + size]
        if not size or len(body) != size or body[0] not in b"TtWwDdRrAaBbVvNn" or not all(32 < c < 127 for c in body):
            raise ValueError("Malformed uncompressed kallsyms")
        relative = struct.unpack_from("<I", image, offsets + i * 4)[0]
        rows.append({"name": body[1:].decode(), "type": chr(body[0]),
                     "address": KERNEL_VA_BASE + relative, "offset": relative})
        pos += size + 1
    if not all(a["offset"] <= b["offset"] for a, b in zip(rows, rows[1:])):
        raise ValueError("Unsorted kallsyms")
    return rows


def fit_property(blob, path, prop):
    fdt = C.CDLL(C.util.find_library("fdt"))
    fdt.fdt_check_full.argtypes = [C.c_void_p, C.c_size_t]
    fdt.fdt_path_offset.argtypes = [C.c_void_p, C.c_char_p]
    fdt.fdt_path_offset.restype = C.c_int
    fdt.fdt_getprop.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.POINTER(C.c_int)]
    fdt.fdt_getprop.restype = C.c_void_p
    buf = C.create_string_buffer(blob)
    if fdt.fdt_check_full(buf, len(blob)):
        raise ValueError("Malformed FIT")
    node = fdt.fdt_path_offset(buf, path.encode())
    size = C.c_int()
    data = fdt.fdt_getprop(buf, node, prop.encode(), C.byref(size)) if node >= 0 else None
    if not data or not 0 < size.value <= len(blob):
        raise ValueError("Missing FIT property: " + path + ":" + prop)
    return C.string_at(data, size.value)


def runtime_codes(image, row):
    """The one alternative intersecting these fingerprints in this exact Image.

    ARM64's CTR workaround substitutes an ADRP/LDR for MRS CTR_EL0/NOP.
    Its replacement and original are on the same 4K page, so the ADRP does
    not need relocation. Refuse changed metadata instead of masking bytes.
    """
    original = image[row["offset"]:row["offset"] + 16]
    if row["name"] != "__flush_dcache_area":
        return [original.hex()]
    at = 0x95fecc
    orig, repl, cap, olen, rlen = struct.unpack_from("<iiHBB", image, at)
    if (at + orig, at + 4 + repl, cap, olen, rlen) != (0x20838, 0x20b78, 31, 8, 8):
        raise ValueError("Unknown cache-maintenance alternative")
    if original[:8].hex() != "23003bd51f2003d5" or (at + orig) >> 12 != (at + 4 + repl) >> 12:
        raise ValueError("Unknown cache-maintenance instruction relocation")
    replacement = image[at + 4 + repl:at + 4 + repl + rlen]
    if replacement.hex() != "634d00f063c445f9":
        raise ValueError("Unknown CTR workaround")
    return [original.hex(), (replacement + original[8:]).hex()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("backup", type=Path)
    p.add_argument("--out", type=Path, required=True, help="NEW owner-local output directory")
    a = p.parse_args()
    spec = importlib.util.spec_from_file_location("gpt", Path(__file__).with_name("stock-linux-gpt.py"))
    gpt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gpt)
    disk = gpt.regular_file(a.backup / "mmcblk0.img")
    _, _, parts, _ = gpt.read_image(disk)
    gpt.validate_factory(parts)
    with disk.open("rb") as f:
        def partition(n):
            part = parts[n]
            f.seek(part["start"] * 512)
            return f.read(part["size"] * 512)
        appsbl = partition(18)
        if hashlib.sha256(appsbl).hexdigest() != STOCK_APPSBL_SHA256:
            raise ValueError("Only the observed retail APPSBL is supported")
        hlos = partition(24)
    if hlos[:4] != b"\x7fELF" or hlos[0x2000:0x2004] != b"\xd0\x0d\xfe\xed":
        raise ValueError("Unexpected stock HLOS wrapper")
    fit = hlos[0x2000:]
    if fit_property(fit, "/images/kernel@1", "compression") != b"lzma\0":
        raise ValueError("Unexpected stock compression")
    compressed = fit_property(fit, "/images/kernel@1", "data")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=64 << 20)
    image = decoder.decompress(compressed, max_length=64 << 20)
    if not decoder.eof or len(image) < 64 or image[56:60] != b"ARMd":
        raise ValueError("Unbounded/invalid stock ARM64 Image")
    if hashlib.sha256(image).hexdigest() != STOCK_KERNEL_SHA256:
        raise ValueError("Only the audited retail LJL.J17p01 kernel is supported")
    start = image.index(b"IKCFG_ST") + 8
    end = image.index(b"IKCFG_ED", start)
    config = gzip.decompress(image[start:end]).decode()
    for required in ("CONFIG_KALLSYMS_UNCOMPRESSED=y", "CONFIG_MODULES=y", "# CONFIG_MODVERSIONS is not set",
                     "# CONFIG_MODULE_SIG is not set", "# CONFIG_KEXEC is not set", "CONFIG_HOTPLUG_CPU=y"):
        if required not in config.splitlines():
            raise ValueError("Unsupported stock config: " + required)
    rows = symbols(image)
    selected = []
    for name in REQUIRED:
        matches = [r for r in rows if r["name"] == name and r["type"] in "Tt"]
        if len(matches) != 1:
            raise ValueError("Ambiguous/missing stock function: " + name)
        row = dict(matches[0])
        row["first_16_bytes"] = image[row["offset"]:row["offset"] + 16].hex()
        row["accepted_runtime_code"] = runtime_codes(image, row)
        selected.append(row)
    banner_at = image.index(b"Linux version ")
    banner = image[banner_at:image.index(b"\0", banner_at)].decode()
    report = {"profile": "retail-ljl-j17p01", "stock_appsbl_sha256": STOCK_APPSBL_SHA256,
              "stock_hlos_sha256": hashlib.sha256(hlos).hexdigest(),
              "stock_kernel_sha256": hashlib.sha256(image).hexdigest(),
              "stock_kernel_banner": banner, "stock_kernel_config_sha256": hashlib.sha256(config.encode()).hexdigest(),
              "symbol_count": len(rows), "functions": selected,
              "standard_kexec_present": False, "profile_supports_explicit_handoff": True,
              "hardware_handoff_validated": False, "performed_hardware_writes": False}
    # All validation precedes creation. No original per-unit records are copied.
    a.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    (a.out / "stock-Image").write_bytes(image)
    (a.out / "stock.config").write_text(config)
    (a.out / "System.map").write_text("".join(f"{r['address']:016x} {r['type']} {r['name']}\n" for r in rows))
    (a.out / "profile.json").write_text(json.dumps(report, indent=2) + "\n")
    header = ["/* Generated from the SHA-bound stock Image; not a hardware validation. */",
              "struct beacon10_stock_function { const char *name; unsigned long address; unsigned int variants; unsigned char code[2][16]; };",
              "static const struct beacon10_stock_function beacon10_stock_functions[] = {"]
    for row in selected:
        variants = ["{ " + ", ".join("0x" + code[i:i+2] for i in range(0, 32, 2)) + " }"
                    for code in row["accepted_runtime_code"]]
        header.append(f'  {{ "{row["name"]}", 0x{row["address"]:x}UL, {len(variants)}, {{ ' + ", ".join(variants) + ' } },')
    header.append("};")
    (a.out / "stock-profile.h").write_text("\n".join(header) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "functions"}, indent=2))


if __name__ == "__main__":
    main()
