#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Package bootstrap/kernel/rootfs for the Beacon10 RAM migration transaction."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('storage_layout',ROOT/'storage-layout.py')
storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bootstrap', required=True, type=Path)
    p.add_argument('--boot', required=True, type=Path)
    p.add_argument('--rootfs', required=True, type=Path)
    p.add_argument('--verifier', required=True, type=Path, help='Host b10-loader binary')
    p.add_argument('--out', required=True, type=Path, help='NEW output file')
    a = p.parse_args()
    subprocess.run([str(a.verifier.resolve()), '--verify', str(a.boot.resolve())], check=True)
    paths = (a.bootstrap, a.boot, a.rootfs)
    storage.validate()
    limits = (storage.BOOTSTRAP_BYTES, storage.KERNEL_BYTES, storage.ROOTFS_BYTES)
    header = bytearray(4096)
    header[:8] = b'B10INST2'
    struct.pack_into('<II', header, 8, 2, 4096)
    offset = 4096
    records = []
    for i, (path, limit) in enumerate(zip(paths, limits)):
        data = path.read_bytes()
        if not 96 <= len(data) <= limit:
            p.error('Component outside reserved capacity: ' + str(path))
        if i != 1:
            if data[:4] != b'hsqs' or not 96 <= struct.unpack_from('<Q', data, 40)[0] <= len(data):
                p.error('Invalid SquashFS: ' + str(path))
            # Parse the actual filesystem and demand the persistent entry point.
            listing = subprocess.check_output(['unsquashfs', '-ll', str(path)], stderr=subprocess.STDOUT).decode()
            if 'squashfs-root/sbin/init' not in listing:
                p.error('Missing /sbin/init: ' + str(path))
            try:storage.check_root_marker(path)
            except (ValueError,subprocess.SubprocessError) as error:p.error(str(error))
        digest = hashlib.sha256(data).digest()
        struct.pack_into('<QQ32s', header, 24 + 48*i, offset, len(data), digest)
        records.append({'offset': offset, 'bytes': len(data), 'sha256': digest.hex()})
        offset = (offset + len(data) + 4095) & ~4095
    struct.pack_into('<Q', header, 16, offset)
    header[168:200] = hashlib.sha256(header).digest()
    with a.out.open('xb') as f:
        f.write(header)
        for path, record in zip(paths, records):
            if f.tell() != record['offset']:
                raise ValueError('Bundle alignment mismatch')
            with path.open('rb') as src:
                while block := src.read(1 << 20):
                    f.write(block)
            f.write(bytes((-f.tell()) % 4096))
    print(json.dumps({'layout': storage.STORAGE_ID, 'handoff_protocol':storage.HANDOFF_ID,
                      'installation_format':'B10INST2','bytes': offset, 'components': records,
                      'hardware_validated': False, 'persistent_installation_allowed': False,
                      'per_unit_identity_in_bundle': False}, indent=2))


if __name__ == '__main__':
    main()
