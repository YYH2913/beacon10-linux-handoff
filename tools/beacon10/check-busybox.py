#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the ARM64 BusyBox mount ABI without mounting anything.

BusyBox built without FEATURE_MOUNT_FLAGS passes nosuid/nodev as filesystem
options instead of mount(2) flags. QSDK 6.6 tmpfs rejects those options. A
host kernel accepting them is not a sufficient test: inspect the emulated
syscall to a deliberately nonexistent target instead.
"""
import argparse
import gzip
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def check_mount_flags(busybox, qemu=None):
    qemu = qemu or shutil.which('qemu-aarch64-static') or shutil.which('qemu-aarch64')
    if not qemu:
        raise ValueError('qemu-aarch64[-static] is required to validate BusyBox mount flags')
    with tempfile.TemporaryDirectory(prefix='beacon10-busybox-check-') as tmp:
        # The child is never created. Running as an unprivileged user is fine.
        target = Path(tmp) / 'does-not-exist'
        result = subprocess.run([qemu, '-strace', str(Path(busybox).resolve()),
                                 'mount', '-t', 'tmpfs', '-o', 'mode=0700,nosuid,nodev',
                                 'tmpfs', str(target)], capture_output=True, text=True, timeout=15)
    calls = [line for line in result.stderr.splitlines() if ' mount("tmpfs",' in line]
    if len(calls) != 1 or 'MS_NOSUID' not in calls[0] or 'MS_NODEV' not in calls[0] or result.returncode == 0:
        raise ValueError('BusyBox must implement mount(2) nosuid/nodev flags; rebuild with CONFIG_FEATURE_MOUNT_FLAGS=y')


def check_recovery_archive(busybox, qemu=None):
    """Exercise the rescue entry's separate gunzip/tar with ordinary files."""
    qemu = qemu or shutil.which('qemu-aarch64-static') or shutil.which('qemu-aarch64')
    if not qemu:
        raise ValueError('qemu-aarch64[-static] is required to validate recovery extraction')
    command = [qemu, str(Path(busybox).resolve())]
    content = b'Beacon10 maintenance fixture\n'
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo('checked-file'); member.size = len(content); member.mode = 0o600
        archive.addfile(member, io.BytesIO(content))
        member = tarfile.TarInfo('checked-link'); member.type = tarfile.SYMTYPE; member.linkname = 'checked-file'
        archive.addfile(member)
    with tempfile.TemporaryDirectory(prefix='beacon10-recovery-archive-') as tmp:
        root = Path(tmp); compressed = root/'fixture.tar.gz'; uncompressed = root/'fixture.tar'
        compressed.write_bytes(gzip.compress(packed.getvalue(), mtime=0))
        with uncompressed.open('wb') as output:
            subprocess.run([*command, 'gunzip', '-c', str(compressed)], stdout=output,
                           stderr=subprocess.PIPE, timeout=15, check=True)
        subprocess.run([*command, 'tar', '-xf', str(uncompressed), '-C', str(root)],
                       capture_output=True, timeout=15, check=True)
        if ((root/'checked-file').read_bytes() != content or
            (root/'checked-file').stat().st_mode & 0o777 != 0o600 or
            not (root/'checked-link').is_symlink() or (root/'checked-link').readlink() != Path('checked-file')):
            raise ValueError('BusyBox recovery archive extraction did not preserve files, private mode or symlinks')
        # A damaged stream must fail before the caller proceeds to extraction.
        compressed.write_bytes(compressed.read_bytes()[:-4])
        result = subprocess.run([*command, 'gunzip', '-c', str(compressed)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
        if result.returncode == 0:
            raise ValueError('BusyBox gunzip accepted a truncated maintenance archive')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('busybox', type=Path)
    p.add_argument('--qemu')
    p.add_argument('--recovery-archive', action='store_true')
    a = p.parse_args()
    check_mount_flags(a.busybox, a.qemu)
    if a.recovery_archive:
        check_recovery_archive(a.busybox, a.qemu)
        print('PASS: recovery gunzip/tar preserves bytes, private mode and symlinks; truncated gzip rejected')
    print('PASS: BusyBox passes nosuid/nodev as mount(2) flags; no mount performed')
