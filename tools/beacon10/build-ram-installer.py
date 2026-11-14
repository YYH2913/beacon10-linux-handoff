#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a self-contained RAM maintenance archive; never contacts a router."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
LAYOUT=json.loads((ROOT/'layout.json').read_text())
ENTER=r'''#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# Minimal rescue BusyBox need not include the id applet. The kernel's own
# proc status supplies the effective UID; the installer checks geteuid again.
effective_uid=
while read -r key real effective saved fs rest; do
    [ "$key" = 'Uid:' ] || continue
    effective_uid=$effective
    break
done < /proc/self/status
[ "$effective_uid" = 0 ] && [ "$(uname -r)" = 5.4.164 ] || exit 1
mode=$1
archive=$2
case "$mode" in
    --maintenance) [ "$#" = 2 ] ;;
    --install) echo 'Beacon10 live installation disabled: hardware validation incomplete.' >&2; exit 1 ;;
    *) echo 'Usage: enter-ram.sh --maintenance ARCHIVE' >&2; exit 2 ;;
esac
[ -f "$archive" ] || exit 1
[ "$(sha256sum "$archive" | cut -d' ' -f1)" = @ARCHIVE_SHA@ ] || exit 1
prefix=/tmp/beacon10-ram-$$
mkdir -m 700 "$prefix"
mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$prefix"
# The rescue tar applet can omit integrated gzip support. Keep decompression
# explicit and check its exit status before extracting the pinned archive.
gunzip -c "$archive" > "$prefix/maintenance.tar"
tar -xf "$prefix/maintenance.tar" -C "$prefix"
rm -f "$prefix/maintenance.tar"
chmod 700 "$prefix"
(cd "$prefix" && sha256sum -c etc/ram.sha256) || exit 1
chmod 700 "$prefix/sbin/upgraded"
"$prefix/bin/b10-install" --check-device "$prefix/install.bin" || exit 1
if [ "$(readlink /proc/1/exe)" = /bin/b10-loader ]; then
    # A partially completed installation boots the persistent recovery root,
    # whose PID1 is our loader rather than procd. Request the same RAM pivot.
    [ ! -e /tmp/beacon10-ram-request ] || exit 1
    # prefix is a separate tmpfs mount. A move from inside it is a cross-FS
    # copy/unlink, not an atomic publication. Stage on the destination /tmp.
    request_tmp=/tmp/beacon10-ram-request.$$
    [ ! -e "$request_tmp" ] || exit 1
    (set -C; printf '%s\n' "$prefix" > "$request_tmp") || exit 1
    chmod 600 "$request_tmp"
    mv "$request_tmp" /tmp/beacon10-ram-request
    echo 'RAM maintenance requested; SSH will disconnect while PID1 pivots.'
    exit 0
fi
# Do not run the OEM FIT validator on our custom bundle: that script can
# itself request a reboot. Temporarily bind a RAM-only validator accepting
# only this already hash-verified archive's exact bundle. The ROM file is not
# modified, and a failed handoff removes the bind before returning.
bundle_sha=$(sha256sum "$prefix/install.bin" | cut -d' ' -f1)
cat > "$prefix/validate-bundle" <<EOF
#!/bin/sh
if [ "\$1" = "$prefix/install.bin" ] && [ "\$(sha256sum "\$1" | cut -d' ' -f1)" = "$bundle_sha" ]; then
    echo '{"valid":true,"forceable":false,"allow_backup":false}'
else
    echo '{"valid":false,"forceable":false,"allow_backup":false}'
fi
EOF
chmod 700 "$prefix/validate-bundle"
mount --bind "$prefix/validate-bundle" /usr/libexec/validate_firmware_image
trap 'umount /usr/libexec/validate_firmware_image 2>/dev/null || true' EXIT
# procd stops its managed services, then execs our static PID1 in the RAM
# prefix. The RAM PID1 pivots out, kills remaining stock userspace, unmounts
# stock roots normally and detaches loop devices before opening the disk.
ubus call system sysupgrade "{\"prefix\":\"$prefix\",\"path\":\"$prefix/install.bin\",\"command\":\"beacon10-ram\"}"
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bootstrap-build',type=Path,required=True)
    p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--cross-compile',default='aarch64-linux-gnu-')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    os.umask(0o022)
    manifest=json.loads((a.bootstrap_build/'manifest.json').read_text())
    if not manifest['includes_migration_installer'] or manifest.get('layout')!=LAYOUT['id']:
        p.error('Expected the bootstrap with a migration writer')
    with a.bundle.open('rb') as f: header=f.read(4096)
    if len(header)!=4096 or header[:16]!=b'B10INST2\x02\0\0\0\0\x10\0\0' or header[40:72].hex()!=manifest['sha256']:
        p.error('RAM root and installation bundle must use the exact same bootstrap')
    a.out.mkdir(mode=0o700,parents=False,exist_ok=False)
    root=a.out/'rootfs';shutil.copytree(a.bootstrap_build/'rootfs',root,symlinks=True)
    shutil.copyfile(a.bundle,root/'install.bin')
    subprocess.run([a.cross_compile+'gcc','-Os','-static','-Wall','-Wextra','-Werror',
                    str(ROOT/'handoff/ram-init.c'),str(ROOT/'handoff/mounts.c'),'-o',str(root/'sbin/upgraded')],check=True)
    subprocess.run([a.cross_compile+'gcc','-Os','-static','-Wall','-Wextra','-Werror',
                    str(ROOT/'handoff/jump.c'),'-o',str(root/'bin/b10-jump')],check=True)
    files=sorted(p for p in root.rglob('*') if p.is_file() and not p.is_symlink())
    (root/'etc/ram.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root))+'\n' for p in files))
    archive=a.out/'ram-installer.tar.gz'
    subprocess.run(['tar','--sort=name','--owner=0','--group=0','--numeric-owner','-czf',str(archive),'-C',str(root),'.'],check=True)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    script=a.out/'enter-ram.sh';script.write_text(ENTER.replace('@ARCHIVE_SHA@',digest));script.chmod(0o755)
    report={'layout':LAYOUT['id'],'handoff_protocol':LAYOUT['handoff_protocol'],
            'archive_bytes':archive.stat().st_size,'archive_sha256':digest,
            'migration_automatic_with_install':True,'maintenance_has_no_storage_writes':True,
            'hardware_validated':False,'persistent_installation_allowed':False,'performed_hardware_writes':False}
    (a.out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
