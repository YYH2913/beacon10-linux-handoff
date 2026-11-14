#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the stock-Linux handoff rootfs; emits ordinary files, never flashes.

The resulting rootfs fails into a local rescue shell unless the exact new GPT,
CID-bound state and payload hashes are present. It includes an explicit
RAM-only migration command, but never invokes that command automatically.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
LAYOUT=json.loads((ROOT/'layout.json').read_text())


def prepare_root(root):
    """Image-public paths must not inherit the operator's private umask."""
    for name in ('bin','sbin','dev','proc','sys','tmp','run','oldroot','root/.ssh','etc',
                 'lib/modules/5.4.164','lib/firmware'):
        (root/name).mkdir(parents=True,exist_ok=True)
    for directory in (root,*root.rglob('*')):
        if directory.is_dir():
            private=directory.relative_to(root).parts[:1]==('root',)
            directory.chmod(0o700 if private else 0o755)


INIT=r'''#!/bin/sh
export PATH=/bin:/sbin
export HOME=/
export TERM=vt100
umask 077
mount -n -t proc proc /proc
mount -n -t sysfs sysfs /sys
mount -n -t tmpfs -o mode=0755,nosuid tmpfs /dev
mknod -m 600 /dev/console c 5 1
mknod -m 666 /dev/null c 1 3
exec </dev/console >/dev/console 2>&1
mount -n -t tmpfs -o mode=0700,nosuid,nodev tmpfs /tmp
mount -n -t tmpfs -o mode=0755,nosuid,nodev tmpfs /lib/firmware
echo 'Beacon10 stock Linux bootstrap / stock-linux-v1'
if [ "$(uname -r)" = 5.4.164 ] && (cd / && sha256sum -c /etc/bootstrap.sha256); then
    # exec preserves PID1: no original startup, Wi-Fi or cloud services run.
    exec /bin/b10-loader --boot
fi
echo 'Bootstrap self-check failed. No partition writes, handoff or reboot attempted.'
while :; do /bin/sh; sleep 1; done
'''


def check_module_manifest(validation, kernel_module):
    if validation.get('diagnostic_only'):
        raise ValueError('Diagnostic handoff modules must never be included in a persistent bootstrap')
    if validation.get('power_protocol_version')!=1 or not validation.get('stock_power_v1',{}).get('committed_channel_and_power_snapshot'):
        raise ValueError('Bootstrap requires a real stock-power-v1 handoff module')
    if not validation['handoff_implemented'] or hashlib.sha256(kernel_module.read_bytes()).hexdigest()!=validation['probe_sha256']:
        raise ValueError('Expected hash/ABI-validated real handoff module')


def check_recovery_applets(busybox):
    qemu = shutil.which('qemu-aarch64-static') or shutil.which('qemu-aarch64')
    if not qemu:
        raise ValueError('qemu-aarch64[-static] is required to validate recovery applets')
    applets = subprocess.check_output([qemu, str(busybox.resolve()), '--list'], text=True).splitlines()
    if not {'udhcpd', 'ip', 'mdev', 'mount', 'insmod'}.issubset(applets):
        raise ValueError('Bootstrap BusyBox requires LAN DHCP and recovery network applets')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--busybox",type=Path,required=True)
    p.add_argument("--module-build",type=Path,required=True)
    p.add_argument("--stock-root",type=Path,required=True,help="Owner-local extracted stock rootfs for LAN recovery modules")
    p.add_argument("--dropbear",type=Path,required=True,help="Static ARM64 dropbearmulti with public-key authentication")
    p.add_argument("--authorized-key",type=Path,required=True,help="SSH public key; never a private key")
    p.add_argument("--cross-compile",default="aarch64-linux-gnu-")
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    spec=importlib.util.spec_from_file_location("probe",ROOT/"build-bootstrap-probe.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.static_arm64(a.busybox)
    module.static_arm64(a.dropbear)
    spec=importlib.util.spec_from_file_location("busybox_check",ROOT/"check-busybox.py")
    busybox_check=importlib.util.module_from_spec(spec);spec.loader.exec_module(busybox_check)
    busybox_check.check_mount_flags(a.busybox)
    busybox_check.check_recovery_archive(a.busybox)
    check_recovery_applets(a.busybox)
    key=a.authorized_key.read_text().strip()
    if not key.startswith(('ssh-ed25519 ','ssh-rsa ','ecdsa-sha2-')) or '\n' in key or 'PRIVATE' in key:
        p.error('Expected one SSH public key')
    kernel_module=a.module_build/"beacon10-handoff.ko"
    validation=json.loads((a.module_build/"probe-validation.json").read_text())
    try:check_module_manifest(validation,kernel_module)
    except ValueError as e:p.error(str(e))
    # Only the build process changes mask. The output parent and SSH material
    # still have explicit 0700/0600; the recovery PID1 keeps its private 077.
    os.umask(0o022)
    a.out.mkdir(mode=0o700,parents=False,exist_ok=False)
    root=a.out/"rootfs"
    prepare_root(root)
    src=ROOT/'handoff'
    subprocess.run([a.cross_compile+'gcc','-Os','-static','-Wall','-Wextra','-Werror',
                    str(src/'loader.c'),str(src/'storage.c'),str(src/'sha256.c'),str(src/'format.c'),
                    '-o',str(root/'bin/b10-loader')],check=True)
    # The migration writer is shipped as a separate, explicit command.  It
    # refuses a mounted stock/QSDK root and requires the literal confirmation
    # token; booting never repartitions or runs migration. The normal loader
    # does record a bounded boot attempt in the eMMC journal.
    subprocess.run([a.cross_compile+'gcc','-Os','-static','-Wall','-Wextra','-Werror',
                    str(src/'install-main.c'),str(src/'install.c'),str(src/'storage.c'),
                    str(src/'sha256.c'),str(src/'format.c'),
                    '-o',str(root/'bin/b10-install')],check=True)
    shutil.copyfile(a.busybox,root/'bin/busybox');(root/'bin/busybox').chmod(0o755)
    for name in ('sh','cat','echo','printf','true','false','test','[','mkdir','mknod','mount','umount','sleep','sync',
                 'insmod','rmmod','ls','uname','readlink','dmesg','sha256sum','ps','kill','ip','mdev','tar','gzip','gunzip',
                 'cp','rm','mv','chmod','cut','grep','wc','sort','reboot'):
        (root/'bin'/name).symlink_to('busybox')
    shutil.copyfile(a.dropbear,root/'bin/dropbearmulti'); (root/'bin/dropbearmulti').chmod(0o755)
    for name in ('dropbear','dropbearkey'): (root/'bin'/name).symlink_to('dropbearmulti')
    (root/'root/.ssh').chmod(0o700)
    (root/'root/.ssh/authorized_keys').write_text(key+'\n');(root/'root/.ssh/authorized_keys').chmod(0o600)
    (root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
    (root/'etc/shadow').write_text('root:*:0:0:99999:7:::\n')
    (root/'etc/group').write_text('root:x:0:\n')
    (root/'etc/shells').write_text('/bin/sh\n')
    (root/'etc/beacon10-storage-layout').write_text(LAYOUT['id']+'\n')
    shutil.copyfile(src/'recovery.sh',root/'sbin/beacon10-recovery');(root/'sbin/beacon10-recovery').chmod(0o755)
    for name in ('qca-ssdk.ko','qca-nss-dp.ko'):
        shutil.copyfile(a.stock_root/'lib/modules/5.4.164'/name,root/'lib/modules/5.4.164'/name)
    # A RAM pivot keeps stock netfilter rules. Include only the owner's
    # iptables executable and its ELF dependency closure for recovery cleanup.
    pending=[(a.stock_root/'usr/sbin/xtables-legacy-multi','bin/xtables-legacy-multi')]
    seen=set()
    while pending:
        original,destination=pending.pop()
        if destination in seen: continue
        seen.add(destination);(root/destination).parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original.resolve(),root/destination)
        text=subprocess.check_output([a.cross_compile+'readelf','-d',str(original)]).decode()
        for dependency in re.findall(r'\(NEEDED\).*\[([^]]+)\]',text):
            candidates=[a.stock_root/'lib'/dependency,a.stock_root/'usr/lib'/dependency]
            found=next((v for v in candidates if v.is_file()),None)
            if not found: raise ValueError('Missing stock recovery ELF dependency: '+dependency)
            if not found.resolve().is_relative_to(a.stock_root.resolve()):
                raise ValueError('Recovery ELF dependency escapes the owner-local stock root: '+dependency)
            pending.append((found,str(found.relative_to(a.stock_root))))
    (root/'lib/ld-musl-aarch64.so.1').symlink_to('libc.so')
    # The musl libc is also the ELF interpreter. copyfile() leaves it at
    # 0644 under our build umask; the kernel then refuses execve(iptables).
    # Shared libraries need only read access, but the interpreter needs X.
    (root/'lib/libc.so').chmod(0o755)
    (root/'bin/iptables').symlink_to('xtables-legacy-multi')
    (root/'bin/xtables-legacy-multi').chmod(0o755)
    shutil.copyfile(kernel_module,root/'lib/modules/5.4.164/beacon10-handoff.ko')
    (root/'sbin/init').write_text(INIT);(root/'sbin/init').chmod(0o755)
    files=sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and not p.is_symlink())
    (root/'etc/bootstrap.sha256').write_text(''.join(hashlib.sha256((root/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in files))
    image=a.out/'bootstrap.squashfs'
    subprocess.run(['mksquashfs',str(root),str(image),'-noappend','-comp','xz','-b','262144','-all-root','-no-xattrs',
                    '-processors','4','-p','dev/console c 0600 0 0 5 1','-p','dev/null c 0666 0 0 1 3'],check=True)
    if image.stat().st_size>6<<20:raise ValueError('Bootstrap exceeds snapshot allowance')
    report={'layout':LAYOUT['id'],'handoff_protocol':LAYOUT['handoff_protocol'],
            'runtime_handoff_implemented':True,'hardware_validated':False,
            'power_protocol_version':1,'persistent_installation_allowed':False,
            'attempt_committed_before_CPU_policy_and_module_init':True,
            'image_public_directory_mode':'0755','image_root_and_SSH_directory_mode':'0700',
            'recovery_LAN_DHCP_without_default_route_or_DNS':True,
            'includes_migration_installer':True,'migration_command':'b10-install --install RAM_BUNDLE --confirm ERASE-STOCK-ROOTS-AND-USER-DATA',
            'performed_hardware_writes':False,
            'bytes':image.stat().st_size,'sha256':hashlib.sha256(image.read_bytes()).hexdigest(),
            'module_validation':validation,'loading_this_squashfs_has_not_been_hardware_tested':True}
    (a.out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
