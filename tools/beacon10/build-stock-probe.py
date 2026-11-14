#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a probe or explicit handoff module; verify the stock module ABI.

Use stock-kernel-profile.py first. The source kernel needs modules_prepare with
the extracted config. No force-load, vermagic patch or disabled version check is
used. Without --handoff the read-only probe cannot shut down CPUs or jump.
With --handoff loading only stages RAM; an explicit root ioctl commits the jump.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess


def elf_module(path):
    b = path.read_bytes()
    if b[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected little-endian ELF64 module")
    at = struct.unpack_from("<Q", b, 40)[0]
    stride, count, names_index = struct.unpack_from("<HHH", b, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", b, at + i * stride) for i in range(count)]
    name_section = sections[names_index]
    names = b[name_section[4]:name_section[4] + name_section[5]]
    cstr = lambda data, off: data[off:data.index(b"\0", off)].decode()
    by_name = {cstr(names, s[0]): s for s in sections}
    info = by_name[".modinfo"]
    values = dict(s.split(b"=", 1) for s in b[info[4]:info[4]+info[5]].split(b"\0") if b"=" in s)
    sym = by_name[".symtab"]
    strings = sections[sym[6]]
    st = b[strings[4]:strings[4]+strings[5]]
    symbols = [struct.unpack_from("<IBBHQQ", b, n) for n in range(sym[4], sym[4]+sym[5], sym[9])]
    undefined = [cstr(st, s[0]) for s in symbols if s[3] == 0 and s[0] and s[1] >> 4 != 2]
    rel = by_name[".rela.gnu.linkonce.this_module"]
    callbacks = {}
    for pos in range(rel[4], rel[4]+rel[5], rel[9]):
        off, info, addend = struct.unpack_from("<QQq", b, pos)
        name = cstr(st, symbols[info >> 32][0])
        if name in ("init_module", "cleanup_module"):
            callbacks[name] = off
    return {"vermagic": values[b"vermagic"].decode(),
            "module_struct_bytes": by_name[".gnu.linkonce.this_module"][5],
            "module_struct_alignment": by_name[".gnu.linkonce.this_module"][8],
            "callbacks": callbacks, "undefined": undefined}


def stock_exports(image, rows, include_data=False):
    positions = {m.start(): m.group().decode() for m in re.finditer(
        rb"(?<=\x00)[A-Za-z_][A-Za-z0-9_.$]{0,127}(?=\x00)", image)}
    exports = {}
    for off in range(4, len(image)-8, 4):
        name = positions.get(off + struct.unpack_from("<i", image, off)[0])
        if not name:
            continue
        value = off - 4 + struct.unpack_from("<i", image, off - 4)[0]
        namespace = off + 4 + struct.unpack_from("<i", image, off + 4)[0]
        # The probe imports text symbols only. Require both the export entry
        # and the independently decoded kallsyms address to agree.
        match = rows.get(name) == value
        if include_data and name not in rows:
            memory = struct.unpack_from("<Q", image, 16)[0]
            match = 0 <= value < memory
        if match and 0 <= namespace < len(image) and image[namespace] == 0:
            exports[name] = value
    return exports


def dp_profile(path):
    """Bind complete EDMA stop functions, adjusting only exact ctx relocations.

    The vendor NSS-DP has no .shutdown callback. Its ndo_stop masks NAPI/IRQs
    but does not disable DMA rings. Reuse the actual vendor ring-stop routines
    without guessing struct net_device or EDMA context layouts.
    """
    b=path.read_bytes()
    if hashlib.sha256(b).hexdigest()!='151e6897ef1f0593f72ce654105cc387d9d9e99437286901eb7559656f5610e3':
        raise ValueError('Unsupported owner stock qca-nss-dp.ko')
    at=struct.unpack_from('<Q',b,40)[0];stride,count,names_index=struct.unpack_from('<HHH',b,58)
    sections=[struct.unpack_from('<IIQQQQIIQQ',b,at+i*stride) for i in range(count)]
    def blob(s):return b[s[4]:s[4]+s[5]]
    names=blob(sections[names_index]);cstr=lambda data,off:data[off:data.index(b'\0',off)].decode()
    byname={cstr(names,s[0]):(i,s) for i,s in enumerate(sections)}
    sym=byname['.symtab'][1];st=blob(sections[sym[6]])
    symbols=[struct.unpack_from('<IBBHQQ',b,n) for n in range(sym[4],sym[4]+sym[5],sym[9])]
    symbols_byname={cstr(st,s[0]):s for s in symbols}
    ctx=symbols_byname['edma_gbl_ctx'];text_index,text=byname['.text'];rel=byname['.rela.text'][1]
    header=['/* Generated only from the SHA-bound owner stock qca-nss-dp module. */',
            'struct b10_dp_reloc { unsigned short offset, type; };',
            'struct b10_dp_function { const char *name; unsigned int bytes, reloc_count; unsigned char code[256]; struct b10_dp_reloc reloc[8]; };',
            'static const struct b10_dp_function b10_dp_functions[] = {']
    for name in ('edma_cfg_tx_rings_disable','edma_cfg_rx_rings_disable','edma_disable_interrupts'):
        s=symbols_byname[name];offset,size=s[4:6]
        if s[3]!=text_index or size>256 or size%4:raise ValueError('Unexpected EDMA text layout')
        fix=[]
        for pos in range(rel[4],rel[4]+rel[5],rel[9]):
            off,info,addend=struct.unpack_from('<QQq',b,pos)
            if not offset<=off<offset+size:continue
            target=symbols[info>>32];kind=info&0xffffffff
            if kind not in (275,277) or target[3]!=ctx[3] or target[4]+addend!=ctx[4]:
                raise ValueError('Unexpected EDMA relocation; no instruction masking allowed')
            fix.append((off-offset,kind))
        code=blob(text)[offset:offset+size]
        header.append('  { "qca_nss_dp:'+name+'", '+str(size)+', '+str(len(fix))+', { '+
                      ','.join('0x%02x'%v for v in code)+' }, { '+','.join('{%d,%d}'%v for v in fix)+' } },')
    header.append('};')
    return '\n'.join(header)+'\n'


def diagnostic_rpm_source(source,inherit=False,power=False,cpr=False):
    """Instrument only a private build; fail closed if production anchors move."""
    if 'stock-rpm-endpoint.h' in source:
        raise ValueError('RPM diagnostic already injected')
    if power and not inherit:raise ValueError('Power snapshot requires RPM inheritance')
    if cpr and not power:raise ValueError('CPR quiescence requires power snapshot')
    edits=(
        ('static void __iomem *edma;', 'static void __iomem *edma;\n#include "stock-rpm-endpoint.h"'),
        ('if(check_edma()) return -ENOEXEC;', 'if(check_edma()) return -ENOEXEC;\n\tif(b10_rpm_check()) return -ENOEXEC;'),
        ('ret=check_stock();\n\tif (ret) goto out;',
         'ret=check_stock();\n\tif (!ret) ret=b10_rpm_live();\n\tif (ret) goto out;'),
        ('step="watchdog mapping";', 'step="diagnostic RPM endpoint ABI/pin";\n\tret=b10_rpm_acquire();\n\tif(ret) goto out;\n\tstep="watchdog mapping";'),
        ('pr_emerg("beacon10: secondary PSCI affinity states OFF verified\\n");',
         'pr_emerg("beacon10: secondary PSCI affinity states OFF verified\\n");\n\tif(b10_rpm_close()) goto reset;'),
        ('release_pages();', 'b10_rpm_unpin();\n\t\trelease_pages();'),
    )
    for before,after in edits:
        expected=2 if before=='release_pages();' else 1
        if source.count(before)!=expected:
            raise ValueError('Diagnostic module injection anchor changed: '+before)
        source=source.replace(before,after)
    if inherit:
        source='#define B10_RPM_INHERIT 1\n'+source
        before='step="private nonoverlapping RAM allocation";'
        if source.count(before)!=1:raise ValueError('RPM metadata validation anchor changed')
        source=source.replace(before,'ret=b10_rpm_state_find(dtb->data,dtb->size);\n\tif(ret) goto out;\n\t'+before)
        before='step="diagnostic RPM endpoint ABI/pin";'
        source=source.replace(before,'ret=b10_rpm_state_locate();\n\tif(ret) goto out;\n\t'+before)
    if power:
        source='#define B10_POWER_SNAPSHOT 1\n'+source
        before='ret=b10_rpm_state_find(dtb->data,dtb->size);'
        source=source.replace(before,'ret=b10_state_find(dtb->data,dtb->size,"nokia,stock-power-state",B10_POWER_BYTES,&b10_power_offset);\n\tif(ret) goto out;\n\t'+before)
        before='ret=b10_rpm_acquire();\n\tif(ret) goto out;'
        source=source.replace(before,before+'\n\tret=b10_state_locate(b10_power_offset,B10_POWER_BYTES,&b10_power_staged);\n\tif(ret) goto out;\n\tret=b10_power_acquire();\n\tif(ret) goto out;')
    if cpr:source='#define B10_CPR_QUIESCE 1\n'+source
    return source


def power_handoff_source(source):
    """Mandatory stock-power-v1 operations, using the shared audited code."""
    source=diagnostic_rpm_source(source,True,True,True)
    source='#define B10_STOCK_POWER_V1 1\n'+source
    anchor='ret=b10_rpm_state_find(dtb->data,dtb->size);'
    if source.count(anchor)!=1:raise ValueError('Power protocol validation anchor changed')
    source=source.replace(anchor,'ret=b10_power_protocol_check(dtb->data,dtb->size);\n\tif(ret) goto out;\n\t'+anchor)
    # These names are supplied by the audited stock CNSS/WLAN modules. The
    # production loader additionally refuses every non-handoff module.
    anchor='if(check_edma()) return -ENOEXEC;'
    source=source.replace(anchor,'if(kallsyms_lookup_name("ipq_cnss2:cnss_subsystem_put") ||\n'
                          '\t   kallsyms_lookup_name("qca_ol:ol_ath_wifi_ssr")) return -EBUSY;\n\t'+anchor)
    return source


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", type=Path, required=True)
    p.add_argument("--headers", type=Path, required=True)
    p.add_argument("--stock-module", type=Path, required=True)
    p.add_argument("--cross-compile", default="aarch64-linux-gnu-")
    p.add_argument("--handoff", action="store_true", help="Build the explicit real-handoff module, not the probe")
    p.add_argument("--stock-dp-module",type=Path,help="Owner stock qca-nss-dp.ko, required with --handoff")
    p.add_argument("--out", type=Path, required=True, help="NEW build directory")
    a = p.parse_args()
    # The standalone release exposes only the read-only probe and mandatory
    # stock-power-v1 sender. Historical RAM diagnostic variants are not a CLI.
    diagnostic_mode=False
    production_power=a.handoff
    a.diagnostic_rpm_endpoint_close=False
    a.diagnostic_rpm_inherit=False
    a.diagnostic_power_snapshot=False
    a.diagnostic_cpr_quiesce=False
    dp=dp_profile(a.stock_dp_module) if a.handoff and a.stock_dp_module else None
    if a.handoff and dp is None:p.error('--handoff requires --stock-dp-module')
    profile = json.loads((a.profile / "profile.json").read_text())
    image = (a.profile / "stock-Image").read_bytes()
    if hashlib.sha256(image).hexdigest() != profile["stock_kernel_sha256"]:
        p.error("Profile/Image hash mismatch")
    if (a.headers / "include/generated/utsrelease.h").read_text().strip() != '#define UTS_RELEASE "5.4.164"':
        p.error("Wrong kernel headers")
    rows = {line.split()[2]: int(line.split()[0], 16)-0xffffffc010080000
            for line in (a.profile / "System.map").read_text().splitlines()}
    exports = stock_exports(image, rows, include_data=a.handoff)
    source = Path(__file__).with_name("handoff" if a.handoff else "stock-linux-probe")
    a.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    out = a.out.resolve()
    names = [p.name for p in source.iterdir() if p.suffix in (".c", ".h", ".S") or p.name == "Makefile"]
    for name in names:
        shutil.copyfile(source / name, out / name)
    shutil.copyfile(a.profile / "stock-profile.h", out / "stock-profile.h")
    if dp:(out/'stock-dp.h').write_text(dp)
    rpm_report=None
    if production_power or a.diagnostic_rpm_endpoint_close or a.diagnostic_rpm_inherit:
        diagnostic=Path(__file__).with_name('diagnostics')
        spec=importlib.util.spec_from_file_location('stock_rpm_profile',diagnostic/'stock-rpm-profile.py')
        rpm=importlib.util.module_from_spec(spec);spec.loader.exec_module(rpm)
        header,rpm_report=rpm.generate(image,rows,production_power or a.diagnostic_power_snapshot,
                                      production_power or a.diagnostic_cpr_quiesce)
        (out/'stock-rpm-profile.h').write_text(header)
        shutil.copyfile(source/'stock-rpm-endpoint.h',out/'stock-rpm-endpoint.h')
        if production_power or a.diagnostic_rpm_inherit:
            shutil.copyfile(source/'stock-rpm-state.h',out/'stock-rpm-state.h')
            rpm_report.update({'mode':'inherit','requires_both_channel_ids_zero':False,
                              'publishes_live_ids_after_quiescence':True,'requires_new_kernel_empty_fifos':True,
                              'close_only_after_device_shutdown_and_cpu_freeze':False,
                              'metadata_only_after_device_shutdown_and_cpu_freeze':True,
                              'regulator_children_must_remain_disabled':not a.diagnostic_cpr_quiesce,
                              'new_kernel_regulator_policy':('deferred-until-manual-replay-and-start'
                                                            if a.diagnostic_cpr_quiesce else 'disabled')})
        else:rpm_report['mode']='close'
        if production_power or a.diagnostic_power_snapshot:
            shutil.copyfile(source/'stock-power-snapshot.h',out/'stock-power-snapshot.h')
            shutil.copyfile(diagnostic/'rpm-power-format.h',out/'rpm-power-format.h')
            # CPR suspend deliberately gates its controller clocks at commit;
            # do not label that extended experiment wholly read-only. These
            # fields describe the old module, not the activated new kernel.
            rpm_report.update({'power_cache_snapshot_only':not a.diagnostic_cpr_quiesce,
                               'no_new_voltage_enable_or_clock_requests':not a.diagnostic_cpr_quiesce,
                               'no_new_supply_voltage_requests':True,
                               'no_new_resource_requests_scope':'old-kernel-module',
                               'new_kernel_must_preserve_PLL_and_block_resource_writes':True})
        # Instrument only this NEW private build. The installed module source
        # and ordinary handoff build never contain endpoint-close calls.
        rpm_report['old_cpr_quiescence_at_commit']=a.diagnostic_cpr_quiesce
        module=out/'module.c'
        module.write_text(power_handoff_source(module.read_text()) if production_power else
                          diagnostic_rpm_source(module.read_text(),a.diagnostic_rpm_inherit,
                                                a.diagnostic_power_snapshot,a.diagnostic_cpr_quiesce))
    symvers = out / "stock.Module.symvers"
    # Stock CONFIG_MODVERSIONS=n: CRCs are absent. This supplies verified
    # exported names to modpost, not invented version checks for the target.
    symvers.write_text("".join(f"0x00000000\t{n}\tvmlinux\tEXPORT_SYMBOL_GPL\t\n" for n in sorted(exports)))
    with (out / "build.log").open("w") as log:
        subprocess.run(["make", "-C", str(a.headers.resolve()), "M="+str(out), "ARCH=arm64",
                        "CROSS_COMPILE="+a.cross_compile, "KBUILD_EXTRA_SYMBOLS="+str(symvers),
                        "-j8", "modules"], check=True, stdout=log, stderr=subprocess.STDOUT)
    target = out / ("beacon10-handoff.ko" if a.handoff else "beacon10-handoff-probe.ko")
    built, stock = elf_module(target), elf_module(a.stock_module)
    for key in ("vermagic", "module_struct_bytes", "module_struct_alignment", "callbacks"):
        if built[key] != stock[key]:
            raise ValueError(f"Stock module ABI mismatch: {key}: {built[key]} != {stock[key]}")
    if any(name not in exports for name in built["undefined"]):
        raise ValueError("Probe imports a symbol not verified in stock exports")
    report = {"stock_profile": profile["profile"], "probe_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
              "verified_module_abi": built, "all_imports_verified_in_stock_exports": True,
              "upstream_header_source_is_exact_vendor_source": False,
              "runtime_module_load_validated": False, "handoff_implemented": a.handoff,
              "hardware_validated": False, "performed_hardware_writes": False}
    report['diagnostic_only']=diagnostic_mode
    report['persistent_install_allowed']=False
    if production_power:
        report['power_protocol_version']=1
        report['stock_power_v1']={'stock_kernel_sha256':rpm_report['stock_kernel_sha256'],
                                'full_runtime_fingerprints':rpm_report['full_runtime_fingerprints'],
                                'committed_channel_and_power_snapshot':True,
                                'old_CPR_stop_at_irreversible_commit':True,
                                'fixed_CPU_kHz':1488000,
                                'old_NPU_must_be_disabled':True,
                                'rejects_loaded_stock_CNSS_or_WLAN':True,
                                'old_module_sends_no_OPEN_CLOSE_or_supply_request':True}
        report['source_sha256']={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in
                                ('module.c','stock-rpm-endpoint.h','stock-rpm-state.h',
                                 'stock-power-snapshot.h','rpm-power-format.h')}
    elif rpm_report:report['rpm_endpoint_close_experiment']=rpm_report
    (out / "probe-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
