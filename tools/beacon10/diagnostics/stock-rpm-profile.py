#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""SHA-bound, owner-local ABI for the endpoint-only RPM close experiment.

Not a production handoff fix. All offsets below are cross-checked against
specific instructions in the one audited retail Image, not upstream layouts.
The generated header contains owner firmware bytes and must not be committed.
"""
import hashlib
import struct

BASE = 0xffffffc010080000
SHA256 = "ea0d53e08791abcb2fdf8536be9e7f791891ef348c5ba79f0cdb309b47be4c44"
FUNCTIONS = (
    "device_shutdown", "cpufreq_suspend", "device_find_child_by_name",
    "qcom_smd_rpm_probe", "qcom_smd_rpm_remove", "rpmsg_dev_remove", "rpmsg_destroy_ept",
    "qcom_glink_destroy_ept", "qcom_glink_send_close_req.isra.7",
    "qcom_glink_alloc_channel", "qcom_glink_channel_release", "qcom_glink_work",
    "qcom_rpm_smd_write", "qcom_smd_rpm_callback", "qcom_glink_rpdev_release",
    "qcom_glink_native_probe", "__qcom_glink_send",
)
POWER_FUNCTIONS = (
    "regulator_get_optional", "regulator_put", "regulator_get_drvdata",
    "regulator_lock", "regulator_unlock", "regulator_get_voltage", "regulator_is_enabled",
    "rpm_reg_probe", "rpm_reg_is_enabled", "rpm_reg_get_voltage", "rpm_reg_write_active",
    "rpm_reg_set_voltage", "rpm_reg_set_corner", "rpm_reg_set_load", "rpm_reg_enable", "rpm_reg_disable",
    "get_cpu_device", "clk_get", "clk_put", "clk_get_rate", "cpufreq_quick_get",
    "cpr3_regulator_get_voltage", "cpr3_regulator_is_enabled",
)


def generate(image, rows, power=False, cpr=False):
    if cpr and not power:
        raise ValueError('CPR quiescence requires the locked power snapshot')
    if hashlib.sha256(image).hexdigest() != SHA256:
        raise ValueError("RPM diagnostic supports only the audited retail Image")

    def insn(address, expected):
        if struct.unpack_from('<I', image, address - BASE)[0] != expected:
            raise ValueError('RPM ABI instruction mismatch at %x' % address)

    # BL cpufreq_suspend inside device_shutdown: governors are stopped before
    # the device list is walked. Do not replace this with SYS_RESTART.
    insn(0xffffffc0104634a4, 0x9402b171)
    # rpmsg_dev_remove and qcom_smd_rpm_probe both load rpdev->ept at 776.
    insn(0xffffffc010580bac, 0xf9418660)
    insn(0xffffffc010418bf0, 0xf9418680)
    # rpm private data is dev->driver_data at 120; first pair is {ept, dev}.
    insn(0xffffffc010418c08, 0xf9003e93)
    insn(0xffffffc010418bf8, 0xa9005260)
    # rpmsg_destroy_ept loads the endpoint operations at +72.
    insn(0xffffffc0105808a0, 0xf9402401)
    # rpm->lock is initialized at +48. No supplier removal is involved.
    insn(0xffffffc010418bc4, 0x9100c000)
    # device_shutdown locks dev->mutex at 128 (x20 is dev + 8).
    insn(0xffffffc010463508, 0x9101e29a)
    # ept/channel: destroy_ept clears cb at 16 and rpdev at 80, uses glink
    # at 88 and lcid at 112. The channel's separate kref is at 96.
    insn(0xffffffc010583240, 0xf9000a7f)
    insn(0xffffffc010583250, 0xf9002a7f)
    insn(0xffffffc010583238, 0xf9402e75)
    insn(0xffffffc0105834e0, 0x3903a016)  # glink->intentless at 232
    insn(0xffffffc010583530, 0xf9007277)  # glink->features at 224
    insn(0xffffffc010583254, 0xb9407261)
    insn(0xffffffc010582928, 0xb9006260)
    insn(0xffffffc01058268c, 0xd1018277)
    # Local and remote close handling zero lcid and rcid before dropping refs.
    insn(0xffffffc010583c44, 0xb90072df)
    insn(0xffffffc010583aec, 0xb90076df)
    # cpufreq_suspend: ADRP x20, b20000; ADD x20,ff0; STRB at +28.
    insn(0xffffffc01050fa74, 0xb0003094)
    insn(0xffffffc01050faa0, 0x913fc294)
    insn(0xffffffc01050faa8, 0x39007280)
    if power:
        # The static next msg_id is absent from CONFIG_KALLSYMS_ALL=n.
        # Tie its data address to ADRP/LDR/STR inside the full verified writer.
        insn(0xffffffc01041896c, 0xd0003381)
        insn(0xffffffc010418980, 0xb94e3820)
        insn(0xffffffc010418990, 0xb90e3822)
        # regulator_get_drvdata follows consumer->rdev at +120; the public
        # accessor returns private driver data, no guessed provider layout.
        insn(0xffffffc01042686c, 0xf9403c00)
        insn(0xffffffc010426870, 0xf9420c00)
        insn(0xffffffc01043036c, 0xb9412800)  # is_enabled at +296
        insn(0xffffffc010430384, 0xb9412c00)  # uV at +300
        insn(0xffffffc010430484, 0xb9413262)  # load at +304
        insn(0xffffffc0104305d0, 0x3944d001)  # dirty mask at +308
        insn(0xffffffc0104304c0, 0x121c6c21)  # bits 0..3 cleared on ACK
        insn(0xffffffc010430700, 0xb9001260)  # resource type at +16
        insn(0xffffffc010430708, 0xb9001660)  # resource id at +20
        insn(0xffffffc01043070c, 0xf9000678)  # owning RPM at +8
    if cpr:
        insn(0xffffffc01043dad0, 0xf9404400)  # platform device+16, drvdata+120
        insn(0xffffffc01043e284, 0xf9000380)  # ctrl->dev is first member
        insn(0xffffffc010436238, 0x3908ea60)  # suspended flag +570
        insn(0xffffffc010436208, 0x3908e27f)  # cpr_enabled +568 clear

    header = [
        '/* OWNER-LOCAL diagnostic firmware fingerprints; never redistribute. */',
        '#define B10_RPM_DEVICE_MUTEX 128U',
        '#define B10_RPM_DEVICE_DATA 120U',
        '#define B10_RPM_DEVICE_EPT 776U',
        '#define B10_RPM_ENDPOINT_OPS 72U',
        '#define B10_RPM_LOCK 48U',
        '#define B10_RPM_CHANNEL_RPDEV 80U',
        '#define B10_RPM_CHANNEL_KREF 96U',
        '#define B10_RPM_CHANNEL_GLINK 88U',
        '#define B10_RPM_CHANNEL_LCID 112U',
        '#define B10_RPM_CHANNEL_RCID 116U',
        '#define B10_RPM_GLINK_FEATURES 224U',
        '#define B10_RPM_GLINK_INTENTLESS 232U',
        '#define B10_RPM_CPUFREQ_SUSPENDED 0xffffffc010b2100cUL',
        '#define B10_POWER_CONSUMER_RDEV 120U',
        '#define B10_POWER_VREG_RPM 8U',
        '#define B10_POWER_VREG_TYPE 16U',
        '#define B10_POWER_VREG_ENABLED 296U',
        '#define B10_POWER_NEXT_MSG_ADDRESS 0xffffffc010a8ae38UL',
        '#define B10_POWER_CPR_ENABLED 568U',
        '#define B10_POWER_CPR_SUSPENDED 570U',
        'struct b10_rpm_fingerprint { const char *name; unsigned long address; unsigned int bytes; const unsigned char *code; };',
    ]
    evidence = []
    cpr_functions=("cpr3_regulator_suspend","cpr4_apss_regulator_suspend","cpr4_apss_regulator_probe","cpr3_clock_enable","cpr3_clock_disable") if cpr else ()
    for index, name in enumerate(FUNCTIONS + (POWER_FUNCTIONS if power else ()) + cpr_functions):
        if name not in rows:
            raise ValueError('RPM ABI missing symbol: ' + name)
        start = rows[name]
        end = min(v for v in rows.values() if v > start)
        code = image[start:end]
        if not code or len(code) % 4 or len(code) > 8192:
            raise ValueError('Unexpected RPM ABI function size: ' + name)
        header.append('static const unsigned char b10_rpm_code_%d[] = { %s };' %
                      (index, ','.join('0x%02x' % v for v in code)))
        evidence.append({'name': name, 'address': BASE + start, 'bytes': len(code),
                         'sha256': hashlib.sha256(code).hexdigest()})
    header.append('static const struct b10_rpm_fingerprint b10_rpm_fingerprints[] = {')
    for index, item in enumerate(evidence):
        header.append(' { "%s", 0x%xUL, %d, b10_rpm_code_%d },' %
                      (item['name'], item['address'], item['bytes'], index))
    header.append('};')
    return '\n'.join(header) + '\n', {
        'diagnostic_only': True, 'hardware_validated': False,
        'stock_kernel_sha256': SHA256, 'full_runtime_fingerprints': evidence,
        'supplier_unregister': False, 'close_only_after_device_shutdown_and_cpu_freeze': True,
        'pending_rpm_writes_serialized_before_close': True,
        'requires_both_channel_ids_zero': True,
        'readonly_power_snapshot': power,
    }
