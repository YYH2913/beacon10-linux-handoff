# Partition layout, migration ordering and recovery risks

This document describes the design and regular-file transaction model, not a
live flashing procedure. The public entry retains
`B10_LIVE_INSTALL_VALIDATED = 0`; no bypass for device authorization or safety
checks is provided.

## 1. Why move three data partitions?

The stock layout uses two 128 MiB rootfs slots and multiple application/config
partitions, with manufacturing data farther into the disk. A transition root
needs only a few MiB. Keeping all stock userspace partitions would waste capacity
and fragment the space available to the new system.

The design:

- Retains the signed boot chain, ART, Wi-Fi/PHY firmware, partition numbering
  and required identities; P1–P25 do not move.
- Shrinks P26/P27 to 8 MiB each while retaining `rootfs`/`rootfs_1` names and
  their original unique GUIDs.
- Moves RI, the backup environment and manufacturing data intact, preserving
  content, length, names and unique GUIDs.
- Uses the remainder for target kernel/rootfs, a contiguous approximately
  1.643 GiB overlay and a small recovery snapshot area.

This is a capacity optimization, not an identity change. Stock Linux identifies
its root by PARTUUID, so preserving P26/P27 GUIDs is essential. The primary
environment in P17 keeps its address. Compatibility of relocated P33 depends
on the audited bootloader locating it through GPT; do not assume every firmware
uses names rather than hard-coded addresses.

## 2. Exact layout

The machine-readable source of truth is `tools/beacon10/layout.json`. All
start/size values are **512-byte LBAs**; size is a count, and the inclusive end
is start + size − 1. This layout applies only to the audited capacity of
**3,817,472 sectors / 1,954,545,664 bytes**. It does not auto-expand to another
eMMC size, SKU or unknown stock GPT.

P1–P25 retain their GPT entries. P24/P25 are 10 MiB each and still contain the
stock signed HLOS. P17 is a mutable primary environment: installation preserves
its bytes, but later successful-boot acknowledgement can change its failure
counter. Installation preservation does not mean permanent byte immutability.

| Partition | Name | Factory start / size | New start / size | New capacity | Purpose |
|---|---|---:|---:|---:|---|
| P26 | `rootfs` | 90658 / 262144 | 90658 / 16384 | 8.000 MiB | Minimal bootstrap A |
| P27 | `rootfs_1` | 352802 / 262144 | 107042 / 16384 | 8.000 MiB | Minimal bootstrap B |
| P28 | `RI` | 614946 / 2048 | 123426 / 2048 | 1.000 MiB | RI, copied intact |
| P29 | `qsdk_kernel` | 616994 / 12288 | 142384 / 65536 | 32.000 MiB | Target B10LINUX payload |
| P30 | `qsdk_rootfs` | 629282 / 131072 | 207920 / 131072 | 64.000 MiB | Target read-only SquashFS root |
| P31 | `beacon_guard31` | 760354 / 131072 | 142378 / 2 | 1024 B | Partition-number guard |
| P32 | `beacon_guard32` | 891426 / 131072 | 142380 / 2 | 1024 B | Partition-number guard |
| P33 | `0:APPSBLENV_1` | 1022498 / 512 | 125474 / 512 | 262144 B | Backup stock environment, copied intact |
| P34 | `beacon_guard34` | 1023010 / 1032192 | 142382 / 2 | 1024 B | Partition-number guard |
| P35 | `mft_data` | 2055202 / 16392 | 125986 / 16392 | 8.004 MiB | Manufacturing data, copied intact |
| P36 | `rootfs_data` | Absent | 338992 / 3445672 | 1682.457 MiB | Target writable overlay |
| P37 | `beacon_rescue` | Absent | 3784664 / 32775 | 16.003 MiB | Device snapshots and boot journal |

P36 is **1,764,184,064 bytes**, approximately 1.643 GiB before filesystem and
overlay overhead. P29/P30/P36 are 4 KiB aligned; the small stock-compatible boot
roots retain their compatible positions, so not every partition is claimed to
be 4 KiB aligned. All usable sectors are allocated. GPT numbering remains
continuous from 1 to 37; physical order differs from number order.

Two bootstrap roots are not complete target A/B: **P29/P30 are a single target
slot**. P37 is about 16 MiB and cannot hold a full stock or target system backup.
It is not an independent signed rescue kernel.

## 3. Required files

- `bootstrap.squashfs`: minimal root containing the loader/module, for P26/P27.
- `boot.bin`: B10LINUX-v1 header, target Image and DTB, for P29.
- Target rootfs SquashFS, for P30.
- B10INST2 bundle: binds the three components as **transaction inputs**.
- Complete external originals: user area, boot0/boot1 and required identity data.
  Do not publish these backups.

Snapshots and journal must bind the actual device CID, original disk GUID and
identity bytes. Never reuse another device's GPT, P37 or environment image.

## 4. First-install transaction design

The sequence below corresponds to `handoff/install.c`. The public
`install-main.c` permits writes only to regular-file models. A live integrator
also needs a fully detached RAM/PID1 environment, offline-volume checks,
exclusive block access, watchdog handling, backups and verified recovery.

1. **Admit inputs.** Validate the entire bundle, component hashes, SquashFS,
   payload and versions against the exact media size, stock GPT and both
   APPSBL/HLOS copies. Do not infer unknown layouts. Before device writes,
   leave the old root, stop old userspace and normally unmount all
   SquashFS/ext4/overlay/mmc/loop dependencies. Lazy unmount is not sufficient.
2. **Snapshot before destruction.** Save original GPT, primary environment, RI,
   backup environment, manufacturing data, new GPT and a bounded bootstrap copy
   into the tail capsule. Hash each item, flush and read back, then publish the
   capsule header last.
3. **Publish INSTALLING.** Bind both journal records to CID, GUID and target
   hashes. Do not publish READY in advance.
4. **Keep roots reachable under old and new tables.** Write a bootstrap at the
   old P27 address, then at fixed P26 and new P27 addresses. The old P27 copy
   remains until the new GPT verifies. Actual stock slot selection after every
   interruption still needs hardware testing; automatic fallback is not promised.
5. **Relocate identity data from the snapshot.** Copy RI, backup environment and
   manufacturing data in full, not selected fields. Do not alter ART or borrow
   another unit's MAC/serial/calibration. Relocation precedes any payload write
   that could overwrite old source regions.
6. **Publish GPT.** Write the backup array/header first, then the primary
   array/header, with a flush/readback at each step. Recheck both tables and the
   complete layout. This is an ordered multi-write transaction, **not atomic**.
7. **Write the target.** Only after the new GPT passes, write P29/P30. Initial
   installation clears P36's first 64 KiB to request a new overlay. Matching
   receiver storage policy may initialize only exact P36, never guessed root
   tail space or P26.
8. **Publish READY.** Update the journal after component verification. Normal
   bootstrap loads the target on the next boot. Reboot remains explicit; the
   installer library does not reboot blindly.

Repeating the same fully completed installation does not erase the overlay.
That property does not make a first-install tool a general upgrade mechanism.
An already migrated `stock-linux-v2` system requires a separately controlled
target-slot update, not another GPT plan, identity move, bootstrap replacement
or P36 format.

## 5. Boot attempts and success acknowledgement

P37 contains two 4096-byte journal records with CRC, GUID, sequence, status and
reserved-byte validation:

- States are INSTALLING/READY, published in alternating records while keeping
  the previous valid record.
- The loader records an attempt before CPU control and module loading. The
  DTB carries the same boot sequence.
- After three unsuccessful attempts, automatic handoff stops in bootstrap
  recovery instead of rebooting forever.
- The new system may ACK only after checking physical P30/P36, power, required
  hardware, this boot's sequence and target hashes.
- ACK must coordinate the journal with both stock failure counters. A successful
  return from a stock environment-save routine is not sufficient durability
  evidence; independent CRC/readback is required.

The target boot-ACK implementation is not published here. A CPU jump without
correct acknowledgement is not a complete unattended-boot integration.

## 6. Boot-failure and recovery risks

Relocation does not inherently break boot, but it invalidates assumptions that
must be checked explicitly:

- Hard-coded backup-environment or manufacturing-data addresses will not follow
  a GPT change.
- Changed GUIDs/root names can prevent stock Linux from finding its PARTUUID.
- Power loss during GPT/root publication can leave a mixed layout. Regular-file
  fault injection does not establish eMMC power-loss atomicity.
- Missing ACK, wrong watchdog inheritance, live DMA or cold initialization of
  a running PLL can all look like a boot hang.
- Duplicate bootstrap roots, a capsule and two GPT copies reduce risk; they do
  not replace external backups, reachable recovery and actual interruption tests.

**Do not apply the old factory P26-only restore to an already migrated disk.**
The old P26 length overlaps the new partitions and identity locations. Recovery
must first identify the complete current layout, records and matching backups,
then use an appropriate full-device or transactional procedure. Do not experiment
with historical `dd` commands.

Automatic recovery from every interruption point has not been established on
hardware. Do not advertise arbitrary power-loss safety or an unbrickable device.
