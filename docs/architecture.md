# Architecture and handoff sequence

## Why use stock Linux as the transition environment?

The observed retail device uses secure boot. Its U-Boot executes `bootipq` to
verify and start the OEM-signed HLOS. This project does not forge an OEM
signature, change security fuses, or assume that an unsigned replacement U-Boot
can enter that chain.

Keeping HLOS while replacing the root filesystem it mounts allows this project's
`/sbin/init` to become PID1. The full stock userspace is skipped; the stock kernel
is not. No stock Wi-Fi or cloud services are needed on the normal handoff path.

## Responsibilities of the public source

### PID1 loader

`tools/beacon10/handoff/loader.c`:

1. Restricts normal boot to root/PID1 and rejects extra stock modules or writable
   disk mounts.
2. Checks the exact media size, both GPT copies, storage layout, device CID and
   READY journal. Three unsuccessful attempts leave the device in recovery.
3. Validates the P29 B10LINUX payload, the full declared P30 rootfs, the DTB and
   reserved memory ranges.
4. Publishes Image/DTB into RAM firmware paths and records the boot attempt
   before CPU policy changes or module loading.
5. Passes complete SHA256 arguments through `finit_module(..., flags=0)`, without
   force-loading or bypassing the kernel ABI checks.
6. Checks STATUS before issuing a separate EXECUTE ioctl.

**Normal boot writes a bounded attempt record to the eMMC journal.** It does not
run migration, rewrite the GPT, clear the overlay, or call the installer.

### Stock-kernel sender

`module.c`, `stock-rpm-*.h` and `stock-power-snapshot.h`:

- Loading validates stock function fingerprints, CPU/EL/PSCI conditions and the
  payload, and allocates pages genuinely owned by the running kernel. It never
  claims physical memory merely because it appears unused.
- Source, code, page-table and control pages avoid the complete destination
  windows. Allocation failure or a mismatch stops staging.
- Only a caller with CAP_SYS_BOOT and the fixed confirmation value can commit.
  Loading the module does not jump.
- After irreversible commit, the sender stops networking and DMA using the
  audited stock ABI, clears PCI bus-mastering, shuts down devices, freezes
  secondary CPUs and checks PSCI OFF. It keeps `device_shutdown()` but avoids
  retail SYS_RESTART notifiers that prevent later CPU_ON.
- The production builder adds mandatory stock-power-v1 sender operations:
  fixed CPU policy, old CPR suspension, live RPM-channel validation, locking of
  committed resource votes and PLL state, and publication into the RAM DTB.
- Finally it stops watchdog/syscore activity, masks interrupts, flushes staged
  pages, and enters the physical trampoline. Failure after irreversible shutdown
  takes the emergency-restart path rather than returning to half-stopped Linux.

### ARM64 trampoline

`trampoline.S`:

- Targets Cortex-A73, EL1, 4 KiB pages and the audited translation model.
- Retains the old high-address mapping until branching into the TTBR0 identity
  mapping.
- Uses no old stack or external symbols after the transition; disables the
  MMU/I/D caches, maintains local caches, and copies/zeroes pages.
- Enters the raw ARM64 Image with `x0 = physical DTB address` and `x1..x3 = 0`.

## Distinct version numbers

- **B10LINUX-v1 / `stock-linux-v1`:** payload and handoff protocol.
- **`stock-linux-v2`:** persistent partition layout, not a new CPU jump protocol.
- **stock-power-v1 / power-state v2:** power handoff protocol and snapshot format.

Do not interchange them. Builders check the target DTB, rootfs storage marker
and persistent geometry for agreement.

## Fixed physical memory contract

- RAM: `0x40000000..0x7fffffff`, 1 GiB.
- Image entry: `0x42000000`; complete destination window: 64 MiB.
- DTB: `0x58000000`; complete destination window: 2 MiB.
- Maximum Image file: 32 MiB; maximum declared Image memory: 64 MiB. The **entire
  P29 payload**, including its header and DTB, must still fit within 32 MiB.

These are board-specific contracts, not general ARM64 defaults.

## Security and validation boundary

SHA256 and CRC provide corruption detection and input binding, not OEM
signatures or a new boundary against malicious root. The stock kernel remains
OEM-verified, but this project does not preserve an end-to-end policy of running
only OEM code. Additional admission controls are the integrator's responsibility.
No remote flashing or jump service is provided.

Regular-file fault models do not establish eMMC power-loss atomicity. Even a
read-only probe module can crash a kernel if its ABI assumptions are wrong.
Successful control transfer does not, by itself, validate target storage,
networking, Wi-Fi, watchdog or power recovery.
