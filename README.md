# beacon10-linux-handoff

**English** | [简体中文](README.cn.md)

Hand off from stock signed Linux to ARM64 Linux.

```text
Stock U-Boot / bootipq
→ Stock signed Linux 5.4.164
→ Minimal SquashFS + PID1: b10-loader → beacon10-handoff.ko → ARM64 trampoline
→ Target Linux (EL1, MMU/caches off, x0=DTB)
```

- No replacement U-Boot or HLOS.
- The stock kernel boots into a minimal root filesystem and acts as a transition environment.
- The full stock system is not started first to run a handoff script.

## Scope

- **Handoff core:** Image/DTB/payload validation, SHA256, controlled RAM allocation and copying, an explicit commit ioctl, DMA/CPU shutdown, and the Cortex-A73/EL1 trampoline.
- **Bootstrap and tools:** PID1 loader, BusyBox/SSH recovery, stock ABI profile generation, SquashFS packaging, and payload/installation-bundle builders.
- **Partitions and migration:** published layout, offline GPT planning, and a regular-file migration model. Live installation is disabled by default.
- **Receiver:** interface and design guidance only. Target driver patches, DTS, power helpers, root-enter, fstools and boot-ACK implementations are not included.

## Do not

- Treat this project as a universal `dd` flashing recipe.
- Upload `bootstrap.squashfs` to the stock web firmware updater.
- Write `boot.bin` into HLOS.
- Use the old factory-layout/P26 recovery procedure on an already migrated device.

## Build and offline checks

```bash
sudo apt-get install build-essential python3 device-tree-compiler libfdt1 \
  squashfs-tools gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
  libc6-dev-arm64-cross qemu-user-static fakeroot

git clone https://github.com/YYH2913/beacon10-linux-handoff.git
cd beacon10-linux-handoff
make host-tools arm64-tools check
```

`check` verifies generated layout constants. Test scripts remain local and are not committed. These commands do not connect to or write to a device.

Outputs:

- `build/host/b10-loader` and `build/host/b10-install`.
- Static ARM64 tools under `build/arm64/`.
- Stock `.ko` and `bootstrap.squashfs`: provide your own stock backup, matching headers, BusyBox, Dropbear and SSH public key, then follow the [build guide](docs/build.md). These outputs are not shipped in releases.

## Documentation

- [Architecture and handoff sequence](docs/architecture.md)
- [Build outputs and flashing boundary](docs/build.md)
- [Partition layout, migration order and recovery risks](docs/partitions-and-migration.md)
- [Receiver design and interface requirements — no implementation](docs/receiver-design.md)
- [Import provenance and initial hashes](docs/import-provenance.json)

Core source is under `tools/beacon10/handoff/`. This is an independent repository; it does not modify the original QSDK14 project.

## License

See each file's SPDX identifier: mainly GPL-2.0-only, with GPL-2.0+ for a few planning tools. See [LICENSE](LICENSE).
