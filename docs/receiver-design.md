# Receiver design and interface requirements

The **receiver** is the new Linux kernel and its early userspace, not the
stock 5.4 sender module. This repository intentionally does not provide target
driver patches, target DTS, power-adopt/root-enter helpers or boot-ACK source.
The requirements below describe integration ideas derived from the public sender
contract; they are not a ready-to-apply kernel implementation.

## 1. Treat warm handoff as a separate boot mode

Although control enters through the ARM64 Image entry point, the board is not
in a conventional cold-boot state. APSS PLL, RPM firmware, some power resources
and the secure world remain active. Changing a DT compatible or bypassing a
failed probe is not sufficient for stable takeover.

Use an explicit boot-mode declaration. If that mode is requested but metadata
is absent or invalid, refuse the affected initialization rather than silently
falling back to cold initialization. Do not change normal cold boot or other
boards as a side effect.

## 2. CPUs, memory and early entry

- Follow the ARM64 boot protocol: EL1, MMU/caches off, `x0` pointing to the DTB,
  and `x1..x3` zero.
- Respect the sender's 1 GiB RAM and reserved regions, including secure firmware,
  remote processors and persistent logs.
- Bring secondary CPUs online through normal PSCI CPU_ON and the standard
  secondary entry. Do not overwrite old entry points or hide failures by
  accepting a single-core boot.
- Match board/SoC properties, root partition and layout markers to the loader.
  External initrd/init overrides are rejected.
- Reserve an 8-byte `/chosen/beacon10,boot-seq` field for the loader's current
  attempt sequence. It must not be replaced by an unrelated ACK sequence.

## 3. RPM / GLINK channel takeover

The sender requires space under DT `/rpm-glink` for:

- `nokia,stock-power-handoff`: protocol version 1 declaration.
- `nokia,stock-rpm-state`: 32 initially zero bytes.
- `nokia,stock-power-state`: 256 initially zero bytes.

Each snapshot must fit within a single staged 4 KiB page. Publication occurs
only after old consumers stop, secondary CPUs turn off, and provider/transport
locks are held. The 32-byte channel record describes live LCID/RCID, features,
intentless mode and committed state. It carries no old kernel pointers.

Independently validate protocol, length, state, IDs and the actual FIFO cursor
bounds, alignment and empty condition. Inherit the live channel without
restarting VERSION/OPEN/CLOSE or resetting cursors out of sync with the peer.
Receiving VERSION_ACK alone does not prove that resource requests, CPR or
CPUFreq are operational.

## 4. PLL, regulators, CPR and CPUFreq

The sender transfers **committed software votes and register snapshots**, not
measured physical voltages. The public wire header defines the 256-byte
power-state v2 magic/version/CRC, three resources and PLL/mux metadata. The
production sender fixes CPU frequency at 1.488 GHz, suspends old CPR, and
requires the old NPU power consumer to be inactive.

Take over in bounded stages:

1. Correlate the snapshot with the running APSS PLL/mux and refuse mismatches.
   Do not reprogram an active PLL through an ordinary cold-start path.
2. Keep resource writes and DVFS restricted early. A probing driver must not
   issue default enable/voltage votes before the channel is ready.
3. Inherit message ID/channel state and reassert unchanged committed votes with
   bounded requests. Require exact matching sequence, resource and success ACK.
   Do not raise voltage or disable safeguards to force boot.
4. Restore control using the new kernel's own fuse data, OPPs and CPR
   floor/ceiling limits. Old software corner indices are not microvolts.
5. Latch faults on validation failure, timeout, duplicate control or out-of-range
   requests, and stop issuing further resource requests.
6. Admit root startup, Wi-Fi and normal userspace only after power state, four
   CPUs, frequencies and clocks agree.

A diagnostic FIFO-cursor preservation trick is not a production power takeover.
Nor may an integrator assume Q6/PCI devices were never initialized if the stock
Wi-Fi stack was already started before handoff.

## 5. Storage and peripherals

- Reinitialize eMMC and validate DMA, HS400/CQE, error recovery and actual
  read/write paths. Successful enumeration is not stability evidence.
- Before mounting P30 read-only, verify the actual GPT, CID, READY state,
  attempt sequence, complete root hash and power health.
- Permit overlay only on exact P36: parent disk, start, length, name and layout
  must agree. On failure stop or use RAM overlay; never guess trailing space
  or format the old P26 instead.
- Check Ethernet PHY addresses, Clause 45, reset polarity and power ordering.
  Link negotiation alone does not prove data-plane operation.
- Wi-Fi needs correct firmware, ART, board identity and calibration policy, with
  regulatory compliance. Three APs starting does not validate client traffic.
- Validate watchdog, Reset/WPS inputs, crash/restart and cold/warm boots
  separately. SSH reachability is not full peripheral acceptance.

## 6. Success acknowledgement and acceptance

A complete receiver should establish at least:

- Unattended cold boot and ordinary reboot into the correct physical root, with
  four CPUs and healthy power state.
- Physical P30 root, physical P36 overlay, persistent writes and matching boot
  sequence. A RAM upper must not masquerade as persistent success.
- Required ports/radios/remote processors driven correctly, with data-integrity
  tests rather than mere interface presence.
- ACK only after health checks; independent verification of the journal and
  both stock environment copies after acknowledgement.
- Recovery retained after repeated failures, plus separately validated upgrade
  and interruption procedures with external backups.

This repository supplies the sender and interface documentation, not the
receiver implementation or those acceptance results. Distribution of modified
GPL Linux binaries still requires compliance with corresponding-source
obligations. Keeping receiver implementation out of this repository does not
waive those obligations.
