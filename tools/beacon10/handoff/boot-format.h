/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BEACON10_BOOT_FORMAT_H
#define BEACON10_BOOT_FORMAT_H
#ifdef __KERNEL__
#include <linux/types.h>
#define B10_U32 __u32
#define B10_U64 __u64
#else
#include <stdint.h>
#define B10_U32 uint32_t
#define B10_U64 uint64_t
#endif

#define B10_BOOT_MAGIC "B10LINUX"
#define B10_BOOT_VERSION 1U
#define B10_HEADER_SIZE 4096U
#define B10_KERNEL_LOAD 0x42000000ULL
#define B10_DTB_LOAD 0x58000000ULL
#define B10_KERNEL_FILE_MAX (32U << 20)
#define B10_KERNEL_MEMORY_MAX (64U << 20)
#define B10_DTB_MAX (2U << 20)
#define B10_STAGE_MIN 0x40000000ULL
#define B10_STAGE_END 0x80000000ULL
#define B10_LAYOUT "stock-linux-v1"

/* All integers little endian; hashes cover exactly the declared bytes.
 * The header itself is hashed with header_sha256 zero. Reserved bytes MUST be
 * zero. This is a corruption check, not an OEM signature or trust anchor.
 */
struct b10_boot_header {
	unsigned char magic[8];
	B10_U32 version, header_size;
	B10_U64 kernel_bytes, kernel_memory, dtb_bytes;
	B10_U64 kernel_offset, dtb_offset, total_bytes;
	B10_U64 kernel_load, dtb_load;
	unsigned char kernel_sha256[32], dtb_sha256[32], header_sha256[32];
	char layout[32];
	unsigned char reserved[3888];
};

/* Relocations, control and source pages must be allocated RAM outside both
 * complete destination reservations, not arbitrary "free-looking" addresses.
 */
struct b10_copy_entry { B10_U64 source, destination; };
#define B10_ENTRIES_PER_PAGE 255U
struct b10_copy_page {
	B10_U64 next, count;
	struct b10_copy_entry entry[B10_ENTRIES_PER_PAGE];
};
struct b10_control { B10_U64 copies, entry, dtb, trace; };

#define B10_IOCTL_STATUS 0xB100
#define B10_IOCTL_EXECUTE 0xB101
#define B10_EXECUTE_CONFIRM 0x42313048414e4431ULL
struct b10_status {
	B10_U32 version, ready;
	B10_U64 image_bytes, image_memory, dtb_bytes, staging_pages;
};
#endif
