/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef B10_INSTALL_FORMAT_H
#define B10_INSTALL_FORMAT_H
#include <stdint.h>
#define B10_INSTALL_MAGIC "B10INST2"
#define B10_INSTALL_VERSION 2U
struct b10_component { uint64_t offset, bytes; unsigned char sha256[32]; };
struct b10_bundle {
	char magic[8]; uint32_t version, bytes; uint64_t total;
	struct b10_component part[3]; /* bootstrap squashfs, B10LINUX, QSDK squashfs */
	unsigned char sha256[32], reserved[3896];
};
struct b10_snapshot {
	uint64_t offset, bytes, source, destination;
	unsigned char sha256[32];
};
struct b10_capsule {
	char magic[8]; uint32_t version, bytes; uint64_t total;
	unsigned char disk_guid[16], cid[16], bundle_sha256[32];
	struct b10_snapshot part[8];
	unsigned char sha256[32], reserved[3464];
};
#define B10_CAPSULE_BYTES (32752U * 512U)
int b10_install(int disk, int bundle, const unsigned char cid[16], int write);
#endif
