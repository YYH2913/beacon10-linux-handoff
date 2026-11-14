/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef B10_STORAGE_H
#define B10_STORAGE_H
#include <stddef.h>
#include <stdint.h>
#include "boot-format.h"
#include "storage-layout.h"
#define B10_SECTORS 3817472ULL
#define B10_CAPSULE_START 3784664ULL
#define B10_STATE_A 32752ULL
#define B10_STATE_B 32760ULL
#define B10_STATE_READY 1U
#define B10_STATE_INSTALLING 2U
/* Zero and UINT64_MAX are not valid journal epochs. */
#define B10_STATE_MAX_SEQUENCE (UINT64_MAX - 1)
struct b10_state {
	char magic[8];
	uint32_t version, bytes;
	uint64_t sequence;
	uint32_t attempts, flags;
	unsigned char disk_guid[16], kernel_sha256[32], cid[16];
	uint64_t rootfs_bytes;
	unsigned char rootfs_sha256[32];
	uint32_t crc;
	unsigned char reserved[3956];
};
uint32_t b10_crc32(const void *data, size_t bytes);
int b10_read_at(int fd, void *data, size_t bytes, uint64_t offset);
int b10_write_verified(int fd, const void *data, size_t bytes, uint64_t offset);
int b10_layout_check(int fd, unsigned char disk_guid[16]);
int b10_state_read(int fd, const unsigned char disk_guid[16], struct b10_state *state);
int b10_state_write(int fd, const struct b10_state *state);
int b10_ack_env(int fd);
int b10_env_check(const unsigned char *env);
#endif
