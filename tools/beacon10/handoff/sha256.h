/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef B10_SHA256_H
#define B10_SHA256_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
typedef u32 b10_word;
typedef u64 b10_count;
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint32_t b10_word;
typedef uint64_t b10_count;
#endif
struct b10_sha256 { b10_word h[8]; b10_count bytes; unsigned char block[64]; };
void b10_sha256_init(struct b10_sha256 *s);
void b10_sha256_update(struct b10_sha256 *s, const void *data, size_t size);
void b10_sha256_final(struct b10_sha256 *s, unsigned char out[32]);
void b10_digest(const void *data, size_t size, unsigned char out[32]);
#endif
