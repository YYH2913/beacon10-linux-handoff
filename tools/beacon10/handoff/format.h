/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef B10_FORMAT_H
#define B10_FORMAT_H
#include "boot-format.h"
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
int b10_dtb_check_persistent(const void *data, size_t size, B10_U64 kernel_memory);
#endif
int b10_image_check(const void *data, size_t size, B10_U64 *memory);
int b10_dtb_check(const void *data, size_t size, B10_U64 kernel_memory);
int b10_header_check(struct b10_boot_header *h);
int b10_dtb_set_sequence(void *data, size_t size, B10_U64 sequence);
#endif
