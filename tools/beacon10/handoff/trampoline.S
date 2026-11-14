/* SPDX-License-Identifier: GPL-2.0-only */
/* Cortex-A73 / EL1 only. No stack accesses, absolute literals, or external
 * references in the copied trampoline. All state lives in allocated RAM
 * outside both complete destination windows, verified by the C allocator.
 */
.text
.balign 16
.global b10_enter
.type b10_enter, %function
/* x0=identity TTBR0, x1=physical trampoline, x2=physical control.
 * Keep TTBR1 (current kernel text) until the branch to the identity mapping.
 */
b10_enter:
	msr daifset, #15
	mov x16, x1
	mov x17, x2
	dsb sy
	msr ttbr0_el1, x0
	mrs x3, tcr_el1
	mov x4, #0xffff
	bic x3, x3, x4
	mov x4, #0x3519 /* 39-bit, 4K, inner-shareable, WBWA, EPD0=0 */
	orr x3, x3, x4
	msr tcr_el1, x3
	isb
	tlbi vmalle1
	dsb sy
	isb
	br x16
.size b10_enter, .-b10_enter

.balign 16
.global b10_trampoline_start
.global b10_trampoline_end
b10_trampoline_start:
	/* x17 survives the virtual-to-physical branch. */
	mrs x3, sctlr_el1
	mov x4, #0x1005 /* MMU, D-cache, I-cache */
	bic x3, x3, x4
	dsb sy
	msr sctlr_el1, x3
	isb
	ldr x18, [x17, #24] /* optional diagnostic RAM marker, zero in normal boot */
	/* Clean/invalidate all local data/unified caches by set/way before
	 * overwriting the old kernel. CCIDX is rejected by the C adapter.
	 * No stack writes after this point can dirty the old destination again.
	 */
	mrs x0, clidr_el1
	ubfx x3, x0, #24, #3
	lsl x3, x3, #1
	mov x10, #0
1:
	cmp x10, x3
	b.hs 5f
	add x2, x10, x10, lsr #1
	lsr x1, x0, x2
	and x1, x1, #7
	cmp x1, #2
	b.lo 4f
	msr csselr_el1, x10
	isb
	mrs x1, ccsidr_el1
	and x2, x1, #7
	add x2, x2, #4
	ubfx x4, x1, #3, #10
	clz w5, w4
	ubfx x6, x1, #13, #15
2:
	mov x7, x4
3:
	lsl x9, x7, x5
	orr x9, x9, x10
	lsl x8, x6, x2
	orr x9, x9, x8
	dc cisw, x9
	subs x7, x7, #1
	b.ge 3b
	subs x6, x6, #1
	b.ge 2b
4:
	add x10, x10, #2
	b 1b
5:
	msr csselr_el1, xzr
	dsb sy
	ic iallu
	dsb sy
	isb
	cbz x18, 11f
	mov w4, #0x3142
	movk w4, #0x5430, lsl #16 /* B10T: physical entry and cache flush reached */
	str w4, [x18]
	dsb sy
11:
	ldp x19, x20, [x17] /* copy-list, Image entry */
	ldr x21, [x17, #16] /* DTB physical address */
6:
	cbz x19, 10f
	ldp x22, x23, [x19] /* next list, number of copies */
	add x24, x19, #16
7:
	cbz x23, 9f
	ldp x25, x26, [x24], #16
	mov x27, #4096
8:
	ldp x0, x1, [x25], #16
	stp x0, x1, [x26], #16
	subs x27, x27, #16
	b.ne 8b
	sub x23, x23, #1
	b 7b
9:
	mov x19, x22
	b 6b
10:
	dsb sy
	ic iallu
	tlbi vmalle1
	dsb sy
	isb
	msr cntv_ctl_el0, xzr
	msr cntp_ctl_el0, xzr
	cbz x18, 12f
	mov w4, #0x3142
	movk w4, #0x4330, lsl #16 /* B10C: Image/DTB copied, about to branch */
	str w4, [x18]
	mrs x4, sctlr_el1
	str w4, [x18, #4]
	ldr w4, [x20]
	str w4, [x18, #8]
	ldr w4, [x21]
	str w4, [x18, #12]
	dsb sy
12:
	mov x0, x21
	mov x1, xzr
	mov x2, xzr
	mov x3, xzr
	br x20
b10_trampoline_end:
.section .note.GNU-stack,"",%progbits
