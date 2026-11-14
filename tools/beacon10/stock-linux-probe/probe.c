// SPDX-License-Identifier: GPL-2.0-only
/* Read-only feasibility probe. Contains no shutdown, MMU, copy or jump path. */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/string.h>
#include "stock-profile.h"

static int __init beacon10_probe_init(void)
{
	unsigned long current_el;
	unsigned int i;

	if (!of_machine_is_compatible("qcom,ipq9574-ap-al02-c2"))
		return -ENODEV;
	if ((unsigned long)kallsyms_lookup_name != beacon10_stock_functions[0].address)
		return -ENOEXEC;
	asm volatile("mrs %0, CurrentEL" : "=r" (current_el));
	if (current_el != 4)
		return -EOPNOTSUPP;
	for (i = 0; i < ARRAY_SIZE(beacon10_stock_functions); i++) {
		const struct beacon10_stock_function *f = &beacon10_stock_functions[i];
		unsigned long address = kallsyms_lookup_name(f->name);
		unsigned int variant;

		if (address != f->address)
			return -ENOEXEC;
		for (variant = 0; variant < f->variants; variant++)
			if (!memcmp((const void *)address, f->code[variant], 16))
				break;
		if (variant == f->variants) {
			pr_err("beacon10: stock function fingerprint mismatch: %s\n", f->name);
			return -ENOEXEC;
		}
	}
	pr_info("beacon10: stock Linux handoff prerequisites match, EL1; probe only, no handoff executed\n");
	return 0;
}

static void __exit beacon10_probe_exit(void)
{
}

module_init(beacon10_probe_init);
module_exit(beacon10_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only Beacon10 stock Linux handoff feasibility probe");
