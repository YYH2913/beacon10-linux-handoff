// SPDX-License-Identifier: GPL-2.0-only
/* Explicit stock-Linux -> ARM64 Image handoff. Loading only prepares RAM.
 * Neither init nor the ioctl path writes storage. Commit is root-only and
 * irreversible; until commit, module unload releases every allocated page.
 */
#include <linux/capability.h>
#include <linux/arm-smccc.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/reboot.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/umh.h>
#include <linux/vmalloc.h>
#include <asm/memory.h>
#include <asm/unaligned.h>
#include <net/net_namespace.h>
#include "boot-format.h"
#include "format.h"
#include "sha256.h"
#include "stock-profile.h"
#include "stock-dp.h"

#define B10_MAX_PAGES 18000U
#define B10_REJECT_PAGES ((B10_KERNEL_MEMORY_MAX+B10_DTB_MAX)/4096U+1U)
static char *image_sha256, *dtb_sha256;
static bool debug_markers;
module_param(image_sha256, charp, 0400);
module_param(dtb_sha256, charp, 0400);
module_param(debug_markers,bool,0400);
MODULE_PARM_DESC(debug_markers,"RAM-only diagnostic markers in the unused tail of the stock persistent log reservation");
MODULE_PARM_DESC(image_sha256, "Required SHA256 of staged Image (64 hex chars)");
MODULE_PARM_DESC(dtb_sha256, "Required SHA256 of staged DTB (64 hex chars)");

extern const unsigned char b10_trampoline_start[], b10_trampoline_end[];
extern void __noreturn b10_enter(unsigned long table, unsigned long code, unsigned long control);
static DEFINE_MUTEX(lock);
static unsigned long *pages, *rejected;
static unsigned nr_pages, nr_rejected;
static struct b10_copy_page *last_copy;
static struct b10_control *control;
static unsigned long pgtable, code_page, control_page;
static struct b10_status status;
static bool committed;
static u64 cpu_mpidr[4];
static void __iomem *watchdog;
static void (*shutdown_devices)(void);
static int (*disable_helpers)(int);
static void (*move_to_reboot_cpu)(void);
static void (*hotplug_enable)(void);
static int (*freeze_cpus)(int, bool);
static bool (*stuck_cpus)(void);
static void (*flush_data)(void *, unsigned long);
static void (*syscore_stop)(void);
static struct net_device *(*find_netdev)(struct net *,const char *);
static struct net_device *(*index_netdev)(struct net *,int);
static int (*close_netdev)(struct net_device *);
static void *edma_context;
static void (*edma_stop[3])(void *);
static void __iomem *edma;

static int check_edma(void)
{
	unsigned i,j;
	unsigned long first=kallsyms_lookup_name(b10_dp_functions[0].name),ctx=0;
	s64 page_delta=0; u32 low=0; unsigned seen=0;
	/* CONFIG_KALLSYMS_ALL=n drops module BSS symbols. Derive the exact ctx
	 * target from the first audited function's ADRP+ADD, then reconstruct
	 * and compare every instruction in all three functions against it.
	 */
	if(!first) {
		edma_context=NULL; memset(edma_stop,0,sizeof(edma_stop));
		return kallsyms_lookup_name("qca_nss_dp:nss_dp_is_in_open_state") ? -ENOEXEC:0;
	}
	for(j=0;j<b10_dp_functions[0].reloc_count;j++) {
		const struct b10_dp_reloc *r=&b10_dp_functions[0].reloc[j];
		u32 insn=get_unaligned_le32((void *)(first+r->offset));
		if(r->type==275) {
			u32 imm=((insn>>5)&0x7ffff)*4+((insn>>29)&3);
			page_delta=(s64)(imm^(1U<<20))-(1U<<20);
			ctx=(first+r->offset)&~4095UL; seen|=1;
		} else if(r->type==277) { low=(insn>>10)&4095; seen|=2; }
	}
	if(seen!=3) return -ENOEXEC;
	ctx+=(page_delta*4096)+low;
	if(ctx<0xffffff8000000000UL || ctx&7) return -ENOEXEC;
	edma_context=(void *)ctx;
	for(i=0;i<ARRAY_SIZE(b10_dp_functions);i++) {
		const struct b10_dp_function *f=&b10_dp_functions[i];
		unsigned char expected[256];
		unsigned long address=kallsyms_lookup_name(f->name);
		if(!address) return -ENOEXEC;
		memcpy(expected,f->code,f->bytes);
		for(j=0;j<f->reloc_count;j++) {
			const struct b10_dp_reloc *r=&f->reloc[j];
			u32 insn=get_unaligned_le32(expected+r->offset);
			if(r->type==275) { /* actual ADRP, relocated to the known ctx */
				s64 delta=((s64)(ctx&~4095UL)-(s64)((address+r->offset)&~4095UL))>>12;
				if(delta<-(1<<20) || delta>=(1<<20)) return -ENOEXEC;
				insn=(insn&~0x60ffffe0U)|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5);
			} else if(r->type==277) insn=(insn&~0x003ffc00U)|((ctx&4095)<<10);
			else return -ENOEXEC;
			put_unaligned_le32(insn,expected+r->offset);
		}
		if(memcmp((void *)address,expected,f->bytes)) return -ENOEXEC;
		edma_stop[i]=(void *)address;
	}
	return 0;
}

static void release_pages(void)
{
	unsigned i;
	for (i=0;i<nr_pages;i++) free_pages(pages[i],0);
	for (i=0;i<nr_rejected;i++) free_pages(rejected[i],0);
	vfree(pages); vfree(rejected);
	pages=rejected=NULL; nr_pages=nr_rejected=0;
}
static unsigned long high_page(void)
{
	while (nr_pages<B10_MAX_PAGES && nr_rejected<B10_REJECT_PAGES) {
		unsigned long address=__get_free_pages(GFP_KERNEL|__GFP_ZERO,0);
		phys_addr_t physical;
		if (!address) return 0;
		physical=virt_to_phys((void *)address);
		if (physical>=B10_STAGE_MIN && physical+PAGE_SIZE<=B10_STAGE_END) {
			/* Every destination is overwritten with the MMU off. Keep all
			 * source/control/code/table pages outside the full two allowed
			 * destination windows, regardless of current Image size.
			 */
			if ((physical<B10_KERNEL_LOAD+B10_KERNEL_MEMORY_MAX && physical+PAGE_SIZE>B10_KERNEL_LOAD) ||
			    (physical<B10_DTB_LOAD+B10_DTB_MAX && physical+PAGE_SIZE>B10_DTB_LOAD))
				goto reject;
			pages[nr_pages++]=address;
			return address;
		}
		/* Keep rejected pages until staging finishes: freeing immediately
		 * could make the allocator hand the same low page back forever.
		 */
reject:
		rejected[nr_rejected++]=address;
	}
	return 0;
}
static int append_copy(unsigned long source, u64 destination)
{
	if (!last_copy || last_copy->count==B10_ENTRIES_PER_PAGE) {
		unsigned long address=high_page();
		struct b10_copy_page *next=(void *)address;
		if (!address) return -ENOMEM;
		if (last_copy) last_copy->next=virt_to_phys(next);
		else control->copies=virt_to_phys(next);
		last_copy=next;
	}
	last_copy->entry[last_copy->count].source=virt_to_phys((void *)source);
	last_copy->entry[last_copy->count].destination=destination;
	last_copy->count++;
	return 0;
}
static int stage_segment(const unsigned char *data, size_t bytes, u64 memory, u64 destination)
{
	u64 off;
	for (off=0;off<ALIGN(memory,PAGE_SIZE);off+=PAGE_SIZE) {
		unsigned long address=high_page();
		size_t copy=off<bytes ? min_t(u64,PAGE_SIZE,bytes-off) : 0;
		int ret;
		if (!address) return -ENOMEM;
		if (copy) memcpy((void *)address,data+off,copy);
		ret=append_copy(address,destination+off);
		if (ret) return ret;
	}
	return 0;
}
static int hash_matches(const void *data, size_t size, const char *hex)
{
	unsigned char actual[32], expected[32];
	if (!hex || strlen(hex)!=64 || hex2bin(expected,hex,32)) return -EINVAL;
	b10_digest(data,size,actual);
	return memcmp(actual,expected,32) ? -EBADMSG : 0;
}
static int check_stock(void)
{
	unsigned i;
	u64 el, mmfr2, tcr, mair;
	struct device_node *node;
	const char *method;
	if (!of_machine_is_compatible("qcom,ipq9574-ap-al02-c2") || PAGE_SIZE!=4096)
		return -ENODEV;
	if ((unsigned long)kallsyms_lookup_name!=beacon10_stock_functions[0].address)
		return -ENOEXEC;
	for (i=0;i<ARRAY_SIZE(beacon10_stock_functions);i++) {
		const struct beacon10_stock_function *f=&beacon10_stock_functions[i];
		unsigned long address=kallsyms_lookup_name(f->name);
		unsigned variant;
		if (address!=f->address) return -ENOEXEC;
		for (variant=0;variant<f->variants;variant++)
			if (!memcmp((void *)address,f->code[variant],16)) break;
		if (variant==f->variants) return -ENOEXEC;
	}
	asm volatile("mrs %0, CurrentEL" : "=r"(el));
	asm volatile("mrs %0, id_aa64mmfr2_el1" : "=r"(mmfr2));
	asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
	asm volatile("mrs %0, mair_el1" : "=r"(mair));
	if (el!=4 || ((mmfr2>>20)&15) || ((mair>>32)&255)!=255 || ((tcr>>30)&3)!=2)
		return -EOPNOTSUPP;
	node=of_find_compatible_node(NULL,NULL,"arm,psci-1.0");
	if (!node) node=of_find_compatible_node(NULL,NULL,"arm,psci-0.2");
	if (!node) return -EOPNOTSUPP;
	i=of_property_read_string(node,"method",&method) || strcmp(method,"smc");
	of_node_put(node);
	if (i) return -EOPNOTSUPP;
	for (i=0;i<4;i++) {
		u32 value;
		node=of_get_cpu_node(i,NULL);
		if (!node) return -ENODEV;
		if (of_property_read_u64(node,"reg",&cpu_mpidr[i])) {
			if (of_property_read_u32(node,"reg",&value)) { of_node_put(node); return -EINVAL; }
			cpu_mpidr[i]=value;
		}
		of_node_put(node);
		if (cpu_mpidr[i]!=i) return -EOPNOTSUPP;
	}
	/* Every indirect call used after commit is SHA-bound by the profile. */
#define RESOLVE(dst,name) do { dst=(void *)kallsyms_lookup_name(name); if (!dst) return -ENOENT; } while (0)
	RESOLVE(shutdown_devices,"device_shutdown");
	RESOLVE(disable_helpers,"__usermodehelper_disable");
	RESOLVE(move_to_reboot_cpu,"migrate_to_reboot_cpu");
	RESOLVE(hotplug_enable,"cpu_hotplug_enable");
	RESOLVE(freeze_cpus,"__freeze_secondary_cpus");
	RESOLVE(stuck_cpus,"cpus_are_stuck_in_kernel");
	RESOLVE(flush_data,"__flush_dcache_area");
	RESOLVE(syscore_stop,"syscore_shutdown");
	RESOLVE(find_netdev,"__dev_get_by_name");
	RESOLVE(index_netdev,"__dev_get_by_index");
	RESOLVE(close_netdev,"dev_close");
#undef RESOLVE
	if(check_edma()) return -ENOEXEC;
	return stuck_cpus() ? -EBUSY : 0;
}
static int psci_others_off(void)
{
	unsigned cpu, retry;
	for (cpu=1;cpu<4;cpu++) {
		for (retry=0;retry<100;retry++) {
			struct arm_smccc_res result;
			arm_smccc_smc(0xc4000004,cpu_mpidr[cpu],0,0,0,0,0,0,&result);
			if (result.a0==1) break; /* PSCI affinity state OFF */
			if ((long)result.a0<0) return -EIO;
			udelay(100);
		}
		if (retry==100) return -ETIMEDOUT;
	}
	return 0;
}
static long b10_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	u64 confirm;
	unsigned i;
	int ret=0;
	struct pci_dev *pci=NULL;
	(void)file;
	if (!capable(CAP_SYS_BOOT)) return -EPERM;
	if (cmd==B10_IOCTL_STATUS) return copy_to_user((void __user *)arg,&status,sizeof(status)) ? -EFAULT : 0;
	if (cmd!=B10_IOCTL_EXECUTE) return -ENOTTY;
	if (copy_from_user(&confirm,(void __user *)arg,sizeof(confirm))) return -EFAULT;
	if (confirm!=B10_EXECUTE_CONFIRM) return -EINVAL;
	if (!mutex_trylock(&lock)) return -EBUSY;
	if (!status.ready || committed) { ret=-EBUSY; goto out; }
	ret=check_stock();
	if (ret) goto out;
	/* From here a failure requires a real reboot; never return userspace to
	 * a system whose device_shutdown() has already run.
	 */
	if (!try_module_get(THIS_MODULE)) { ret=-EBUSY; goto out; }
	committed=true;
	pr_emerg("beacon10: committing stock Linux -> QSDK handoff\n");
	/* NSS-DP has .remove but no platform .shutdown. Closing each physical
	 * netdev under RTNL invokes its own vendor ndo_stop before normal
	 * device_shutdown; do not depend on unused PCI bus-master bits for EDMA.
	 * __dev_get_by_name needs no reference while RTNL is held, so no vendor
	 * net_device layout is dereferenced by this out-of-tree module.
	 */
	rtnl_lock();
	for(i=1;i<=65535;i++) {
		struct net_device *dev=index_netdev(&init_net,i);
		if(dev && close_netdev(dev)) { rtnl_unlock(); goto reset; }
	}
	rtnl_unlock();
	if(edma_context) {
		/* Calls use the exact vendor context object and fully reconstructed
		 * relocated vendor instructions; no guessed context member offsets.
		 */
		for(i=0;i<ARRAY_SIZE(edma_stop);i++) edma_stop[i](edma_context);
		writel(0,edma+4); /* audited EDMA PORT_CTRL, disable the DMA port */
		if(readl(edma+4)) goto reset;
		udelay(1000);
	}
	for_each_pci_dev(pci) pci_clear_master(pci);
	/* A handoff is not a hardware restart. Retail SYS_RESTART notifiers
	 * prevent later CPU_ON even in the still-running stock kernel. Keep
	 * normal device shutdown/DMA quiescence, but do not announce a reboot.
	 * Stop usermode helpers explicitly before destroying the old context.
	 */
	if (disable_helpers(UMH_DISABLED)) goto reset;
	shutdown_devices();
	move_to_reboot_cpu();
	hotplug_enable(); /* migrate_to_reboot_cpu disables it; hotplug is needed below */
	ret=freeze_cpus(0,false);
	pr_emerg("beacon10: freeze returned %d, current CPU=%u online=%u\n",ret,raw_smp_processor_id(),num_online_cpus());
	if (ret || raw_smp_processor_id()!=0 || num_online_cpus()!=1 || psci_others_off())
		goto reset;
	pr_emerg("beacon10: secondary PSCI affinity states OFF verified\n");
	/* Firmware / all data are in RAM before devices or interrupts disappear. */
	writel(0,watchdog+8); writel(1,watchdog+4);
	if (readl(watchdog+8)&1) goto reset;
	pr_emerg("beacon10: watchdog disabled; calling syscore_shutdown\n");
	syscore_stop();
	pr_emerg("beacon10: syscore shutdown complete; entering physical trampoline\n");
	preempt_disable();
	asm volatile("msr daifset, #15" ::: "memory");
	for (i=0;i<nr_pages;i++) flush_data((void *)pages[i],PAGE_SIZE);
	asm volatile("dsb sy; ic iallu; dsb sy; isb" ::: "memory");
	b10_enter(virt_to_phys((void *)pgtable),virt_to_phys((void *)code_page),
		  virt_to_phys((void *)control_page));
reset:
	pr_emerg("beacon10: CPU/DMA shutdown did not complete; not copying or jumping\n");
	emergency_restart();
	for (;;) cpu_relax();
out:
	mutex_unlock(&lock);
	return ret;
}
static const struct file_operations b10_fops={
	.owner=THIS_MODULE, .unlocked_ioctl=b10_ioctl,
};
static struct miscdevice b10_misc={
	.minor=MISC_DYNAMIC_MINOR, .name="beacon10-handoff", .fops=&b10_fops, .mode=0600,
};
static int __init b10_init(void)
{
	const struct firmware *image=NULL, *dtb=NULL;
	u64 memory;
	size_t code_bytes=b10_trampoline_end-b10_trampoline_start;
	int ret=check_stock();
	const char *step="stock CPU/ABI preconditions";
	BUILD_BUG_ON(sizeof(struct b10_boot_header)!=4096);
	BUILD_BUG_ON(sizeof(struct b10_copy_page)!=4096);
	if (ret) { pr_err("beacon10: %s rejected (%d)\n",step,ret); return ret; }
	if (!image_sha256 || !dtb_sha256) return -EINVAL;
	if (!code_bytes || code_bytes>PAGE_SIZE) return -EFBIG;
	step="request Image";
	ret=request_firmware_direct(&image,"beacon10/Image",NULL);
	if (ret) goto out;
	step="request DTB";
	ret=request_firmware_direct(&dtb,"beacon10/beacon10.dtb",NULL);
	if (ret) goto out;
	step="Image/DTB validation";
	ret=hash_matches(image->data,image->size,image_sha256);
	if (!ret) ret=hash_matches(dtb->data,dtb->size,dtb_sha256);
	if (!ret) ret=b10_image_check(image->data,image->size,&memory);
	if (!ret) ret=b10_dtb_check(dtb->data,dtb->size,memory);
	if (ret) goto out;
	step="private nonoverlapping RAM allocation";
	pages=vzalloc(B10_MAX_PAGES*sizeof(*pages));
	rejected=vzalloc(B10_REJECT_PAGES*sizeof(*rejected));
	if (!pages || !rejected) { ret=-ENOMEM; goto out; }
	control_page=high_page(); code_page=high_page(); pgtable=high_page();
	if (!control_page || !code_page || !pgtable) { ret=-ENOMEM; goto out; }
	control=(void *)control_page;
	control->entry=B10_KERNEL_LOAD; control->dtb=B10_DTB_LOAD;
	if(debug_markers) control->trace=0x55affff0ULL;
	memcpy((void *)code_page,b10_trampoline_start,code_bytes);
	/* 39-bit TTBR0: one level-1 block for 40000000..7fffffff. AP=RO avoids
	 * WXN trouble while fetching the trampoline. Writes happen MMU-off.
	 */
	((u64 *)pgtable)[1]=0x40000000ULL | 0x791ULL;
	step="nonoverlapping RAM Image/DTB staging";
	ret=stage_segment(image->data,image->size,memory,B10_KERNEL_LOAD);
	if (!ret) ret=stage_segment(dtb->data,dtb->size,dtb->size,B10_DTB_LOAD);
	if (ret) goto out;
	step="watchdog mapping";
	watchdog=ioremap(0x0b017000,PAGE_SIZE);
	if (!watchdog) { ret=-ENOMEM; goto out; }
	edma=ioremap(0x3ab00000,PAGE_SIZE);
	if(!edma) { ret=-ENOMEM; goto out; }
	step="status device registration";
	ret=misc_register(&b10_misc);
	if (ret) goto out;
	status.version=1; status.ready=1; status.image_bytes=image->size;
	status.image_memory=memory; status.dtb_bytes=dtb->size; status.staging_pages=nr_pages;
	pr_info("beacon10: Image and DTB staged in private nonoverlapping RAM; explicit ioctl required to jump\n");
out:
	release_firmware(dtb); release_firmware(image);
	if (ret) {
		pr_err("beacon10: %s failed (%d), staged pages=%u rejected pages=%u\n",step,ret,nr_pages,nr_rejected);
		if (watchdog) iounmap(watchdog);
		if (edma) iounmap(edma);
		release_pages();
	}
	return ret;
}
static void __exit b10_exit(void)
{
	misc_deregister(&b10_misc);
	iounmap(watchdog);
	iounmap(edma);
	release_pages();
}
module_init(b10_init);
module_exit(b10_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Explicit Beacon10 stock Linux to QSDK ARM64 kernel handoff");
