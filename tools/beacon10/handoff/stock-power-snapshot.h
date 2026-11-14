/* SPDX-License-Identifier: GPL-2.0-only */
/* Stock handoff: retain references/read caches, never enable/set a supply.
 * B10_CPR_QUIESCE additionally suspends the old APSS controller at irreversible
 * commit, after governor/secondary CPU shutdown; staging remains read-only.
 * Final snapshot takes provider locks BEFORE the transport lock so an old
 * regulator setter cannot publish a new, unacknowledged value into the DT.
 */
#include <linux/clk.h>
#include <linux/regulator/consumer.h>
#include "rpm-power-format.h"

static struct regulator *b10_power_supply[5];
static void *b10_power_rdev[3],*b10_power_data[3];
static struct clk *b10_power_cpu_clock;
static void __iomem *b10_power_pll,*b10_power_mux;
static unsigned long b10_power_offset;
static unsigned char *b10_power_staged;
static unsigned char b10_power_snapshot[B10_POWER_BYTES];
static unsigned int b10_power_locked;
#ifdef B10_CPR_QUIESCE
static struct device *b10_power_cpr_device;
static void *b10_power_cpr_ctrl;
static bool b10_power_cpr_stopped;
static int b10_power_stop_cpr(void)
{
	int (*suspend)(void *)=(void *)kallsyms_lookup_name("cpr3_regulator_suspend");
	u8 enabled,stopped;
	int ret;
	if(!b10_power_cpr_ctrl) return -ENODEV;
	device_lock(b10_power_cpr_device);
	ret=suspend(b10_power_cpr_ctrl);
	if(!ret && (probe_kernel_read(&enabled,(char *)b10_power_cpr_ctrl+B10_POWER_CPR_ENABLED,1) || enabled ||
	   probe_kernel_read(&stopped,(char *)b10_power_cpr_ctrl+B10_POWER_CPR_SUSPENDED,1) || stopped!=1)) ret=-EIO;
	device_unlock(b10_power_cpr_device);
	if(!ret) {
		b10_power_cpr_stopped=true;
		pr_emerg("beacon10 CPR diagnostic: old APSS CPR suspended and loop disabled before snapshot\n");
	}
	return ret;
}
#endif
static void (*b10_power_reg_lock)(void *);
static void (*b10_power_reg_unlock)(void *);
static unsigned int (*b10_power_quick_get)(unsigned int);

static void b10_power_release(void)
{
	unsigned i;
	while(b10_power_locked) b10_power_reg_unlock(b10_power_rdev[--b10_power_locked]);
	for(i=0;i<ARRAY_SIZE(b10_power_supply);i++) {
		if(b10_power_supply[i]) regulator_put(b10_power_supply[i]);
		b10_power_supply[i]=NULL;
	}
	if(b10_power_cpu_clock) clk_put(b10_power_cpu_clock);
	b10_power_cpu_clock=NULL;
	if(b10_power_pll) iounmap(b10_power_pll);
	if(b10_power_mux) iounmap(b10_power_mux);
	b10_power_pll=b10_power_mux=NULL;
#ifdef B10_CPR_QUIESCE
	put_device(b10_power_cpr_device);b10_power_cpr_device=NULL;
#endif
}

static int b10_power_acquire(void)
{
	static const char * const name[5]={"s1","s2","s4","apc_corner","npu_corner"};
	static const u32 id[3]={1,2,4};
	struct device *cpu=get_cpu_device(0);
	unsigned i;
	if(!cpu) return -ENODEV;
#ifdef B10_CPR_QUIESCE
	b10_power_cpr_device=bus_find_device_by_name(&platform_bus_type,NULL,"b018000.cpr4-ctrl");
	if(!b10_power_cpr_device) return -ENODEV;
	{
		void *owner;
		if(strcmp(dev_driver_string(b10_power_cpr_device),"qcom,cpr4-apss-regulator") ||
		   probe_kernel_read(&b10_power_cpr_ctrl,(char *)b10_power_cpr_device+B10_RPM_DEVICE_DATA,8) || !b10_power_cpr_ctrl ||
		   probe_kernel_read(&owner,b10_power_cpr_ctrl,8) || owner!=b10_power_cpr_device) return -ENOEXEC;
	}
#endif
	b10_power_reg_lock=(void *)kallsyms_lookup_name("regulator_lock");
	b10_power_reg_unlock=(void *)kallsyms_lookup_name("regulator_unlock");
	b10_power_quick_get=(void *)kallsyms_lookup_name("cpufreq_quick_get");
	for(i=0;i<5;i++) {
		struct regulator *supply=regulator_get_optional(NULL,name[i]);
		if(IS_ERR(supply)) return PTR_ERR(supply); /* no dummy fallback */
		b10_power_supply[i]=supply;
		if(i<3) {
			void *data=regulator_get_drvdata(supply),*rpm;
			u32 identity[2];
			if(!data || probe_kernel_read(&rpm,(char *)data+B10_POWER_VREG_RPM,8) || rpm!=b10_rpm_private ||
			   probe_kernel_read(identity,(char *)data+B10_POWER_VREG_TYPE,8) ||
			   identity[0]!=B10_POWER_SMPA || identity[1]!=id[i] ||
			   probe_kernel_read(&b10_power_rdev[i],(char *)supply+B10_POWER_CONSUMER_RDEV,8) || !b10_power_rdev[i])
				return -ENOEXEC;
			b10_power_data[i]=data;
		}
		pr_info("beacon10 power diagnostic: pinned %s, cached value=%d enabled=%d; no resource request\n",
			name[i],regulator_get_voltage(supply),regulator_is_enabled(supply));
	}
	b10_power_cpu_clock=clk_get(cpu,"cpu");
	if(IS_ERR(b10_power_cpu_clock)) {
		int ret=PTR_ERR(b10_power_cpu_clock);b10_power_cpu_clock=NULL;return ret;
	}
	b10_power_pll=ioremap(0x0b116000,0x40);
	b10_power_mux=ioremap(0x0b111050,0x0c);
	if(!b10_power_pll || !b10_power_mux) return -ENOMEM;
#ifdef B10_STOCK_POWER_V1
 if(clk_get_rate(b10_power_cpu_clock)!=1488000000UL || b10_power_quick_get(0)!=1488000 ||
    regulator_is_enabled(b10_power_supply[4])!=0) return -EINVAL;
#endif
	pr_info("beacon10 power diagnostic: CPU clock=%luHz policy=%ukHz; no clock/voltage writes\n",
		clk_get_rate(b10_power_cpu_clock),b10_power_quick_get(0));
	return 0;
}

static int b10_power_lock_snapshot(void)
{
	unsigned i;
	unsigned long rate;
	int value,enabled;
	memset(b10_power_snapshot,0,sizeof(b10_power_snapshot));
	/* Read CPR corner indices before locking its supplier. */
	for(i=3;i<5;i++) {
		value=regulator_get_voltage(b10_power_supply[i]);
		enabled=regulator_is_enabled(b10_power_supply[i]);
		if(value<1 || enabled<0) return -EINVAL;
		b10_power_put(b10_power_snapshot,104+(i-3)*8,value);
		b10_power_put(b10_power_snapshot,108+(i-3)*8,enabled);
	}
	/* These three audited MP5496 providers are independent leaf resources,
	 * not coupled regulator groups. No RPM lock has been taken yet.
	 * Retain the provider locks until the old kernel is discarded.
	 */
	for(i=0;i<3;i++) {
		b10_power_reg_lock(b10_power_rdev[i]);
		b10_power_locked++;
	}
	rate=clk_get_rate(b10_power_cpu_clock);
	if(rate>0xffffffffUL) return -EINVAL;
#ifdef B10_STOCK_POWER_V1
 if(rate!=1488000000UL || b10_power_quick_get(0)!=1488000 ||
    b10_power_get(b10_power_snapshot,116)!=0 || !b10_power_cpr_stopped) return -EINVAL;
#endif
	b10_power_put(b10_power_snapshot,0,B10_POWER_MAGIC);
	b10_power_put(b10_power_snapshot,4,B10_POWER_VERSION);
	b10_power_put(b10_power_snapshot,8,B10_POWER_BYTES);
	b10_power_put(b10_power_snapshot,12,B10_POWER_FLAGS);
	b10_power_put(b10_power_snapshot,20,rate);
	b10_power_put(b10_power_snapshot,24,b10_power_quick_get(0));
	b10_power_put(b10_power_snapshot,28,B10_POWER_RAILS);
	for(i=0;i<3;i++) {
		unsigned off=B10_POWER_RAIL_OFFSET(i),j;
		u32 identity[2],cache[4];
		if(probe_kernel_read(identity,(char *)b10_power_data[i]+B10_POWER_VREG_TYPE,8) ||
		   probe_kernel_read(cache,(char *)b10_power_data[i]+B10_POWER_VREG_ENABLED,16)) return -EFAULT;
		b10_power_put(b10_power_snapshot,off,identity[0]);
		b10_power_put(b10_power_snapshot,off+4,identity[1]);
		for(j=0;j<4;j++) b10_power_put(b10_power_snapshot,off+8+j*4,cache[j]);
	}
	b10_power_put(b10_power_snapshot,120,7);
	for(i=0;i<16;i++) b10_power_put(b10_power_snapshot,B10_POWER_PLL_OFFSET+i*4,readl(b10_power_pll+i*4));
	for(i=0;i<3;i++) b10_power_put(b10_power_snapshot,B10_POWER_MUX_OFFSET+i*4,readl(b10_power_mux+i*4));
	b10_power_put(b10_power_snapshot,B10_POWER_NEXT_MSG_OFFSET,READ_ONCE(*(u32 *)B10_POWER_NEXT_MSG_ADDRESS));
#ifdef B10_CPR_QUIESCE
	b10_power_put(b10_power_snapshot,B10_POWER_CPR_STOPPED_OFFSET,b10_power_cpr_stopped);
#endif
	b10_power_put(b10_power_snapshot,252,b10_power_crc(b10_power_snapshot));
	if(!b10_power_valid(b10_power_snapshot,sizeof(b10_power_snapshot))) {
		pr_emerg("beacon10 power diagnostic: final snapshot rejected, no handoff\n");
		return -EINVAL;
	}
	pr_emerg("beacon10 power diagnostic: locked snapshot CPU=%luHz S1=%uuV S2=%uuV S4=%u; not physical measurements\n",
		rate,b10_power_get(b10_power_snapshot,44),b10_power_get(b10_power_snapshot,68),
		b10_power_get(b10_power_snapshot,92));
	return 0;
}

static int b10_power_publish(void)
{
	/* Called only while the old transport lock is held. Carry forward the
	 * exact next request ID, not a reset sequence or invented random value.
	 */
	b10_power_put(b10_power_snapshot,B10_POWER_NEXT_MSG_OFFSET,READ_ONCE(*(u32 *)B10_POWER_NEXT_MSG_ADDRESS));
	b10_power_put(b10_power_snapshot,252,b10_power_crc(b10_power_snapshot));
	if(!b10_power_staged || b10_power_locked!=3 || !b10_power_valid(b10_power_snapshot,sizeof(b10_power_snapshot)))
		return -EINVAL;
	memcpy(b10_power_staged,b10_power_snapshot,sizeof(b10_power_snapshot));
	return 0;
}
