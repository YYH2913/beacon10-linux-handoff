/* SPDX-License-Identifier: GPL-2.0-only */
/* Shared stock-power-v1 and explicit RAM diagnostic implementation.
 * Module init checks/pins the active endpoint but does not close it or change
 * frequency/voltage. The irreversible commit closes it only after normal
 * device shutdown (including governor suspension) and CPU offline complete.
 */
#include <linux/kref.h>
#include <linux/platform_device.h>
#include "stock-rpm-profile.h"
#ifdef B10_RPM_INHERIT
#include "stock-rpm-state.h"
#endif

static struct device *b10_rpm_device;
static void *b10_rpm_endpoint, *b10_rpm_private;
static bool b10_rpm_pinned;
static void (*b10_rpm_release)(struct kref *);
static void (*b10_rpm_destroy)(void *);
#ifdef B10_POWER_SNAPSHOT
#include "stock-power-snapshot.h"
#endif

static int b10_rpm_check(void)
{
	unsigned i;
	for (i=0;i<ARRAY_SIZE(b10_rpm_fingerprints);i++) {
		const struct b10_rpm_fingerprint *f=&b10_rpm_fingerprints[i];
		unsigned long address=kallsyms_lookup_name(f->name);
		if(address!=f->address || memcmp((void *)address,f->code,f->bytes)) {
			pr_err("beacon10 RPM diagnostic: full ABI check failed: %s\n",f->name);
			return -ENOEXEC;
		}
	}
	b10_rpm_release=(void *)kallsyms_lookup_name("qcom_glink_channel_release");
	b10_rpm_destroy=(void *)kallsyms_lookup_name("qcom_glink_destroy_ept");
	return 0;
}

static void b10_rpm_unpin(void)
{
#ifdef B10_POWER_SNAPSHOT
	b10_power_release();
#endif
	if(b10_rpm_pinned)
		kref_put((struct kref *)((char *)b10_rpm_endpoint+B10_RPM_CHANNEL_KREF),b10_rpm_release);
	b10_rpm_pinned=false;
	put_device(b10_rpm_device);
	b10_rpm_device=NULL;
}

static int b10_rpm_live(void)
{
	void *ept,*data,*pair[2],*owner,*cb;
	if(!b10_rpm_pinned || strcmp(dev_driver_string(b10_rpm_device),"qcom_smd_rpm") ||
	   probe_kernel_read(&ept,(char *)b10_rpm_device+B10_RPM_DEVICE_EPT,8) || ept!=b10_rpm_endpoint ||
	   probe_kernel_read(&data,(char *)b10_rpm_device+B10_RPM_DEVICE_DATA,8) || data!=b10_rpm_private ||
	   probe_kernel_read(pair,data,sizeof(pair)) || pair[0]!=ept || pair[1]!=b10_rpm_device ||
	   probe_kernel_read(&owner,(char *)ept+B10_RPM_CHANNEL_RPDEV,8) || owner!=b10_rpm_device ||
	   probe_kernel_read(&cb,(char *)ept+16,8) || cb!=(void *)kallsyms_lookup_name("qcom_smd_rpm_callback"))
		return -ENODEV;
	return 0;
}

static int b10_rpm_acquire(void)
{
	struct device *parent;
	struct device *(*find_child)(struct device *,const char *);
	void *ept, *data, *pair[2], *owner, *ops, *destroy;
	u32 ids[2];
	int ret=-EINVAL;
	BUILD_BUG_ON(offsetof(struct device,mutex)!=B10_RPM_DEVICE_MUTEX);
	BUILD_BUG_ON(sizeof(struct kref)!=4);
	if(b10_rpm_check()) return -ENOEXEC;
	parent=bus_find_device_by_name(&platform_bus_type,NULL,"rpm-glink");
	if(!parent) return -ENODEV;
	find_child=(void *)kallsyms_lookup_name("device_find_child_by_name");
	b10_rpm_device=find_child(parent,"rpm-glink.rpm_requests.-1.-1");
	put_device(parent);
	if(!b10_rpm_device) return -ENODEV;
	/* Hold the driver-core device lock while reading/pinning the channel:
	 * remote removal must finish rpmsg_dev_remove before dropping its refs.
	 * Only this exact, instruction-checked device mutex offset is compiled.
	 */
	device_lock(b10_rpm_device);
	if(strcmp(dev_driver_string(b10_rpm_device),"qcom_smd_rpm")) goto out;
	if(probe_kernel_read(&ept,(char *)b10_rpm_device+B10_RPM_DEVICE_EPT,8) || !ept ||
	   probe_kernel_read(&data,(char *)b10_rpm_device+B10_RPM_DEVICE_DATA,8) || !data ||
	   probe_kernel_read(pair,data,sizeof(pair)) || pair[0]!=ept || pair[1]!=b10_rpm_device ||
	   probe_kernel_read(&owner,(char *)ept+B10_RPM_CHANNEL_RPDEV,8) || owner!=b10_rpm_device ||
	   probe_kernel_read(ids,(char *)ept+B10_RPM_CHANNEL_LCID,sizeof(ids)) ||
	   !ids[0] || !ids[1] || ids[0]>65535 || ids[1]>65535 ||
           probe_kernel_read(&ops,(char *)ept+B10_RPM_ENDPOINT_OPS,8) || !ops ||
	   probe_kernel_read(&destroy,ops,8) || destroy!=(void *)b10_rpm_destroy)
		goto out;
	if(!kref_get_unless_zero((struct kref *)((char *)ept+B10_RPM_CHANNEL_KREF))) goto out;
	b10_rpm_endpoint=ept; b10_rpm_private=data; b10_rpm_pinned=true;
	pr_info("beacon10 RPM diagnostic: endpoint ABI checked and pinned, lcid=%u rcid=%u; no close at staging\n",ids[0],ids[1]);
	ret=0;
out:
	device_unlock(b10_rpm_device);
	if(ret) b10_rpm_unpin();
	return ret;
}

static int b10_rpm_close(void)
{
	unsigned i;
	u8 suspended;
	u32 lcid,rcid;
	struct mutex *rpm_lock=(void *)((char *)b10_rpm_private+B10_RPM_LOCK);
	if(!b10_rpm_pinned || num_online_cpus()!=1 || raw_smp_processor_id()!=0 ||
	   probe_kernel_read(&suspended,(void *)B10_RPM_CPUFREQ_SUSPENDED,1) || suspended!=1)
		return -EBUSY;
	device_lock(b10_rpm_device);
	if(b10_rpm_live()) { device_unlock(b10_rpm_device); return -ENODEV; }
#ifdef B10_POWER_SNAPSHOT
#ifdef B10_CPR_QUIESCE
	if(b10_power_stop_cpr()) { device_unlock(b10_rpm_device); return -EIO; }
#endif
	if(b10_power_lock_snapshot()) { device_unlock(b10_rpm_device); return -EINVAL; }
#endif
	/* Drain the final resource request and block any late consumers without
	 * deleting regulator suppliers or issuing an enable/voltage request.
	 * The remote firmware's policy on CLOSE remains to be hardware-tested.
	 * This lock remains held until the old kernel is discarded/rebooted.
	 */
	for(i=0;i<500;i++) {
		if(mutex_trylock(rpm_lock)) break;
		msleep(10);
	}
	if(i==500) { device_unlock(b10_rpm_device); return -ETIMEDOUT; }
#ifdef B10_RPM_INHERIT
	{
		void *glink; unsigned long features;u8 intentless;
		if(!b10_rpm_state_staged ||
		   probe_kernel_read(&glink,(char *)b10_rpm_endpoint+B10_RPM_CHANNEL_GLINK,8) || !glink ||
		   probe_kernel_read(&features,(char *)glink+B10_RPM_GLINK_FEATURES,8) || features ||
		   probe_kernel_read(&intentless,(char *)glink+B10_RPM_GLINK_INTENTLESS,1) || intentless!=1) {
			device_unlock(b10_rpm_device);return -EINVAL;
		}
		lcid=READ_ONCE(*(u32 *)((char *)b10_rpm_endpoint+B10_RPM_CHANNEL_LCID));
		rcid=READ_ONCE(*(u32 *)((char *)b10_rpm_endpoint+B10_RPM_CHANNEL_RCID));
		if(!lcid || !rcid || lcid>65535 || rcid>65535) { device_unlock(b10_rpm_device);return -EINVAL; }
#ifdef B10_POWER_SNAPSHOT
		if(b10_power_publish()) { device_unlock(b10_rpm_device);return -EINVAL; }
#endif
		/* Publish only after consumers have stopped and all writes drained.
		 * New Linux must independently require empty, valid FIFO cursors.
		 * No VERSION/OPEN/CLOSE or RPM resource request is sent here.
		 */
		put_unaligned_be32(0x42313052,b10_rpm_state_staged);
		put_unaligned_be32(1,b10_rpm_state_staged+4);
		put_unaligned_be32(lcid,b10_rpm_state_staged+8);
		put_unaligned_be32(rcid,b10_rpm_state_staged+12);
		put_unaligned_be32(features,b10_rpm_state_staged+16);
		put_unaligned_be32(1,b10_rpm_state_staged+20);
		put_unaligned_be32(1,b10_rpm_state_staged+24);
		smp_wmb();
		device_unlock(b10_rpm_device);
		pr_emerg("beacon10 RPM diagnostic: inherited live intentless channel lcid=%u rcid=%u; no CLOSE/OPEN sent\n",lcid,rcid);
		return 0;
	}
#else
	pr_emerg("beacon10 RPM diagnostic: governors suspended, CPUs off, requests drained; endpoint-only CLOSE\n");
	b10_rpm_destroy(b10_rpm_endpoint);
	device_unlock(b10_rpm_device);
	for(i=0;i<300;i++) {
		lcid=READ_ONCE(*(u32 *)((char *)b10_rpm_endpoint+B10_RPM_CHANNEL_LCID));
		rcid=READ_ONCE(*(u32 *)((char *)b10_rpm_endpoint+B10_RPM_CHANNEL_RCID));
		if(!lcid && !rcid) {
			pr_emerg("beacon10 RPM diagnostic: CLOSE acknowledged in both directions; suppliers retained\n");
			return 0;
		}
		msleep(10);
	}
	pr_emerg("beacon10 RPM diagnostic: incomplete CLOSE lcid=%u rcid=%u; refuse handoff\n",lcid,rcid);
	return -ETIMEDOUT;
#endif
}
