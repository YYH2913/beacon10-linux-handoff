// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/watchdog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "boot-format.h"
#include "format.h"
#include "sha256.h"
#include "storage.h"
#ifdef B10_MINIMAL_RAM_TRIAL
#include "ram-trial-input.h"
#endif

static int rescue_watchdog=-1;
static int watchdog_feed(void)
{
	return rescue_watchdog<0 || ioctl(rescue_watchdog,WDIOC_KEEPALIVE,0) ? -EIO:0;
}
static int watchdog_start(void)
{
	int timeout=60,actual=0;
	if(rescue_watchdog>=0) return watchdog_feed();
	if(mknod("/dev/watchdog",S_IFCHR|0600,makedev(10,130)) && errno!=EEXIST) return -errno;
	rescue_watchdog=open("/dev/watchdog",O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
	if(rescue_watchdog<0) return -errno;
	/* Keep the descriptor open even on error: closing an armed watchdog is
	 * not a recovery strategy. Rescue can keep feeding the inherited timer.
	 */
	(void)ioctl(rescue_watchdog,WDIOC_SETTIMEOUT,&timeout);
	if(ioctl(rescue_watchdog,WDIOC_GETTIMEOUT,&actual) || actual<30) return -EIO;
	return watchdog_feed();
}
static int policy_value(const char *name,const char *expected,int write_value)
{
	char path[192],value[64]; ssize_t n; int fd,ret=0;
	if(snprintf(path,sizeof(path),"/sys/devices/system/cpu/cpufreq/policy0/%s",name)>=(int)sizeof(path)) return -EINVAL;
	fd=open(path,(write_value ? O_WRONLY:O_RDONLY)|O_CLOEXEC|O_NOFOLLOW);
	if(fd<0) return -errno;
	if(write_value) {
		if(write(fd,expected,strlen(expected))!=(ssize_t)strlen(expected)) ret=-EIO;
	} else {
		n=read(fd,value,sizeof(value));
		if(n!=(ssize_t)strlen(expected) || memcmp(value,expected,(size_t)n)) ret=-EIO;
	}
	if(close(fd) && !ret) ret=-EIO;
	return ret;
}
static int pin_cpu_policy(void)
{
	int ret=policy_value("scaling_governor","userspace\n",1);
	if(!ret) ret=policy_value("scaling_setspeed","1488000\n",1);
	if(!ret) ret=policy_value("scaling_governor","userspace\n",0);
	if(!ret) ret=policy_value("scaling_cur_freq","1488000\n",0);
	return ret;
}

static int load_boot(const char *path,struct b10_boot_header *h,unsigned char **image,unsigned char **dtb,int persistent)
{
	struct stat st;
	unsigned char hash[32], gap[4096];
	uint64_t memory;
	int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW),ret=-EINVAL;
	*image=*dtb=NULL;
	if(fd<0) return -errno;
	if(fstat(fd,&st) || (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))) goto out;
	if(b10_read_at(fd,h,sizeof(*h),0) || b10_header_check(h)) goto out;
	if(S_ISREG(st.st_mode) && (uint64_t)st.st_size!=h->total_bytes) goto out;
	*image=malloc(h->kernel_bytes); *dtb=malloc(h->dtb_bytes);
	if(!*image || !*dtb) { ret=-ENOMEM; goto out; }
	if(b10_read_at(fd,*image,h->kernel_bytes,h->kernel_offset) ||
	   b10_read_at(fd,*dtb,h->dtb_bytes,h->dtb_offset)) { ret=-EIO; goto out; }
	b10_digest(*image,h->kernel_bytes,hash);
	if(memcmp(hash,h->kernel_sha256,32)) { ret=-EBADMSG; goto out; }
	b10_digest(*dtb,h->dtb_bytes,hash);
	if(memcmp(hash,h->dtb_sha256,32)) { ret=-EBADMSG; goto out; }
	if(b10_image_check(*image,h->kernel_bytes,&memory) || memory!=h->kernel_memory ||
	   (persistent ? b10_dtb_check_persistent(*dtb,h->dtb_bytes,memory):
	                 b10_dtb_check(*dtb,h->dtb_bytes,memory))) goto out;
	if(h->dtb_offset>h->kernel_offset+h->kernel_bytes) {
		size_t n=h->dtb_offset-h->kernel_offset-h->kernel_bytes,i;
		if(n>sizeof(gap) || b10_read_at(fd,gap,n,h->kernel_offset+h->kernel_bytes)) goto out;
		for(i=0;i<n;i++) if(gap[i]) goto out;
	}
	ret=0;
out:
	close(fd);
	if(ret) { free(*image); free(*dtb); *image=*dtb=NULL; }
	return ret;
}
static int output_file(const char *dir,const char *name,const void *data,size_t size)
{
	char path[512]; size_t done=0;
	int fd;
	if(snprintf(path,sizeof(path),"%s/%s",dir,name)>=(int)sizeof(path)) return -EINVAL;
	fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
	if(fd<0) return -errno;
	while(done<size) {
		ssize_t n=write(fd,(const char *)data+done,size-done);
		if(n<0 && errno==EINTR) continue;
		if(n<=0) { close(fd); return -EIO; }
		done+=(size_t)n;
	}
	if(fsync(fd)) { close(fd); return -EIO; }
	close(fd); return 0;
}
static void hex(char out[65],const unsigned char bytes[32])
{
	unsigned i;
	for(i=0;i<32;i++) snprintf(out+2*i,3,"%02x",bytes[i]);
}
static int device_node(const char *sysdev,const char *path,int block)
{
	FILE *f=fopen(sysdev,"r"); unsigned maj,min;
	struct stat st;
	int ret;
	if(!f) return -errno;
	ret=fscanf(f,"%u:%u",&maj,&min); fclose(f);
	if(ret!=2) return -EINVAL;
	if(lstat(path,&st)==0)
		return ((block ? S_ISBLK(st.st_mode) : S_ISCHR(st.st_mode)) &&
			st.st_rdev==makedev(maj,min)) ? 0 : -EPERM;
	if(errno!=ENOENT) return -errno;
	return mknod(path,(block ? S_IFBLK : S_IFCHR)|0600,makedev(maj,min)) ? -errno : 0;
}
static int no_extra_modules(void)
{
	char line[1024],name[256]; FILE *f=fopen("/proc/modules","r");
	if(!f) return -errno;
	while(fgets(line,sizeof(line),f)) {
		if(sscanf(line,"%255s",name)!=1 || strcmp(name,"beacon10_handoff")) { fclose(f); return -EBUSY; }
	}
	fclose(f); return 0;
}
static int no_writable_disks(void)
{
	char dev[256],path[256],type[64],opts[512],line[1200];
	FILE *f=fopen("/proc/mounts","r");
	if(!f) return -errno;
	while(fgets(line,sizeof(line),f)) {
		if(sscanf(line,"%255s %255s %63s %511s",dev,path,type,opts)!=4) { fclose(f); return -EINVAL; }
		if((!strncmp(dev,"/dev/",5) || !strcmp(dev,"rootfs")) &&
		   (!strncmp(opts,"rw,",3) || !strcmp(opts,"rw"))) { fclose(f); return -EBUSY; }
	}
	fclose(f); return 0;
}
static int load_module(const struct b10_boot_header *h)
{
	char image[65],dtb[65],options[192];
	struct stat st;
	int fd,ret,n;
	hex(image,h->kernel_sha256); hex(dtb,h->dtb_sha256);
	n=snprintf(options,sizeof(options),"image_sha256=%s dtb_sha256=%s"
#ifdef B10_MINIMAL_RAM_TRIAL
		   " debug_markers=1"
#endif
		   ,image,dtb);
	if(n<0 || n>=(int)sizeof(options)) return -EOVERFLOW;
	fd=open("/lib/modules/5.4.164/beacon10-handoff.ko",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
	if(fd<0) return -errno;
	if(fstat(fd,&st)) ret=-errno;
	else if(!S_ISREG(st.st_mode)) ret=-EINVAL;
	else {
		/* A minimal BusyBox can silently discard insmod arguments. Pass the
		 * two required hashes directly, with ordinary kernel ABI checks and
		 * no force flags, as the audited status-only client already does.
		 */
		ret=syscall(SYS_finit_module,fd,options,0) ? -errno:0;
	}
	close(fd);
	return ret;
}
static int cid_check(const unsigned char expected[16])
{
	char text[40]; unsigned i;
	FILE *f=fopen("/sys/class/block/mmcblk0/device/cid","r");
	if(!f) return -errno;
	if(!fgets(text,sizeof(text),f)) { fclose(f); return -EIO; }
	fclose(f);
	if(strcspn(text,"\r\n")!=32) return -EINVAL;
	for(i=0;i<16;i++) { unsigned v; if(sscanf(text+2*i,"%2x",&v)!=1 || v!=expected[i]) return -EPERM; }
	return 0;
}
static int stage_and_jump(const struct b10_boot_header *h)
{
 struct b10_status status;
 uint64_t confirm=B10_EXECUTE_CONFIRM;
 int ret,control=-1;
	ret=pin_cpu_policy();
	if(ret || watchdog_feed()) { if(!ret) ret=-EIO; goto done; }
	ret=load_module(h);
	if(ret) goto done;
	ret=device_node("/sys/class/misc/beacon10-handoff/dev","/dev/beacon10-handoff",0);
	if(ret) goto done;
	control=open("/dev/beacon10-handoff",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
	if(control<0 || ioctl(control,B10_IOCTL_STATUS,&status) || status.version!=1 || !status.ready ||
	   status.image_bytes!=h->kernel_bytes || status.image_memory!=h->kernel_memory || status.dtb_bytes!=h->dtb_bytes) {
		ret=-ENOEXEC; goto done;
	}
	sync();
	puts("Beacon10: validated stock-linux-v1; committing kernel handoff"); fflush(stdout);
	ret=ioctl(control,B10_IOCTL_EXECUTE,&confirm) ? -errno : -EIO;
done:
 if(control>=0) close(control);
 return ret;
}

#ifndef B10_MINIMAL_RAM_TRIAL
static int boot(void)
{
	struct b10_boot_header h;
	struct b10_state state;
	unsigned char guid[16],*image=NULL,*dtb=NULL,root_head[96];
	uint64_t size=0;
	int fd=-1,ret=-EPERM;
	if(geteuid() || getpid()!=1 || no_extra_modules() || no_writable_disks()) return -EPERM;
	if(watchdog_start()) return -EIO;
	if(device_node("/sys/class/block/mmcblk0/dev","/dev/mmcblk0",1) ||
	   device_node("/sys/class/block/mmcblk0p29/dev","/dev/mmcblk0p29",1)) return -ENODEV;
	fd=open("/dev/mmcblk0",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
	if(fd<0) return -errno;
	if(ioctl(fd,BLKGETSIZE64,&size) || size!=B10_SECTORS*512 || b10_layout_check(fd,guid)) goto out;
	if(b10_state_read(fd,guid,&state) || state.flags!=B10_STATE_READY || state.attempts>=3 || cid_check(state.cid)) goto out;
	/* Keep room for both this attempt and its successful acknowledgement. */
	if(state.sequence>B10_STATE_MAX_SEQUENCE-2) { ret=-EOVERFLOW; goto out; }
	ret=load_boot("/dev/mmcblk0p29",&h,&image,&dtb,1);
	if(ret) goto out;
	if(memcmp(state.kernel_sha256,h.kernel_sha256,32)) { ret=-ESTALE; goto out; }
	/* Refuse absent/corrupt root headers before shutting down the old kernel. */
	if(b10_read_at(fd,root_head,sizeof(root_head),B10_ROOTFS_START_SECTORS*512) || memcmp(root_head,"hsqs",4)) { ret=-ENOEXEC; goto out; }
	if(state.rootfs_bytes<96 || state.rootfs_bytes>B10_ROOTFS_PARTITION_BYTES) { ret=-EINVAL; goto out; }
	{
		struct b10_sha256 sha; unsigned char block[65536],digest[32]; uint64_t off;
		b10_sha256_init(&sha);
		for(off=0;off<state.rootfs_bytes;) {
			size_t n=state.rootfs_bytes-off<sizeof(block) ? state.rootfs_bytes-off : sizeof(block);
			if(b10_read_at(fd,block,n,B10_ROOTFS_START_SECTORS*512+off)) { ret=-EIO; goto out; }
			b10_sha256_update(&sha,block,n); off+=n;
			if(watchdog_feed()) { ret=-EIO; goto out; }
		}
		b10_sha256_final(&sha,digest);
		if(memcmp(digest,state.rootfs_sha256,32)) { ret=-EBADMSG; goto out; }
	}
	if(b10_dtb_set_sequence(dtb,h.dtb_bytes,state.sequence+1)) { ret=-EINVAL; goto out; }
	b10_digest(dtb,h.dtb_bytes,h.dtb_sha256);
	if(mkdir("/lib/firmware/beacon10",0700) ||
	   output_file("/lib/firmware/beacon10","Image",image,h.kernel_bytes) ||
	   output_file("/lib/firmware/beacon10","beacon10.dtb",dtb,h.dtb_bytes)) { ret=-EIO; goto out; }
	free(image); free(dtb); image=dtb=NULL;
	/* Include CPU control and module staging in the bounded attempt. The
	 * DT already carries this sequence. A stuck stage can then expire the
	 * watchdog three times before the next boot stays in recovery.
	 */
	state.sequence++; state.attempts++;
	if(watchdog_feed()) { ret=-EIO; goto out; }
	ret=b10_state_write(fd,&state);
	if(ret) goto out;
	if(close(fd)) { fd=-1; ret=-EIO; goto out; } fd=-1;
	ret=stage_and_jump(&h);
out:
	if(fd>=0) close(fd);
	free(image); free(dtb);
	return ret;
}
#endif
#ifdef B10_MINIMAL_RAM_TRIAL
static int ram_hash_file(void)
{
	unsigned char block[65536],digest[32]; char actual[65]; struct b10_sha256 sha;
	struct stat st; ssize_t n; int fd,ret=-EBADMSG;
	fd=open("/trial/boot.bin",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
	if(fd<0) return -errno;
	if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_nlink!=1 ||
	   st.st_size<4096 || st.st_size>(32<<20)) goto out;
	b10_sha256_init(&sha);
	while((n=read(fd,block,sizeof(block)))!=0) {
		if(n<0) { if(errno==EINTR) continue; goto out; }
		b10_sha256_update(&sha,block,(size_t)n);
		if(watchdog_feed()) goto out;
	}
	b10_sha256_final(&sha,digest); hex(actual,digest);
	ret=strcmp(actual,B10_RAM_BOOT_SHA256)?-EBADMSG:0;
out:
	close(fd); return ret;
}
static int ram_factory_check(void)
{
	unsigned char block[34*512],digest[32]; char actual[65]; uint64_t size;
	int fd,ret=-ESTALE;
	if(device_node("/sys/class/block/mmcblk0/dev","/dev/mmcblk0",1)) return -ENODEV;
	fd=open("/dev/mmcblk0",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
	if(fd<0) return -errno;
	if(ioctl(fd,BLKGETSIZE64,&size) || size!=B10_SECTORS*512 ||
	   b10_read_at(fd,block,sizeof(block),0)) goto out;
	b10_digest(block,sizeof(block),digest); hex(actual,digest);
	ret=strcmp(actual,B10_RAM_FACTORY_GPT_SHA256)?-ESTALE:0;
out:
	close(fd); return ret;
}
static int ram_boot(void)
{
	static const unsigned char cid[16]=B10_RAM_CID;
	struct b10_boot_header h; struct statfs fs; FILE *f; char state[16];
	unsigned char *image=NULL,*dtb=NULL; unsigned attempt;
	int ret=-EPERM;
	if(geteuid() || getpid()!=1 || statfs("/",&fs) || fs.f_type!=SQUASHFS_MAGIC ||
	   !(fs.f_flags&ST_RDONLY) || no_extra_modules() || no_writable_disks()) return ret;
	if(watchdog_start()) return -EIO;
	for(attempt=0;attempt<30;attempt++) {
		if(!access("/sys/class/remoteproc/remoteproc0/state",R_OK) &&
		   !access("/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",R_OK)) break;
		if(watchdog_feed()) return -EIO;
		sleep(1);
	}
	if(attempt==30) return -ETIMEDOUT;
	f=fopen("/sys/class/remoteproc/remoteproc0/state","r");
	if(!f) return -ENODEV;
	state[0]=0;
	if(!fgets(state,sizeof(state),f) || strcmp(state,"offline\n")) { fclose(f); return -EBUSY; }
	fclose(f);
	if(cid_check(cid) || ram_factory_check() || ram_hash_file()) return -ESTALE;
	ret=load_boot("/trial/boot.bin",&h,&image,&dtb,0);
	if(ret) goto out;
	if(statfs("/lib/firmware",&fs) || fs.f_type!=TMPFS_MAGIC ||
	   mkdir("/lib/firmware/beacon10",0700) ||
	   output_file("/lib/firmware/beacon10","Image",image,h.kernel_bytes) ||
	   output_file("/lib/firmware/beacon10","beacon10.dtb",dtb,h.dtb_bytes)) { ret=-EIO; goto out; }
	free(image); free(dtb); image=dtb=NULL;
	puts("Beacon10 minimal PID1 RAM trial: factory CID/GPT and fixed payload verified; no disk writes");
	fflush(stdout);
	ret=stage_and_jump(&h);
out:
	free(image); free(dtb); return ret;
}
#endif
static void rescue_hold(void)
{
	/* An unrecoverable root transition must not run old-loader path logic
	 * in a new chroot, or silently turn rescue into a watchdog reboot loop.
	 */
	for(;;) {
		if(rescue_watchdog>=0) (void)watchdog_feed();
		sleep(1);
	}
}
static void rescue_ram_request(void)
{
	char path[256],wdt[32],target[320]; struct stat st; struct statfs fs;
	char *previous_wdt=NULL; const char *inherited_wdt;
	int fd=open("/tmp/beacon10-ram-request",O_RDONLY|O_CLOEXEC|O_NOFOLLOW),old;
	int flags=-1,rooted=0,error;
	ssize_t n;
	if(fd<0) return;
	if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_nlink!=1 || st.st_uid ||
	   st.st_mode&077 || st.st_size<1 || st.st_size>250) { close(fd); return; }
	n=read(fd,path,sizeof(path)-1); close(fd);
	if(n!=st.st_size || memchr(path,0,(size_t)n)) return;
	path[n]=0; if(path[n-1]=='\n') path[--n]=0;
	if(strncmp(path,"/tmp/beacon10-ram-",18) || !path[18] || strspn(path+18,"0123456789")!=strlen(path+18) ||
	   lstat(path,&st) || !S_ISDIR(st.st_mode) || st.st_uid || st.st_mode&077 ||
	   statfs(path,&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) return;
	if(snprintf(target,sizeof(target),"%s/sbin/upgraded",path)>=(int)sizeof(target) ||
	   lstat(target,&st) || !S_ISREG(st.st_mode) || st.st_nlink!=1 || st.st_uid ||
	   st.st_mode&022 || !(st.st_mode&S_IXUSR)) return;
	old=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC); if(old<0) return;
	inherited_wdt=getenv("WDTFD");
	if(inherited_wdt && !(previous_wdt=strdup(inherited_wdt))) { close(old); return; }
	if(rescue_watchdog>=0 && (flags=fcntl(rescue_watchdog,F_GETFD))<0) goto failed;
	/* Consume an accepted request before changing roots. A failed exec is
	 * reported once; only a fresh operator request may retry the transition.
	 */
	if(unlink("/tmp/beacon10-ram-request")) goto failed;
	if(rescue_watchdog>=0) {
		if(fcntl(rescue_watchdog,F_SETFD,flags&~FD_CLOEXEC)) goto failed;
		snprintf(wdt,sizeof(wdt),"%d",rescue_watchdog);
		if(setenv("WDTFD",wdt,1)) goto failed;
	}
	if(chroot(path)) goto failed;
	rooted=1;
	if(fchdir(old)) goto failed;
	/* Keep the CLOEXEC old-root fd until exec succeeds. It is our rollback
	 * anchor if a regular executable has a bad ELF/interpreter or IO error.
	 */
	execl("/sbin/upgraded","upgraded","/install.bin","beacon10-ram",(char *)NULL);
failed:
	error=errno;
	if(rooted && (fchdir(old) || chroot(".") || chdir("/"))) {
		fputs("Beacon10: RAM maintenance root rollback failed; holding watchdog without retry or disk writes.\n",stderr);
		free(previous_wdt); close(old); rescue_hold();
	}
	if(flags>=0) (void)fcntl(rescue_watchdog,F_SETFD,flags);
	if(previous_wdt) (void)setenv("WDTFD",previous_wdt,1);
	else (void)unsetenv("WDTFD");
	free(previous_wdt); close(old);
	fprintf(stderr,"Beacon10: RAM maintenance request stopped (%d); original recovery retained; no automatic retry or disk writes.\n",error);
}
static void rescue_feed(void)
{
	if(rescue_watchdog>=0) (void)watchdog_feed();
	rescue_ram_request();
}
static void rescue_wait(pid_t pid)
{
	int status;
	if(pid<0) return;
	for(;;) {
		pid_t n=waitpid(pid,&status,WNOHANG);
		if(n==pid || (n<0 && errno!=EINTR)) break;
		rescue_feed(); sleep(1);
	}
}
static void rescue(int error)
{
	fprintf(stderr,"Beacon10: handoff stopped (%d); no automatic reboot or blind retry.\n",error);
	/* No procd runs in the persistent bootstrap. Keep the hardware watchdog
	 * fed while waiting for recovery instead of silently reboot-looping.
	 */
	if(watchdog_start()) fputs("Beacon10: unable to establish recovery watchdog\n",stderr);
	{
		pid_t pid=fork();
		if(!pid) { execl("/sbin/beacon10-recovery","beacon10-recovery",(char *)NULL); _exit(127); }
		rescue_wait(pid);
	}
	for(;;) {
		pid_t pid=fork();
		if(!pid) { execl("/bin/sh","sh",(char *)NULL); _exit(127); }
		rescue_wait(pid);
		rescue_feed(); sleep(1);
	}
}
int main(int argc,char **argv)
{
#ifdef B10_MINIMAL_RAM_TRIAL
	if(argc==2 && !strcmp(argv[1],"--ram-handoff")) {
		if(geteuid() || getpid()!=1) { fputs("PID1 required\n",stderr); return 2; }
		{ int ret=ram_boot(); rescue(ret); }
	}
	fputs("Usage: b10-loader --ram-handoff (fixed-payload RAM trial, PID1 only)\n",stderr);
	return 2;
#else
	struct b10_boot_header h;
	unsigned char *image,*dtb;
	int ret;
	if(argc==2 && !strcmp(argv[1],"--boot")) {
		if(geteuid() || getpid()!=1) { fputs("PID1 required\n",stderr); return 2; }
		ret=boot(); rescue(ret);
	}
	if((argc==3 && !strcmp(argv[1],"--verify")) || (argc==4 && !strcmp(argv[1],"--extract"))) {
		ret=load_boot(argv[2],&h,&image,&dtb,1);
		if(ret) { fprintf(stderr,"Beacon10 boot payload rejected: %d\n",ret); return 1; }
		if(argc==4) {
			if(mkdir(argv[3],0700) || output_file(argv[3],"Image",image,h.kernel_bytes) ||
			   output_file(argv[3],"beacon10.dtb",dtb,h.dtb_bytes)) { free(image); free(dtb); return 1; }
		}
		free(image); free(dtb);
		printf("PASS: B10LINUX-v1 Image=%llu memory=%llu DTB=%llu; no device writes\n",
		       (unsigned long long)h.kernel_bytes,(unsigned long long)h.kernel_memory,(unsigned long long)h.dtb_bytes);
		return 0;
	}
	fputs("Usage: b10-loader --verify BOOT | --extract BOOT NEW_DIRECTORY | --boot (PID1 only)\n",stderr);
	return 2;
#endif
}
