// SPDX-License-Identifier: GPL-2.0-only
/* Replaces procd as PID1 through its existing system.sysupgrade interface.
 * This binary and all dependencies are static and prepared on a tmpfs mount.
 * It pivots out of the stock root, detaches old mounts, then runs an explicit
 * maintenance command. It never touches the eMMC itself.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/loop.h>
#include <linux/watchdog.h>
#include <mntent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "mounts.h"

static int watchdog_fd=-1;
static int log_fd=-1;
static void stage_log(const char *message)
{
	char line[256]; int n=snprintf(line,sizeof(line),"<3>beacon10-ram: %s\n",message);
	if(log_fd>=0 && n>0 && (size_t)n<sizeof(line)) { ssize_t done=write(log_fd,line,(size_t)n); (void)done; }
}
static void feed(void)
{ if(watchdog_fd>=0) { char b=0; ssize_t n=write(watchdog_fd,&b,1); if(n!=1) watchdog_fd=-1; } }
static int child(char *const args[])
{
	pid_t pid=fork(); int status;
	if(pid<0) return -1;
	if(!pid) { if(watchdog_fd>=0) close(watchdog_fd); execv(args[0],args); _exit(127); }
	for(;;) {
		pid_t n=waitpid(pid,&status,WNOHANG);
		if(n==pid) return WIFEXITED(status)?WEXITSTATUS(status):128;
		if(n<0 && errno!=EINTR) return -1;
		feed(); sleep(1);
	}
}
static void rescue(void)
{
	char *network[]={"/sbin/beacon10-recovery",NULL},*shell[]={"/bin/sh",NULL};
	(void)child(network);
	for(;;) { (void)child(shell); feed(); sleep(1); }
}
static void close_inherited(void)
{
	DIR *d=opendir("/proc/self/fd"); struct dirent *e;
	if(!d) return;
	while((e=readdir(d))) {
		int fd;
		if(!*e->d_name || strspn(e->d_name,"0123456789")!=strlen(e->d_name)) continue;
		fd=atoi(e->d_name);
		if(fd>2 && fd!=watchdog_fd && fd!=log_fd && fd!=dirfd(d)) close(fd);
	}
	closedir(d);
}
static int rehome_watchdog(void)
{
	struct stat st; int old=watchdog_fd;
	if(old<0) return 0;
	if(fstat(old,&st) || !S_ISCHR(st.st_mode)) return -1;
	/* Retail procd opens /watchdog on the overlay rather than /dev. That
	 * open file pins the old mount. Close without the magic 'V' (the core
	 * keeps the watchdog running), reopen via the moved tmpfs /dev and pet
	 * immediately. Never disable watchdog protection during installation.
	 */
	if(mknod("/dev/beacon10-watchdog",S_IFCHR|0600,st.st_rdev) && errno!=EEXIST) return -1;
	feed(); close(old); watchdog_fd=-1;
	watchdog_fd=open("/dev/beacon10-watchdog",O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
	if(watchdog_fd<0) return -1;
	feed(); stage_log("watchdog reopened on tmpfs /dev; old overlay fd released");
	return 0;
}
static int signal_userspace(int sig)
{
	DIR *d=opendir("/proc"); struct dirent *e; int result=0;
	if(!d) return -1;
	while((e=readdir(d))) {
		char path[64],line[4096],*end,state;
		long ppid,pgrp,session,tty,tpgid; unsigned long flags; long pid; FILE *f;
		if(!*e->d_name || strspn(e->d_name,"0123456789")!=strlen(e->d_name)) continue;
		pid=strtol(e->d_name,NULL,10); if(pid<=1) continue;
		snprintf(path,sizeof(path),"/proc/%ld/stat",pid); f=fopen(path,"r"); if(!f) continue;
		if(!fgets(line,sizeof(line),f)) { fclose(f); continue; } fclose(f);
		end=strrchr(line,')');
		if(!end || sscanf(end+1," %c %ld %ld %ld %ld %ld %lu",&state,&ppid,&pgrp,&session,&tty,&tpgid,&flags)!=7) { result=-1; break; }
		/* Some vendor kernel threads explicitly allow SIGKILL. kill(-1)
		 * can terminate ECM's worker and make later cleanup use freed state.
		 * PF_KTHREAD is the stable /proc stat flag, not a guessed task layout.
		 */
		if(flags&0x00200000UL) continue;
		if(kill((pid_t)pid,sig) && errno!=ESRCH) { result=-1; break; }
	}
	closedir(d); return result;
}
static int pivot(void)
{
	int newroot=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	struct statfs fs;
	if(newroot<0 || fstatfs(newroot,&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) return -1;
	/* procd called chroot(prefix), while its cwd remains the original root.
	 * Match upgraded's escape, then use the saved new-root fd for pivot_root.
	 */
	if(chroot(".") || fchdir(newroot)) { close(newroot); return -1; }
	close(newroot);
	stage_log("escaped stock chroot; moving proc/sys/dev");
	if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)) return -1;
	if(mount("/proc","proc",NULL,MS_MOVE,NULL) || mount("/sys","sys",NULL,MS_MOVE,NULL) ||
	   mount("/dev","dev",NULL,MS_MOVE,NULL) || syscall(SYS_pivot_root,".","oldroot") || chdir("/")) return -1;
	stage_log("pivoted to tmpfs; closing inherited descriptors");
	close_inherited();
	if(rehome_watchdog()) return -1;
	/* Kill old userspace after pivot. No stock process may keep a block fd
	 * alive through the migration. Unmount normally: a lazy detach alone
	 * would leave dirty ext4/loop writes racing the physical disk writer.
	 */
	/* Retail daemons have SIGTERM cleanup which spawns reboot(2). Freeze
	 * them before a fatal signal instead. Only userspace processes are
	 * targeted; vendor kthreads can accept fatal signals and must be excluded.
	 * sync + normal unmount below still drains storage.
	 */
	stage_log("stopping old userspace to suppress OEM reboot-on-exit hooks");
	if(signal_userspace(SIGSTOP)) return -1;
	feed();
	stage_log("sending SIGKILL to stopped old userspace");
	if(signal_userspace(SIGKILL)) return -1;
	feed(); sleep(1);
	sync();
	if(b10_drain_old_mounts(feed)) return -1;
	stage_log("old filesystem tree fully unmounted");
	if(statfs("/",&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) return -1;
	return 0;
}
int main(int argc,char **argv)
{
	const char *wdt=getenv("WDTFD");
	char *install[]={"/bin/b10-install","--install","/install.bin","--confirm",
	                 "ERASE-STOCK-ROOTS-AND-USER-DATA",NULL};
	int ret;
	(void)argv;
	if(getpid()!=1 || argc!=3) return 2;
	/* cwd is still the stock root at the procd exec boundary. */
	log_fd=open("dev/kmsg",O_WRONLY|O_CLOEXEC);
	stage_log("static RAM PID1 started");
	if(wdt && *wdt && strspn(wdt,"0123456789")==strlen(wdt)) watchdog_fd=atoi(wdt);
	close_inherited();
	feed();
	if(pivot()) { stage_log("RAM root isolation failed; entering recovery without storage writes"); fputs("Beacon10: RAM root isolation failed; storage not opened.\n",stderr); rescue(); }
	if(access("/INSTALL-CONFIRMED",F_OK)) {
		stage_log("maintenance mode: starting SSH recovery; installer not requested");
		puts("Beacon10: RAM maintenance mode; no installation requested."); rescue();
	}
	ret=child(install);
	if(ret) { fprintf(stderr,"Beacon10: install stopped (%d); staying in RAM recovery.\n",ret); rescue(); }
	puts("Beacon10: automatic relocation and installation verified; rebooting into stock bootstrap.");
	sync(); feed(); reboot(RB_AUTOBOOT); rescue();
	return 1;
}
