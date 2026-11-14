// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <mntent.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mounts.h"
int b10_drain_old_mounts(void (*tick)(void))
{
	unsigned count=0,round;
	if(mkdir("/drain",0700) && errno!=EEXIST) return -errno;
	/* An overlay's upper/work dirs keep the old /tmp mount referenced.
	 * Move all old submounts out first, then unmount the overlay root, then
	 * drain the moved mounts normally. No lazy detach leaves dirty ext4 live.
	 */
	for(;;) {
		FILE *f=setmntent("/proc/mounts","r"); struct mntent *m; struct stat st;
		char deepest[4096]={0},target[64]; int fd;
		if(!f) return -errno;
		while((m=getmntent(f)))
			if(!strncmp(m->mnt_dir,"/oldroot/",9) && strlen(m->mnt_dir)>strlen(deepest) && strlen(m->mnt_dir)<sizeof(deepest))
				strcpy(deepest,m->mnt_dir);
		endmntent(f);
		if(!deepest[0]) break;
		if(++count>256 || stat(deepest,&st)) return -EINVAL;
		snprintf(target,sizeof(target),"/drain/mount-%u",count);
		if(S_ISDIR(st.st_mode)) { if(mkdir(target,0700)) return -errno; }
		else { fd=open(target,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600); if(fd<0) return -errno; close(fd); }
		if(tick) tick();
		if(mount(deepest,target,NULL,MS_MOVE,NULL)) return -errno;
	}
	for(round=0;umount("/oldroot");round++) {
		if(errno!=EBUSY || round>=20) return -errno;
		/* Killed stock tasks can still be completing buffered IO/exit.
		 * Retry normal unmount for a bounded time; never lazy detach it.
		 */
		if(tick) tick();
		sync(); sleep(1);
	}
	for(round=0;round<257;round++) {
		FILE *f=setmntent("/proc/mounts","r"); struct mntent *m;
		unsigned present=0,progress=0;
		if(!f) return -errno;
		while((m=getmntent(f))) {
			if(strncmp(m->mnt_dir,"/drain/",7)) continue;
			present++;
			if(tick) tick();
			if(!umount(m->mnt_dir)) progress++;
			else if(errno!=EBUSY) { int ret=-errno; endmntent(f); return ret; }
		}
		endmntent(f);
		if(!present) break;
		if(!progress) return -EBUSY;
	}
	for(count=0;count<16;count++) {
		char path[64]; int fd;
		snprintf(path,sizeof(path),"/dev/loop%u",count);
		fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0) continue;
		if(ioctl(fd,LOOP_CLR_FD,0) && errno!=ENXIO) { int ret=-errno; close(fd); return ret; }
		close(fd);
	}
	return 0;
}
