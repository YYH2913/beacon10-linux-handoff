// SPDX-License-Identifier: GPL-2.0-only
/* Explicit commit client for a RAM-only diagnostic, never invoked by init. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <unistd.h>
#include "boot-format.h"
int main(int argc,char **argv)
{
	struct b10_status status; struct statfs fs; char init[128],line[2048],type[128],dev[256],path[256];
	uint64_t confirm=B10_EXECUTE_CONFIRM; ssize_t n; int fd; FILE *f;
	if(argc!=3 || strcmp(argv[1],"--confirm") || strcmp(argv[2],"RAM-KERNEL-HANDOFF-DISCONNECTS-SSH") || geteuid()) return 2;
	n=readlink("/proc/1/exe",init,sizeof(init)-1); if(n<0) return 1; init[n]=0;
	if(strcmp(init,"/sbin/upgraded") || statfs("/",&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) {
		fputs("Refusing jump outside the isolated RAM maintenance root.\n",stderr); return 1;
	}
	f=fopen("/proc/mounts","r"); if(!f) return 1;
	while(fgets(line,sizeof(line),f)) {
		if(sscanf(line,"%255s %255s %127s",dev,path,type)!=3 || !strcmp(type,"ext4") || !strcmp(type,"squashfs") ||
		   !strcmp(type,"overlay") || !strcmp(type,"overlayfs") || !strncmp(dev,"/dev/mmc",8) || !strncmp(dev,"/dev/loop",9)) {
			fclose(f); fputs("Refusing jump with a mounted disk filesystem.\n",stderr); return 1;
		}
	}
	fclose(f);
	fd=open("/dev/beacon10-handoff",O_RDWR|O_CLOEXEC|O_NOFOLLOW); if(fd<0) { perror("control open"); return 1; }
	if(ioctl(fd,B10_IOCTL_STATUS,&status) || status.version!=1 || !status.ready) { close(fd); return 1; }
	puts("Committing RAM kernel handoff; device shutdown starts now."); fflush(stdout); sync();
	if(ioctl(fd,B10_IOCTL_EXECUTE,&confirm)) perror("handoff ioctl");
	close(fd); return 1;
}
