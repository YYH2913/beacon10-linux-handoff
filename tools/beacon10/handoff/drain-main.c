// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <linux/magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/statfs.h>
#include <unistd.h>
#include "mounts.h"
int main(void)
{
	struct statfs fs; char init[128]; ssize_t n; int ret;
	if(geteuid() || statfs("/",&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) return 2;
	n=readlink("/proc/1/exe",init,sizeof(init)-1); if(n<0) return 2;init[n]=0;
	if(strcmp(init,"/sbin/upgraded")) return 2;
	sync(); ret=b10_drain_old_mounts(NULL);
	if(ret) fprintf(stderr,"Old mount drain stopped: %d\n",ret);
	else puts("PASS: old overlay and dependent mounts fully unmounted; loop mappings detached");
	return ret?1:0;
}
