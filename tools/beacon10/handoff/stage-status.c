// SPDX-License-Identifier: GPL-2.0-only
/* Status-only test client: deliberately contains no EXECUTE ioctl. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "boot-format.h"
int main(int argc,char **argv)
{
	struct b10_status s; unsigned maj,min; FILE *f;
	const char *node="/dev/beacon10-handoff"; int fd,ret; struct stat st;
	if(argc==4 && !strcmp(argv[1],"--load")) {
		fd=open(argv[2],O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(fd<0) return 1;
		ret=(int)syscall(SYS_finit_module,fd,argv[3],0); close(fd);
		if(ret) { perror("finit_module"); return 1; }
	} else if(argc!=1) return 2;
	f=fopen("/sys/class/misc/beacon10-handoff/dev","r"); if(!f) { perror("status sysfs"); return 1; }
	ret=fscanf(f,"%u:%u",&maj,&min); fclose(f); if(ret!=2) { fputs("Invalid sysfs dev\n",stderr); return 1; }
	if(lstat(node,&st)) {
		if(errno!=ENOENT || mknod(node,S_IFCHR|0600,makedev(maj,min))) { perror("status mknod"); return 1; }
	} else if(!S_ISCHR(st.st_mode) || st.st_rdev!=makedev(maj,min)) return 1;
	fd=open(node,O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(fd<0) { perror("status open"); return 1; }
	ret=ioctl(fd,B10_IOCTL_STATUS,&s); close(fd);
	if(ret) { perror("status ioctl"); return 1; }
	if(s.version!=1 || !s.ready) { fprintf(stderr,"Status invalid version=%u ready=%u\n",s.version,s.ready); return 1; }
	printf("STAGED: Image=%llu memory=%llu DTB=%llu pages=%llu; status ioctl only\n",
	       (unsigned long long)s.image_bytes,(unsigned long long)s.image_memory,
	       (unsigned long long)s.dtb_bytes,(unsigned long long)s.staging_pages);
	return 0;
}
