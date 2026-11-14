// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "install-format.h"
#include "storage.h"

/* Only regular-file transaction tests and read-only device preflight are
 * enabled while the persistent boot/peripheral validation is incomplete.
 * This is deliberately not a command-line or environment override.
 */
enum { B10_LIVE_INSTALL_VALIDATED = 0 };

static int cid_parse(const char *text,unsigned char out[16])
{
	unsigned i;
	if(strcspn(text,"\r\n")!=32) return -EINVAL;
	for(i=0;i<32;i++) if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')||(text[i]>='A'&&text[i]<='F'))) return -EINVAL;
	for(i=0;i<16;i++) { unsigned v; if(sscanf(text+2*i,"%2x",&v)!=1) return -EINVAL; out[i]=(unsigned char)v; }
	return 0;
}
static int ram_only(void)
{
	struct statfs fs; struct utsname uts;
	char line[2048],dev[256],mount[256],type[128]; FILE *f;
	if(geteuid() || uname(&uts) || strcmp(uts.release,"5.4.164") ||
	   statfs("/",&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) return -EPERM;
	f=fopen("/sys/firmware/devicetree/base/compatible","r"); if(!f) return -ENODEV;
	{ const char *compatible="qcom,ipq9574-ap-al02-c2"; size_t n=fread(line,1,sizeof(line),f); fclose(f);
	  if(!memmem(line,n,compatible,strlen(compatible)+1)) return -ENODEV; }
	f=fopen("/proc/mounts","r"); if(!f) return -errno;
	while(fgets(line,sizeof(line),f)) {
		if(sscanf(line,"%255s %255s %127s",dev,mount,type)!=3) { fclose(f); return -EINVAL; }
		if(!strcmp(type,"squashfs") || !strcmp(type,"ext4") || !strcmp(type,"overlay") ||
		   !strcmp(type,"overlayfs") || !strncmp(dev,"/dev/mmc",8) || !strncmp(dev,"/dev/loop",9)) {
			fclose(f); return -EBUSY;
		}
	}
	fclose(f); return 0;
}
int main(int argc,char **argv)
{
	unsigned char cid[16]; struct stat st; int fd=-1,bundle=-1,ret=-EINVAL,live=0,write=0;
	const char *disk,*input;
	uint64_t bytes=0;
	if(argc==6 && !strcmp(argv[1],"--image") && (!strcmp(argv[5],"--check") || !strcmp(argv[5],"--apply"))) {
		disk=argv[2]; input=argv[3]; write=!strcmp(argv[5],"--apply");
		if(cid_parse(argv[4],cid)) goto usage;
	} else if((argc==3 && !strcmp(argv[1],"--check-device")) ||
	          (argc==5 && !strcmp(argv[1],"--install") && !strcmp(argv[3],"--confirm") &&
	           !strcmp(argv[4],"ERASE-STOCK-ROOTS-AND-USER-DATA"))) {
		char text[40]; FILE *f;
		live=1; write=argc==5; disk="/dev/mmcblk0"; input=argv[2];
		if(write && !B10_LIVE_INSTALL_VALIDATED) {
			fputs("Beacon10 live installation disabled: hardware validation incomplete. No device opened.\n",stderr);
			return 1;
		}
		if(geteuid()) { ret=-EPERM; goto out; }
		if(write) { ret=ram_only(); if(ret) goto out; }
		f=fopen("/sys/class/block/mmcblk0/device/cid","r");
		if(!f) { ret=-errno; goto out; }
		if(!fgets(text,sizeof(text),f)) { fclose(f); ret=-EIO; goto out; }
		fclose(f); ret=cid_parse(text,cid); if(ret) goto out;
	} else goto usage;
	fd=open(disk,(write?O_RDWR:O_RDONLY)|O_CLOEXEC|O_NOFOLLOW|(live&&write?O_EXCL:0));
	if(fd<0) { ret=-errno; goto out; }
	if(fstat(fd,&st) || (live ? !S_ISBLK(st.st_mode) : !S_ISREG(st.st_mode))) { ret=-EPERM; goto out; }
	if(live) { if(ioctl(fd,BLKGETSIZE64,&bytes)) { ret=-errno; goto out; } }
	else bytes=st.st_size;
	if(bytes!=B10_SECTORS*512 || flock(fd,LOCK_EX|LOCK_NB)) { ret=-EBUSY; goto out; }
	bundle=open(input,O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(bundle<0) { ret=-errno; goto out; }
	if(live&&write) { struct statfs fs; if(fstatfs(bundle,&fs) || (unsigned long)fs.f_type!=TMPFS_MAGIC) { ret=-EPERM; goto out; } }
	ret=b10_install(fd,bundle,cid,write);
out:
	if(bundle>=0) close(bundle);
	if(fd>=0) close(fd);
	if(ret) { fprintf(stderr,"Beacon10 transaction refused/stopped: %d. Do not reboot blindly.\n",ret); return 1; }
	puts(write?"Beacon10: identity relocated, dual GPT/payload verified; READY committed. Reboot remains explicit.":
	           "Beacon10: install inputs validated; no writes performed.");
	return 0;
usage:
	fputs("Usage: b10-install --image REGULAR_FILE BUNDLE CID_HEX --check|--apply\n"
	      "       b10-install --check-device RAM_BUNDLE (read-only)\n"
	      "       b10-install --install RAM_BUNDLE --confirm ERASE-STOCK-ROOTS-AND-USER-DATA\n"
	      "Live mode requires a fully detached tmpfs root; never invoke from stock rootfs.\n",stderr);
	return 2;
}
