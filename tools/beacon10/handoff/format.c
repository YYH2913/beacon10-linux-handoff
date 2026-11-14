// SPDX-License-Identifier: GPL-2.0-only
#include "format.h"
#include "sha256.h"
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#include "storage-layout.h"
#endif
static B10_U32 be32(const unsigned char *p)
{ return (B10_U32)p[0]<<24 | (B10_U32)p[1]<<16 | (B10_U32)p[2]<<8 | p[3]; }
static B10_U64 be64(const unsigned char *p)
{ return (B10_U64)be32(p)<<32 | be32(p+4); }
static B10_U64 le64(const unsigned char *p)
{
	B10_U64 n=0; unsigned i;
	for (i=0;i<8;i++) n|=(B10_U64)p[i]<<(8*i);
	return n;
}
static int overlap(B10_U64 a, B10_U64 n, B10_U64 b, B10_U64 m)
{ return !n || a+n<a || !m || b+m<b || (a<b+m && b<a+n); }
int b10_image_check(const void *data, size_t size, B10_U64 *memory)
{
	const unsigned char *p=data;
	B10_U64 offset, bytes, flags;
	if (size<64 || size>B10_KERNEL_FILE_MAX || memcmp(p+56,"ARMd",4)) return -ENOEXEC;
	offset=le64(p+8); bytes=le64(p+16); flags=le64(p+24);
	if (bytes<size || bytes>B10_KERNEL_MEMORY_MAX || flags&1 || offset>B10_KERNEL_LOAD ||
	    (B10_KERNEL_LOAD-offset)%(2U<<20)) return -ENOEXEC;
	*memory=bytes;
	return 0;
}
static int has_string(const unsigned char *p, size_t n, const char *wanted)
{
	size_t i=0, w=strlen(wanted);
	while (i<n) {
		const unsigned char *end=memchr(p+i,0,n-i);
		size_t len;
		if (!end) return 0;
		len=(size_t)(end-(p+i));
		if (len==w && !memcmp(p+i,wanted,w)) return 1;
		i+=len+1;
	}
	return 0;
}
static int args_check(const unsigned char *p, size_t n, int persistent)
{
	size_t i=0; unsigned root=0, marker=0;
#ifndef __KERNEL__
	unsigned storage=0;
#endif
	if (!n || p[n-1] || memchr(p,0,n-1)) return -EINVAL;
	while (i<n-1) {
		size_t end=i;
		while (end<n-1 && p[end]!=' ') end++;
		if (end-i>=5 && !memcmp(p+i,"root=",5)) {
			if (end-i!=strlen("root=/dev/mmcblk0p30") ||
			    memcmp(p+i,"root=/dev/mmcblk0p30",end-i)) return -EINVAL;
			root++;
		}
		if (end-i==strlen("beacon10.handoff=" B10_LAYOUT) &&
		    !memcmp(p+i,"beacon10.handoff=" B10_LAYOUT,end-i)) marker++;
#ifndef __KERNEL__
		if (persistent && end-i>=17 && !memcmp(p+i,"beacon10.storage=",17)) {
			if(end-i!=strlen("beacon10.storage=" B10_STORAGE_LAYOUT) ||
			   memcmp(p+i,"beacon10.storage=" B10_STORAGE_LAYOUT,end-i)) return -EINVAL;
			storage++;
		}
#endif
		if ((end-i>=5 && !memcmp(p+i,"init=",5)) ||
		    (end-i>=7 && !memcmp(p+i,"rdinit=",7))) return -EINVAL;
		if (persistent &&
		    ((end-i>=18 && !memcmp(p+i,"b10_diag_deadline=",18)) ||
		     (end-i>=18 && !memcmp(p+i,"sdhci.debug_quirks",18)))) return -EPERM;
		i=end+1;
	}
#ifndef __KERNEL__
	if(persistent && storage!=1) return -EINVAL;
#endif
	return root==1 && marker==1 ? 0 : -EINVAL;
}
static int reservation(B10_U64 start, B10_U64 size, B10_U64 memory)
{
	return overlap(start,size,B10_KERNEL_LOAD,memory) ||
	       overlap(start,size,B10_DTB_LOAD,B10_DTB_MAX) ? -EINVAL : 0;
}
static int dtb_check(const void *data, size_t size, B10_U64 memory, int persistent)
{
	const unsigned char *b=data;
	size_t pos, end, strings, strings_size, reserve;
	unsigned depth=0, compatible=0, args=0, soc=0, major=0, minor=0, memory_seen=0;
	int chosen=0, reserved=0, memnode=0, finished=0;
	if (size<40 || size>B10_DTB_MAX || be32(b)!=0xd00dfeed || be32(b+4)!=size ||
	    be32(b+20)!=17 || be32(b+24)>17) return -ENOEXEC;
	pos=be32(b+8); strings=be32(b+12); reserve=be32(b+16);
	strings_size=be32(b+32); end=pos+be32(b+36);
	if (pos<40 || pos%4 || end<pos || end>size || strings<end || strings>size ||
	    strings_size>size-strings || reserve<40 || reserve%8 || reserve>=pos) return -EINVAL;
	while (reserve+16<=pos) {
		B10_U64 a=be64(b+reserve), n=be64(b+reserve+8);
		reserve+=16;
		if (!a && !n) break;
		if (reservation(a,n,memory)) return -EINVAL;
	}
	if (reserve>pos || reserve<16 || be64(b+reserve-16) || be64(b+reserve-8)) return -EINVAL;
	while (pos+4<=end) {
		B10_U32 token=be32(b+pos); pos+=4;
		if (token==1) {
			const unsigned char *nul=memchr(b+pos,0,end-pos);
			size_t n;
			if (!nul || depth>=32) return -EINVAL;
			n=(size_t)(nul-(b+pos));
			if (!depth && n) return -EINVAL;
			if (depth==1) {
				chosen=n==6 && !memcmp(b+pos,"chosen",6);
				reserved=n==15 && !memcmp(b+pos,"reserved-memory",15);
				memnode=(n==6 && !memcmp(b+pos,"memory",6)) ||
					(n==15 && !memcmp(b+pos,"memory@40000000",15));
			}
			pos=(pos+n+4)&~(size_t)3; depth++;
		} else if (token==2) {
			if (!depth) return -EINVAL;
			depth--;
			if (depth==1) chosen=reserved=memnode=0;
		} else if (token==3) {
			B10_U32 len, off; const char *name; const unsigned char *v;
			if (!depth || pos+8>end) return -EINVAL;
			len=be32(b+pos); off=be32(b+pos+4); pos+=8;
			if (off>=strings_size || !memchr(b+strings+off,0,strings_size-off) || len>end-pos)
				return -EINVAL;
			name=(const char *)b+strings+off; v=b+pos;
			if (persistent && !strncmp(name,"nokia,ram-",10)) return -EPERM;
			if (depth==1 && !strcmp(name,"compatible")) {
				if (++compatible!=1 || !has_string(v,len,"nokia,beacon10")) return -EINVAL;
			}
			if (depth==1 && (!strcmp(name,"cpu_type") || !strcmp(name,"soc_version_major") ||
			    !strcmp(name,"soc_version_minor"))) {
				unsigned *count=!strcmp(name,"cpu_type") ? &soc : !strcmp(name,"soc_version_major") ? &major : &minor;
				const char *wanted=count==&soc ? "\x02\x02\0\0" : "\x01\0\0\0";
				if (++*count!=1 || len!=4 || memcmp(v,wanted,4)) return -EINVAL;
			}
			if (depth==2 && chosen && !strcmp(name,"bootargs")) {
				if (++args!=1 || args_check(v,len,persistent)) return -EINVAL;
			}
			if (depth==2 && chosen && (!strcmp(name,"linux,initrd-start") || !strcmp(name,"linux,initrd-end")))
				return -EINVAL;
			if (depth==2 && memnode && !strcmp(name,"reg")) {
				if (++memory_seen!=1 || len!=16 || be64(v)!=0x40000000 || be64(v+8)!=0x40000000)
					return -EINVAL;
			}
			if (depth==3 && reserved && !strcmp(name,"reg")) {
				unsigned i;
				if (!len || len%16) return -EINVAL;
				for (i=0;i<len;i+=16) if (reservation(be64(v+i),be64(v+i+8),memory)) return -EINVAL;
			}
			pos=(pos+len+3)&~(size_t)3;
		} else if (token==9) {
			if (depth) return -EINVAL;
			finished=1; break;
		} else if (token!=4) return -EINVAL;
		if (pos>end) return -EINVAL;
	}
	return finished && compatible==1 && args==1 && soc==1 && major==1 && minor==1 && memory_seen==1 ? 0 : -EINVAL;
}
int b10_dtb_check(const void *data, size_t size, B10_U64 memory)
{
	return dtb_check(data,size,memory,0);
}
#ifndef __KERNEL__
int b10_dtb_check_persistent(const void *data, size_t size, B10_U64 memory)
{
	return dtb_check(data,size,memory,1);
}
#endif
int b10_header_check(struct b10_boot_header *h)
{
	unsigned char expected[32], actual[32];
	size_t i;
	if (sizeof(*h)!=B10_HEADER_SIZE || memcmp(h->magic,B10_BOOT_MAGIC,8) ||
	    h->version!=B10_BOOT_VERSION || h->header_size!=B10_HEADER_SIZE ||
	    memcmp(h->layout,B10_LAYOUT,sizeof(B10_LAYOUT)) ||
	    h->kernel_load!=B10_KERNEL_LOAD || h->dtb_load!=B10_DTB_LOAD ||
	    h->kernel_bytes<64 || h->kernel_bytes>B10_KERNEL_FILE_MAX ||
	    h->kernel_memory<h->kernel_bytes || h->kernel_memory>B10_KERNEL_MEMORY_MAX ||
	    h->dtb_bytes<40 || h->dtb_bytes>B10_DTB_MAX || h->kernel_offset!=B10_HEADER_SIZE ||
	    h->dtb_offset!=((B10_HEADER_SIZE+h->kernel_bytes+4095)&~4095ULL) ||
	    h->total_bytes!=h->dtb_offset+h->dtb_bytes || h->total_bytes>B10_KERNEL_FILE_MAX)
		return -EINVAL;
	for (i=sizeof(B10_LAYOUT);i<sizeof(h->layout);i++) if (h->layout[i]) return -EINVAL;
	for (i=0;i<sizeof(h->reserved);i++) if (h->reserved[i]) return -EINVAL;
	memcpy(expected,h->header_sha256,32); memset(h->header_sha256,0,32);
	b10_digest(h,sizeof(*h),actual); memcpy(h->header_sha256,expected,32);
	return memcmp(actual,expected,32) ? -EBADMSG : 0;
}
int b10_dtb_set_sequence(void *data,size_t size,B10_U64 sequence)
{
	unsigned char *b=data,*found=NULL;
	size_t pos,end,strings,strings_size;
	unsigned depth=0; int chosen=0;
	if(!sequence || size<40 || be32(b)!=0xd00dfeed || be32(b+4)!=size) return -EINVAL;
	pos=be32(b+8); end=pos+be32(b+36); strings=be32(b+12); strings_size=be32(b+32);
	if(pos<40 || end<pos || end>size || strings<end || strings>size || strings_size>size-strings) return -EINVAL;
	while(pos+4<=end) {
		B10_U32 token=be32(b+pos); pos+=4;
		if(token==1) {
			unsigned char *nul=memchr(b+pos,0,end-pos); size_t n;
			if(!nul || depth>=32) return -EINVAL;
			n=(size_t)(nul-(b+pos));
			if(depth==1) chosen=n==6 && !memcmp(b+pos,"chosen",6);
			pos=(pos+n+4)&~(size_t)3; depth++;
		} else if(token==2) {
			if(!depth) return -EINVAL;
			depth--; if(depth==1) chosen=0;
		} else if(token==3) {
			B10_U32 len,off;
			if(!depth || pos+8>end) return -EINVAL;
			len=be32(b+pos); off=be32(b+pos+4); pos+=8;
			if(off>=strings_size || !memchr(b+strings+off,0,strings_size-off) || len>end-pos) return -EINVAL;
			if(depth==2 && chosen && !strcmp((char *)b+strings+off,"beacon10,boot-seq")) {
				if(found || len!=8) return -EINVAL;
				found=b+pos;
			}
			pos=(pos+len+3)&~(size_t)3;
		} else if(token==9) {
			unsigned i;
			if(depth || !found) return -EINVAL;
			for(i=0;i<8;i++) found[7-i]=(unsigned char)(sequence>>(8*i));
			return 0;
		} else if(token!=4) return -EINVAL;
		if(pos>end) return -EINVAL;
	}
	return -EINVAL;
}
