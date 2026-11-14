// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "storage.h"
#include "layout-generated.h"

uint32_t b10_crc32(const void *data, size_t bytes)
{
	const unsigned char *p=data;
	uint32_t c=~0U;
	unsigned i;
	while (bytes--) { c^=*p++; for(i=0;i<8;i++) c=(c>>1)^(0xedb88320U & (0U-(c&1))); }
	return ~c;
}
static uint32_t u32(const unsigned char *p)
{ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static uint64_t u64(const unsigned char *p)
{ return u32(p) | (uint64_t)u32(p+4)<<32; }
static void put32(unsigned char *p,uint32_t n)
{ unsigned i; for(i=0;i<4;i++) p[i]=(unsigned char)(n>>(8*i)); }
int b10_read_at(int fd, void *data, size_t bytes, uint64_t offset)
{
	unsigned char *p=data;
	while (bytes) {
		ssize_t n=pread(fd,p,bytes,(off_t)offset);
		if (n<0 && errno==EINTR) continue;
		if (n<=0) return -EIO;
		p+=n; bytes-=(size_t)n; offset+=(size_t)n;
	}
	return 0;
}
int b10_write_verified(int fd, const void *data, size_t bytes, uint64_t offset)
{
	const unsigned char *p=data;
	unsigned char verify[4096];
	size_t done=0;
	while (done<bytes) {
		ssize_t n=pwrite(fd,p+done,bytes-done,(off_t)(offset+done));
		if (n<0 && errno==EINTR) continue;
		if (n<=0) return -EIO;
		done+=(size_t)n;
	}
	/* fsync on the whole eMMC user-area fd issues the block flush barrier.
	 * Any flush/readback error terminates the transaction, never blind retry.
	 */
	if (fsync(fd)) return -errno;
	for (done=0;done<bytes;) {
		size_t n=bytes-done<sizeof(verify) ? bytes-done : sizeof(verify);
		if (b10_read_at(fd,verify,n,offset+done) || memcmp(verify,p+done,n)) return -EIO;
		done+=n;
	}
	return 0;
}
static int gpt_header(const unsigned char *h,int backup,const unsigned char *table)
{
	unsigned char copy[512]; uint32_t crc;
	if (memcmp(h,"EFI PART",8) || u32(h+8)!=0x10000 || u32(h+12)!=92 ||
	    u64(h+24)!=(backup ? B10_SECTORS-1 : 1) || u64(h+32)!=(backup ? 1 : B10_SECTORS-1) ||
	    u64(h+40)!=34 || u64(h+48)!=B10_SECTORS-34 ||
	    u64(h+72)!=(backup ? B10_SECTORS-33 : 2) || u32(h+80)!=128 || u32(h+84)!=128 ||
	    u32(h+88)!=b10_crc32(table,16384)) return -EINVAL;
	memcpy(copy,h,sizeof(copy)); crc=u32(copy+16); memset(copy+16,0,4);
	return b10_crc32(copy,92)==crc ? 0 : -EBADMSG;
}
int b10_layout_check(int fd,unsigned char disk_guid[16])
{
	unsigned char *data=malloc(34*512+33*512);
	const unsigned char *h,*t,*bh,*bt;
	unsigned i,j;
	int ret=-EINVAL;
	if (!data) return -ENOMEM;
	if (b10_read_at(fd,data,34*512,0) || b10_read_at(fd,data+34*512,33*512,(B10_SECTORS-33)*512)) goto out;
	h=data+512; t=data+1024; bt=data+34*512; bh=bt+16384;
	if (gpt_header(h,0,t) || gpt_header(bh,1,bt) || memcmp(t,bt,16384) || memcmp(h+56,bh+56,16)) goto out;
	for (i=0;i<128;i++) {
		const unsigned char *e=t+128*i;
		if (i>=37) {
			for (j=0;j<128;j++) if(e[j]) goto out;
			continue;
		}
		if (!memcmp(e,(unsigned char[16]){0},16) || !memcmp(e+16,(unsigned char[16]){0},16) ||
		    u64(e+32)!=b10_parts[i].start || u64(e+40)!=b10_parts[i].start+b10_parts[i].sectors-1)
			goto out;
		for (j=0;j<36;j++) {
			unsigned char c=j<strlen(b10_parts[i].name) ? (unsigned char)b10_parts[i].name[j] : 0;
			if (e[56+2*j]!=c || e[57+2*j]) goto out;
		}
		for (j=0;j<i;j++) if (!memcmp(e+16,t+128*j+16,16)) goto out;
	}
	memcpy(disk_guid,h+56,16); ret=0;
out:
	free(data); return ret;
}
static int valid_state(struct b10_state *s,const unsigned char guid[16])
{
	uint32_t crc=s->crc; unsigned i;
	if (sizeof(*s)!=4096 || memcmp(s->magic,"B10STATE",8) || s->version!=1 || s->bytes!=4096 ||
	    !s->sequence || s->sequence>B10_STATE_MAX_SEQUENCE || memcmp(s->disk_guid,guid,16) ||
	    (s->flags!=B10_STATE_READY && s->flags!=B10_STATE_INSTALLING)) return 0;
	for (i=0;i<sizeof(s->reserved);i++) if(s->reserved[i]) return 0;
	s->crc=0; i=b10_crc32(s,sizeof(*s)); s->crc=crc;
	return i==crc;
}
int b10_state_read(int fd,const unsigned char guid[16],struct b10_state *s)
{
	struct b10_state a,b; int av,bv;
	if (b10_read_at(fd,&a,sizeof(a),(B10_CAPSULE_START+B10_STATE_A)*512) ||
	    b10_read_at(fd,&b,sizeof(b),(B10_CAPSULE_START+B10_STATE_B)*512)) return -EIO;
	av=valid_state(&a,guid); bv=valid_state(&b,guid);
	if (!av && !bv) return -EBADMSG;
	if (av && bv && a.sequence==b.sequence && memcmp(&a,&b,sizeof(a))) return -EBADMSG;
	*s=av && (!bv || a.sequence>=b.sequence) ? a : b;
	return 0;
}
int b10_state_write(int fd,const struct b10_state *state)
{
	struct b10_state s=*state,old,a;
	uint64_t slot;
	int ret;
	s.crc=0; s.crc=b10_crc32(&s,sizeof(s));
	/* A verified write is not a valid publication if our own reader rejects
	 * its contents. Validate the complete new record before touching a slot.
	 */
	if(!valid_state(&s,state->disk_guid)) return -EINVAL;
	ret=b10_state_read(fd,state->disk_guid,&old);
	if (ret || state->sequence!=old.sequence+1) return -EINVAL;
	if(b10_read_at(fd,&a,sizeof(a),(B10_CAPSULE_START+B10_STATE_A)*512)) return -EIO;
	/* Always replace the other slot, even if the only surviving record was
	 * seeded in a slot whose number does not match sequence parity.
	 */
	slot=valid_state(&a,state->disk_guid) && !memcmp(&a,&old,sizeof(a)) ? B10_STATE_B : B10_STATE_A;
	return b10_write_verified(fd,&s,sizeof(s),(B10_CAPSULE_START+slot)*512);
}
static int env_zero(unsigned char *p)
{
	const size_t size=262144;
	size_t at=4, match=0, length=0, body_end=0;
	unsigned bootcmd=0;
	if (u32(p)!=b10_crc32(p+4,size-4)) return -EBADMSG;
	while (at<size) {
		unsigned char *end=memchr(p+at,0,size-at), *eq;
		size_t n,prev;
		if (!end) return -EINVAL;
		n=(size_t)(end-(p+at));
		if (!n) { body_end=at+1; break; }
		eq=memchr(p+at,'=',n);
		if (!eq || eq==p+at) return -EINVAL;
		if ((size_t)(eq-(p+at))==7 && !memcmp(p+at,"bootcmd",7)) {
			if(n!=15 || memcmp(p+at,"bootcmd=bootipq",15)) return -EINVAL;
			bootcmd++;
		}
		/* Reject duplicate keys, including keys unrelated to this write. */
		for (prev=4;prev<at;prev+=strlen((char *)p+prev)+1) {
			size_t key=(size_t)(eq-(p+at));
			if (!memcmp(p+prev,p+at,key) && p[prev+key]=='=') return -EINVAL;
		}
		if ((size_t)(eq-(p+at))==15 && !memcmp(p+at,"boot_fail_count",15)) {
			size_t j;
			if (match || end==eq+1) return -EINVAL;
			for(j=(size_t)(eq-p)+1;j<(size_t)(end-p);j++) if(p[j]<'0'||p[j]>'9') return -EINVAL;
			match=(size_t)(eq-p)+1; length=(size_t)(end-(eq+1));
		}
		at+=n+1;
	}
	if (!body_end || !match || bootcmd!=1) return -EINVAL;
	memmove(p+match+1,p+match+length,body_end-(match+length));
	p[match]='0';
	memset(p+body_end-(length-1),0,length-1);
	put32(p,b10_crc32(p+4,size-4));
	return 0;
}
int b10_env_check(const unsigned char *env)
{
	unsigned char *copy=malloc(262144); int ret;
	if(!copy) return -ENOMEM;
	memcpy(copy,env,262144); ret=env_zero(copy); free(copy); return ret;
}
int b10_ack_env(int fd)
{
	unsigned char *env=malloc(2*262144);
	unsigned char guid[16];
	int ret;
	if (!env) return -ENOMEM;
	ret=b10_layout_check(fd,guid);
	if (!ret) ret=b10_read_at(fd,env,262144,18466ULL*512);
	if (!ret) ret=b10_read_at(fd,env+262144,262144,125474ULL*512);
	if (!ret) ret=env_zero(env);
	if (!ret) ret=env_zero(env+262144);
	if (!ret) ret=b10_write_verified(fd,env+262144,262144,125474ULL*512);
	if (!ret) ret=b10_write_verified(fd,env,262144,18466ULL*512);
	free(env); return ret;
}
