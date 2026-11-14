// SPDX-License-Identifier: GPL-2.0-only
/* The same transaction runs against regular model files and an offline eMMC.
 * Its caller supplies the live-device guards. No partition ioctl or reboot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "storage.h"
#include "sha256.h"
#include "format.h"
#include "install-format.h"
#include "layout-generated.h"
#include "factory-generated.h"

#define CAPS (B10_CAPSULE_START*512)
static uint32_t get32(const unsigned char *p)
{ return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t get64(const unsigned char *p)
{ return get32(p)|(uint64_t)get32(p+4)<<32; }
static void set32(unsigned char *p,uint32_t n)
{ unsigned i; for(i=0;i<4;i++) p[i]=(unsigned char)(n>>(8*i)); }
static void set64(unsigned char *p,uint64_t n)
{ set32(p,(uint32_t)n); set32(p+4,(uint32_t)(n>>32)); }
static int zero(const void *p,size_t n)
{ const unsigned char *b=p; while(n--) if(*b++) return 0; return 1; }
static uint64_t align4k(uint64_t n) { return (n+4095)&~4095ULL; }
static int hash_range(int fd,uint64_t off,uint64_t n,unsigned char digest[32])
{
	unsigned char data[65536]; struct b10_sha256 sha;
	b10_sha256_init(&sha);
	while(n) {
		size_t bytes=n<sizeof(data)?n:sizeof(data);
		if(b10_read_at(fd,data,bytes,off)) return -EIO;
		b10_sha256_update(&sha,data,bytes); n-=bytes; off+=bytes;
	}
	b10_sha256_final(&sha,digest); return 0;
}
static int expected_hash(int fd,uint64_t off,uint64_t bytes,const char *expected)
{
	unsigned char hash[32]; char hex[65]; unsigned i;
	static const char digits[]="0123456789abcdef";
	if(hash_range(fd,off,bytes,hash)) return -EIO;
	for(i=0;i<32;i++) { hex[2*i]=digits[hash[i]>>4]; hex[2*i+1]=digits[hash[i]&15]; }
	hex[64]=0; return strcmp(hex,expected)?-ENOEXEC:0;
}
static int stock_boot(int fd)
{
	const char *ap="8a11218e58def68f59b4d9c63c90adcf23b31716c825e1da4815e4aabfd5f1a8";
	const char *hl="73a16dff7f9a6414b4add8bd3d2cf72c3948f08c759f9f7de4052e5ad0810033";
	return expected_hash(fd,18978ULL*512,2097152,ap) || expected_hash(fd,23074ULL*512,2097152,ap) ||
	       expected_hash(fd,49698ULL*512,10485760,hl) || expected_hash(fd,70178ULL*512,10485760,hl) ? -ENOEXEC:0;
}
static int factory_gpt(const unsigned char *data)
{
	unsigned char h[512]; const unsigned char *t=data+1024;
	uint32_t count,crc; unsigned i,j;
	memcpy(h,data+512,512); count=get32(h+80); crc=get32(h+16); set32(h+16,0);
	if(memcmp(h,"EFI PART",8) || get32(h+8)!=0x10000 || get32(h+12)!=92 ||
	   b10_crc32(h,92)!=crc || get64(h+24)!=1 || get64(h+32)!=B10_SECTORS-1 ||
	   get64(h+40)!=34 || get64(h+48)!=B10_SECTORS-34 || get64(h+72)!=2 ||
	   (count!=36 && count!=128) || get32(h+84)!=128 ||
	   b10_crc32(t,count*128)!=get32(h+88)) return -EINVAL;
	for(i=0;i<count;i++) {
		const unsigned char *e=t+i*128;
		if(i>=35) { if(!zero(e,128)) return -EINVAL; continue; }
		if(zero(e,16) || zero(e+16,16) || get64(e+32)!=b10_factory[i].start ||
		   get64(e+40)!=b10_factory[i].start+b10_factory[i].sectors-1) return -EINVAL;
		for(j=0;j<36;j++) {
			unsigned char c=j<strlen(b10_factory[i].name)?b10_factory[i].name[j]:0;
			if(e[56+2*j]!=c || e[57+2*j]) return -EINVAL;
		}
		for(j=0;j<i;j++) if(!memcmp(e+16,t+j*128+16,16)) return -EINVAL;
	}
	return 0;
}
static void gpt_header(unsigned char *h,const unsigned char *t,int backup)
{
	set64(h+24,backup?B10_SECTORS-1:1); set64(h+32,backup?1:B10_SECTORS-1);
	set64(h+72,backup?B10_SECTORS-33:2); set32(h+80,128); set32(h+84,128);
	set32(h+88,b10_crc32(t,16384)); set32(h+16,0); set32(h+16,b10_crc32(h,92));
}
static void make_gpt(const unsigned char *old,unsigned char *data)
{
	static const unsigned char type[16]={0xaf,0x3d,0xc6,0x0f,0x83,0x84,0x72,0x47,0x8e,0x79,0x3d,0x69,0xd8,0x47,0x7d,0xe4};
	unsigned char *h=data+512,*t=data+1024,*bh=data+66*512;
	unsigned i;
	memset(data,0,67*512); memcpy(data,old,34*512);
	memset(t+35*128,0,16384-35*128);
	for(i=0;i<37;i++) {
		unsigned char *e=t+128*i;
		if(i>=28 && i!=32 && i!=34) {
			struct b10_sha256 sha; unsigned char digest[32];
			memset(e,0,128); memcpy(e,type,16);
			b10_sha256_init(&sha); b10_sha256_update(&sha,h+56,16);
			b10_sha256_update(&sha,"beacon10-" B10_STORAGE_LAYOUT "/",strlen("beacon10-" B10_STORAGE_LAYOUT "/"));
			b10_sha256_update(&sha,b10_parts[i].name,strlen(b10_parts[i].name));
			b10_sha256_final(&sha,digest); memcpy(e+16,digest,16);
			e[23]=(e[23]&15)|64; e[24]=(e[24]&63)|128;
			{ unsigned j; for(j=0;j<strlen(b10_parts[i].name);j++) e[56+2*j]=b10_parts[i].name[j]; }
		}
		set64(e+32,b10_parts[i].start); set64(e+40,b10_parts[i].start+b10_parts[i].sectors-1);
	}
	gpt_header(h,t,0); memcpy(data+34*512,t,16384); memcpy(bh,h,512); gpt_header(bh,t,1);
}
static int read_bundle(int fd,struct b10_bundle *b,struct b10_boot_header *boot)
{
	struct stat st; unsigned char hash[32],head[96],saved[32]; uint64_t at=4096,memory; unsigned i;
	const uint64_t limits[3]={6U<<20,B10_KERNEL_PARTITION_BYTES,B10_ROOTFS_PARTITION_BYTES}; int ret=-EINVAL;
	if(fstat(fd,&st) || !S_ISREG(st.st_mode) || b10_read_at(fd,b,sizeof(*b),0) ||
	   sizeof(*b)!=4096 || memcmp(b->magic,B10_INSTALL_MAGIC,8) || b->version!=B10_INSTALL_VERSION || b->bytes!=4096 ||
	   !zero(b->reserved,sizeof(b->reserved))) return -EINVAL;
	memcpy(saved,b->sha256,32); memset(b->sha256,0,32); b10_digest(b,sizeof(*b),hash); memcpy(b->sha256,saved,32);
	if(memcmp(saved,hash,32)) return -EBADMSG;
	for(i=0;i<3;i++) {
		if(b->part[i].offset!=at || b->part[i].bytes<96 || b->part[i].bytes>limits[i]) return -EINVAL;
		if(hash_range(fd,at,b->part[i].bytes,hash) || memcmp(hash,b->part[i].sha256,32)) return -EBADMSG;
		if(i!=1 && (b10_read_at(fd,head,sizeof(head),at) || memcmp(head,"hsqs",4) ||
		   get64(head+40)<96 || get64(head+40)>b->part[i].bytes || get32(head+28)!=4)) return -ENOEXEC;
		at=align4k(at+b->part[i].bytes);
		{
			unsigned char gap[4096]; size_t n=at-b->part[i].offset-b->part[i].bytes;
			if(b10_read_at(fd,gap,n,at-n) || !zero(gap,n)) return -EBADMSG;
		}
	}
	if(at!=b->total || (uint64_t)st.st_size!=at ||
	   b10_read_at(fd,boot,sizeof(*boot),b->part[1].offset) || b10_header_check(boot) ||
	   boot->total_bytes!=b->part[1].bytes) return -EINVAL;
	{
		unsigned char *image=malloc(boot->kernel_bytes),*dtb=malloc(boot->dtb_bytes);
		if(!image || !dtb) { free(image); free(dtb); return -ENOMEM; }
		if(!b10_read_at(fd,image,boot->kernel_bytes,b->part[1].offset+boot->kernel_offset) &&
		   !b10_read_at(fd,dtb,boot->dtb_bytes,b->part[1].offset+boot->dtb_offset) &&
		   !b10_image_check(image,boot->kernel_bytes,&memory) && memory==boot->kernel_memory &&
		   !b10_dtb_check_persistent(dtb,boot->dtb_bytes,memory)) {
			b10_digest(image,boot->kernel_bytes,hash);
			if(!memcmp(hash,boot->kernel_sha256,32)) {
				b10_digest(dtb,boot->dtb_bytes,hash); if(!memcmp(hash,boot->dtb_sha256,32)) ret=0;
			}
		}
		free(image); free(dtb);
	}
	return ret;
}
static int snapshot_check(struct b10_capsule *c,const unsigned char *data,const unsigned char cid[16],const struct b10_bundle *b)
{
	unsigned char hash[32],saved[32]; uint64_t at=4096; unsigned i;
	const uint64_t sizes[8]={b->part[0].bytes,34*512,33*512,262144,1048576,262144,8392704,67*512};
	const uint64_t sources[8]={0,0,(B10_SECTORS-33)*512,18466ULL*512,614946ULL*512,1022498ULL*512,2055202ULL*512,0};
	const uint64_t dests[8]={90658ULL*512,0,0,18466ULL*512,123426ULL*512,125474ULL*512,125986ULL*512,0};
	if(sizeof(*c)!=4096 || memcmp(c->magic,"B10CAPS1",8) || c->version!=1 || c->bytes!=4096 ||
	   c->total> B10_CAPSULE_BYTES || c->total<4096 || memcmp(c->cid,cid,16) ||
	   memcmp(c->bundle_sha256,b->sha256,32) || !zero(c->reserved,sizeof(c->reserved))) return -EINVAL;
	memcpy(saved,c->sha256,32); memset(c->sha256,0,32); b10_digest(c,sizeof(*c),hash); memcpy(c->sha256,saved,32);
	if(memcmp(saved,hash,32)) return -EBADMSG;
	for(i=0;i<8;i++) {
		if(c->part[i].offset!=at || c->part[i].bytes!=sizes[i] || c->part[i].source!=sources[i] ||
		   c->part[i].destination!=dests[i] || at>c->total || sizes[i]>c->total-at) return -EINVAL;
		b10_digest(data+at,sizes[i],hash); if(memcmp(hash,c->part[i].sha256,32)) return -EBADMSG;
		at=align4k(at+sizes[i]);
	}
	if(at!=c->total || memcmp(data+c->part[0].offset,"hsqs",4) ||
	   memcmp(c->part[0].sha256,b->part[0].sha256,32) || factory_gpt(data+c->part[1].offset) ||
	   memcmp(c->disk_guid,data+c->part[1].offset+512+56,16)) return -EINVAL;
	/* Regenerate the exact planned table from the saved original, not live metadata. */
	{
		unsigned char gpt[67*512]; make_gpt(data+c->part[1].offset,gpt);
		if(memcmp(gpt,data+c->part[7].offset,sizeof(gpt))) return -EBADMSG;
	}
	for(i=3;i<=5;i+=2) {
		const unsigned char *env=data+c->part[i].offset;
		if(b10_env_check(env)) return -EBADMSG;
	}
	return 0;
}
static int create_snapshot(int disk,int bundle,unsigned char *data,const unsigned char cid[16],const struct b10_bundle *b)
{
	struct b10_capsule *c=(void *)data; unsigned i; uint64_t at=4096;
	const uint64_t sizes[8]={b->part[0].bytes,34*512,33*512,262144,1048576,262144,8392704,67*512};
	const uint64_t sources[8]={0,0,(B10_SECTORS-33)*512,18466ULL*512,614946ULL*512,1022498ULL*512,2055202ULL*512,0};
	const uint64_t dests[8]={90658ULL*512,0,0,18466ULL*512,123426ULL*512,125474ULL*512,125986ULL*512,0};
	memset(data,0,B10_CAPSULE_BYTES); memcpy(c->magic,"B10CAPS1",8); c->version=1; c->bytes=4096;
	memcpy(c->cid,cid,16); memcpy(c->bundle_sha256,b->sha256,32);
	for(i=0;i<8;i++) {
		c->part[i].offset=at; c->part[i].bytes=sizes[i]; c->part[i].source=sources[i]; c->part[i].destination=dests[i];
		if(at+sizes[i]>B10_CAPSULE_BYTES) return -EFBIG;
		if(i==7) make_gpt(data+c->part[1].offset,data+at);
		else if(b10_read_at(i==0?bundle:disk,data+at,sizes[i],i==0?b->part[0].offset:sources[i])) return -EIO;
		b10_digest(data+at,sizes[i],c->part[i].sha256); at=align4k(at+sizes[i]);
	}
	c->total=at; memcpy(c->disk_guid,data+c->part[1].offset+568,16); b10_digest(c,sizeof(*c),c->sha256);
	return snapshot_check(c,data,cid,b);
}
static int copy_component(int disk,int bundle,const struct b10_component *part,uint64_t dest)
{
	unsigned char data[65536],hash[32]; uint64_t at=0;
	if(!hash_range(disk,dest,part->bytes,hash) && !memcmp(hash,part->sha256,32)) return 0;
	while(at<part->bytes) {
		size_t n=part->bytes-at<sizeof(data)?part->bytes-at:sizeof(data);
		if(b10_read_at(bundle,data,n,part->offset+at) || b10_write_verified(disk,data,n,dest+at)) return -EIO;
		at+=n;
	}
	return hash_range(disk,dest,part->bytes,hash) || memcmp(hash,part->sha256,32)?-EIO:0;
}
int b10_install(int disk,int bundle,const unsigned char cid[16],int write)
{
	struct b10_bundle b; struct b10_boot_header boot; struct b10_state state,old;
	unsigned char *data=malloc(B10_CAPSULE_BYTES),guid[16],current[34*512],hash[32];
	struct b10_capsule *c=(void *)data; int ret=-ENOMEM,fresh=0; unsigned i;
	uint64_t sequence=1;
	if(!data) return ret;
	ret=read_bundle(bundle,&b,&boot); if(ret) goto out;
	ret=stock_boot(disk); if(ret) goto out;
	if(b10_read_at(disk,data,4096,CAPS) || b10_read_at(disk,current,sizeof(current),0)) { ret=-EIO; goto out; }
	if(memcmp(c->magic,"B10CAPS1",8) || c->total<4096 || c->total>B10_CAPSULE_BYTES) {
		if(factory_gpt(current)) { ret=-EINVAL; goto out; }
		ret=create_snapshot(disk,bundle,data,cid,&b); if(ret) goto out; fresh=1;
	} else {
		if(b10_read_at(disk,data+4096,c->total-4096,CAPS+4096)) { ret=-EINVAL; goto out; }
		{
			unsigned char saved[32],actual[32];
			memcpy(saved,c->sha256,32); memset(c->sha256,0,32); b10_digest(c,sizeof(*c),actual); memcpy(c->sha256,saved,32);
			if(memcmp(saved,actual,32) && !factory_gpt(current)) {
				ret=create_snapshot(disk,bundle,data,cid,&b); fresh=1;
			} else ret=snapshot_check(c,data,cid,&b);
		}
		/* A torn first publication is recoverable while the factory primary
		 * table is intact. No payload that overlaps source identity data is
		 * ever written before replacing that table. Binding failures remain
		 * fatal rather than accepting another card or installation bundle.
		 */
		if(ret==-EBADMSG && !factory_gpt(current) && !memcmp(c->cid,cid,16) &&
		   !memcmp(c->bundle_sha256,b.sha256,32)) {
			ret=create_snapshot(disk,bundle,data,cid,&b); fresh=1;
		}
		if(ret) goto out;
		/* Only old, new, or torn versions of our own two tables are accepted.
		 * P1-P25 must still be byte identical before repairing a torn header.
		 */
		if(memcmp(current+1024,data+c->part[1].offset+1024,25*128)) { ret=-ESTALE; goto out; }
	}
	memcpy(guid,c->disk_guid,16);
	if(!write) { ret=0; goto out; }
	if(!b10_layout_check(disk,hash) && !b10_state_read(disk,guid,&old) && old.flags==B10_STATE_READY) {
		ret=memcmp(old.cid,cid,16) || memcmp(old.kernel_sha256,boot.kernel_sha256,32) ||
		    old.rootfs_bytes!=b.part[2].bytes || memcmp(old.rootfs_sha256,b.part[2].sha256,32) ? -ESTALE:0;
		if(!ret && old.sequence>B10_STATE_MAX_SEQUENCE-2) ret=-EOVERFLOW;
		if(!ret) ret=copy_component(disk,bundle,&b.part[1],B10_KERNEL_START_SECTORS*512);
		if(!ret) ret=copy_component(disk,bundle,&b.part[2],B10_ROOTFS_START_SECTORS*512);
		goto out; /* Repeating a completed install must not erase the overlay. */
	}
	/* Reserve INSTALLING, READY, the first boot attempt and its ACK before
	 * any snapshot, partition, or environment-related state is published.
	 */
	if(!b10_state_read(disk,guid,&old)) {
		if(old.sequence>B10_STATE_MAX_SEQUENCE-4) { ret=-EOVERFLOW; goto out; }
		sequence=old.sequence+1;
	}
	if(fresh) {
		/* Publish the snapshot header last. Until it verifies, source bytes,
		 * boot roots and both GPTs remain untouched.
		 */
		ret=b10_write_verified(disk,data+4096,c->total-4096,CAPS+4096); if(ret) goto out;
		ret=b10_write_verified(disk,data,4096,CAPS); if(ret) goto out;
	}
	memset(&state,0,sizeof(state)); memcpy(state.magic,"B10STATE",8); state.version=1; state.bytes=4096;
	state.sequence=sequence; state.flags=B10_STATE_INSTALLING; memcpy(state.disk_guid,guid,16); memcpy(state.cid,cid,16);
	memcpy(state.kernel_sha256,boot.kernel_sha256,32); state.rootfs_bytes=b.part[2].bytes;
	memcpy(state.rootfs_sha256,b.part[2].sha256,32);
	state.crc=b10_crc32(&state,sizeof(state));
	ret=b10_write_verified(disk,&state,sizeof(state),(B10_CAPSULE_START+B10_STATE_A)*512); if(ret) goto out;
	ret=b10_write_verified(disk,&state,sizeof(state),(B10_CAPSULE_START+B10_STATE_B)*512); if(ret) goto out;
	/* Both factory boot slots can reach a bootstrap before moving their GPT
	 * entries. The old P27 copy survives until both new tables verify.
	 */
	ret=copy_component(disk,bundle,&b.part[0],352802ULL*512); if(ret) goto out;
	ret=copy_component(disk,bundle,&b.part[0],90658ULL*512); if(ret) goto out;
	ret=copy_component(disk,bundle,&b.part[0],107042ULL*512); if(ret) goto out;
	for(i=4;i<=6;i++) {
		const struct b10_snapshot *s=&c->part[i];
		ret=b10_write_verified(disk,data+s->offset,s->bytes,s->destination); if(ret) goto out;
	}
	{
		const unsigned char *gpt=data+c->part[7].offset;
		ret=b10_write_verified(disk,gpt+34*512,32*512,(B10_SECTORS-33)*512); if(ret) goto out;
		ret=b10_write_verified(disk,gpt+66*512,512,(B10_SECTORS-1)*512); if(ret) goto out;
		ret=b10_write_verified(disk,gpt+1024,16384,1024); if(ret) goto out;
		ret=b10_write_verified(disk,gpt+512,512,512); if(ret) goto out;
	}
	ret=b10_layout_check(disk,hash); if(ret || memcmp(hash,guid,16)) { ret=-EINVAL; goto out; }
	ret=copy_component(disk,bundle,&b.part[1],B10_KERNEL_START_SECTORS*512); if(ret) goto out;
	ret=copy_component(disk,bundle,&b.part[2],B10_ROOTFS_START_SECTORS*512); if(ret) goto out;
	/* Request a new overlay. Fstools will format only the exact P36 on first
	 * QSDK boot; clear old ext4 superblocks before publishing READY.
	 */
	{
		unsigned char blank[65536]={0};
		ret=b10_write_verified(disk,blank,sizeof(blank),B10_OVERLAY_START_SECTORS*512); if(ret) goto out;
	}
	state.flags=B10_STATE_READY; state.sequence++;
	ret=b10_state_write(disk,&state);
out:
	free(data); return ret;
}
