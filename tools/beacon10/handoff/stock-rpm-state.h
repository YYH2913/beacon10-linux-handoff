/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixed-size metadata shared by guarded RAM tests and stock-power-v1. */
#define B10_RPM_STATE_BYTES 32U
static unsigned long b10_rpm_state_offset;
static unsigned char *b10_rpm_state_staged;

static int b10_state_property(const void *data,size_t size,const char *property,unsigned bytes,unsigned long *offset,const unsigned char *expected)
{
	const unsigned char *b=data,*found=NULL;
	size_t pos,end,strings,strings_size;
	unsigned depth=0,i; bool rpm=false;
	if(!bytes || bytes>4096) return -EINVAL;
	if(size<40 || get_unaligned_be32(b)!=0xd00dfeed || get_unaligned_be32(b+4)!=size) return -EINVAL;
	pos=get_unaligned_be32(b+8); end=pos+get_unaligned_be32(b+36);
	strings=get_unaligned_be32(b+12); strings_size=get_unaligned_be32(b+32);
	if(pos<40 || end<pos || end>size || strings<end || strings>size || strings_size>size-strings) return -EINVAL;
	while(pos+4<=end) {
		u32 token=get_unaligned_be32(b+pos); pos+=4;
		if(token==1) {
			const unsigned char *nul=memchr(b+pos,0,end-pos);size_t n;
			if(!nul || depth>=32) return -EINVAL;
			n=nul-(b+pos);
			if(depth==1) rpm=n==9 && !memcmp(b+pos,"rpm-glink",9);
			pos=(pos+n+4)&~(size_t)3;depth++;
		} else if(token==2) {
			if(!depth) return -EINVAL;
			depth--;if(depth==1) rpm=false;
		} else if(token==3) {
			u32 len,off;
			if(!depth || pos+8>end) return -EINVAL;
			len=get_unaligned_be32(b+pos);off=get_unaligned_be32(b+pos+4);pos+=8;
			if(off>=strings_size || !memchr(b+strings+off,0,strings_size-off) || len>end-pos) return -EINVAL;
			if(depth==2 && rpm && !strcmp((const char *)b+strings+off,property)) {
				if(found || len!=bytes || bytes>4096 || (pos&4095)>4096-bytes) return -EINVAL;
				found=b+pos;
				if(expected) { if(memcmp(found,expected,len)) return -EINVAL; }
				else for(i=0;i<len;i++) if(found[i]) return -EINVAL;
			}
			pos=(pos+len+3)&~(size_t)3;
		} else if(token==9) {
			if(depth || !found) return -EINVAL;
			*offset=found-b;return 0;
		} else if(token!=4) return -EINVAL;
		if(pos>end) return -EINVAL;
	}
	return -EINVAL;
}

static int b10_state_find(const void *data,size_t size,const char *property,unsigned bytes,unsigned long *offset)
{
 return b10_state_property(data,size,property,bytes,offset,NULL);
}

#ifdef B10_STOCK_POWER_V1
static int b10_power_protocol_check(const void *data,size_t size)
{
 static const unsigned char version[4]={0,0,0,1};
 unsigned long offset;
 return b10_state_property(data,size,"nokia,stock-power-handoff",4,&offset,version);
}
#endif

static int b10_rpm_state_find(const void *data,size_t size)
{
	return b10_state_find(data,size,"nokia,stock-rpm-state",B10_RPM_STATE_BYTES,&b10_rpm_state_offset);
}

static int b10_state_locate(unsigned long offset,unsigned bytes,unsigned char **staged)
{
	struct b10_copy_page *copy=phys_to_virt(control->copies);
	u64 destination=B10_DTB_LOAD+offset;
	unsigned i,limit=0;
	while(copy && limit++<B10_MAX_PAGES) {
		if(copy->count>B10_ENTRIES_PER_PAGE) return -EINVAL;
		for(i=0;i<copy->count;i++) {
			if(destination>=copy->entry[i].destination &&
			   destination+bytes<=copy->entry[i].destination+4096) {
				*staged=(unsigned char *)phys_to_virt(copy->entry[i].source)+
					(destination-copy->entry[i].destination);
				return 0;
			}
		}
		copy=copy->next ? phys_to_virt(copy->next):NULL;
	}
	return -EINVAL;
}

static int b10_rpm_state_locate(void)
{
	return b10_state_locate(b10_rpm_state_offset,B10_RPM_STATE_BYTES,&b10_rpm_state_staged);
}
