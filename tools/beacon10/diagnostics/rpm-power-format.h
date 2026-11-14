/* SPDX-License-Identifier: GPL-2.0-only */
/* Diagnostic metadata only: software votes are NOT physical voltage readings.
 * No pointers or unit identity are transferred. All cells are big endian.
 */
#ifndef B10_RPM_POWER_FORMAT_H
#define B10_RPM_POWER_FORMAT_H
#define B10_POWER_BYTES 256U
#define B10_POWER_MAGIC 0x42313050U
#define B10_POWER_VERSION 2U
#define B10_POWER_FLAGS 7U /* committed, provider locks held, transport read-only */
#define B10_POWER_RAILS 3U
#define B10_POWER_RAIL_OFFSET(i) (32U+24U*(i))
#define B10_POWER_PLL_OFFSET 128U
#define B10_POWER_MUX_OFFSET 192U
#define B10_POWER_NEXT_MSG_OFFSET 204U
#define B10_POWER_CPR_STOPPED_OFFSET 208U
#define B10_POWER_CRC_OFFSET 252U
#define B10_POWER_SMPA 0x61706d73U

static inline unsigned int b10_power_get(const unsigned char *p,unsigned int off)
{
	return (unsigned int)p[off]<<24 | (unsigned int)p[off+1]<<16 |
		(unsigned int)p[off+2]<<8 | p[off+3];
}
static inline void b10_power_put(unsigned char *p,unsigned int off,unsigned int value)
{
	p[off]=value>>24;p[off+1]=value>>16;p[off+2]=value>>8;p[off+3]=value;
}
static inline unsigned int b10_power_crc(const unsigned char *p)
{
	unsigned int crc=~0U,i,j;
	for(i=0;i<B10_POWER_CRC_OFFSET;i++) {
		crc^=p[i];
		for(j=0;j<8;j++) crc=(crc>>1)^((0U-(crc&1U))&0xedb88320U);
	}
	return ~crc;
}
static inline int b10_power_valid(const unsigned char *p,unsigned int bytes)
{
	unsigned int i,rate;
	static const unsigned int id[3]={1,2,4};
	if(bytes!=B10_POWER_BYTES || b10_power_get(p,0)!=B10_POWER_MAGIC ||
	   b10_power_get(p,4)!=B10_POWER_VERSION || b10_power_get(p,8)!=bytes ||
	   b10_power_get(p,12)!=B10_POWER_FLAGS || b10_power_get(p,16) ||
	   b10_power_get(p,28)!=B10_POWER_RAILS || b10_power_get(p,120)!=7 ||
   b10_power_get(p,124) || b10_power_get(p,252)!=b10_power_crc(p) ||
   !b10_power_get(p,B10_POWER_NEXT_MSG_OFFSET) ||
   b10_power_get(p,B10_POWER_NEXT_MSG_OFFSET)>0xfffffff0U ||
   b10_power_get(p,B10_POWER_CPR_STOPPED_OFFSET)>1U) return 0;
	rate=b10_power_get(p,20);
	if(rate<936000000U || rate>2208000000U || rate%1000U ||
	   b10_power_get(p,24)!=rate/1000U) return 0;
	/* Only the observed integer Huayra PLL and direct APSS mux are audited.
	 * Correlate the clock-framework sample with actual PLL L/mode and RCG
	 * source/divider, rather than trusting a possibly stale software rate.
	 */
	if(rate%24000000U || b10_power_get(p,136)!=rate/24000000U ||
	   (b10_power_get(p,128)&0x80000007U)!=0x80000007U ||
	   (b10_power_get(p,152)&0x01000000U) ||
	   (b10_power_get(p,196)&0x371fU)!=0x501U) return 0;
	for(i=0;i<3;i++) {
		unsigned int off=B10_POWER_RAIL_OFFSET(i),value=b10_power_get(p,off+12);
		if(b10_power_get(p,off)!=B10_POWER_SMPA || b10_power_get(p,off+4)!=id[i] ||
		   b10_power_get(p,off+8)!=1 || b10_power_get(p,off+16)>1000000U ||
		   b10_power_get(p,off+20)) return 0;
		if((i==0 && (value<587500U || value>1075000U || value%12500U)) ||
		   (i==1 && (value<700000U || value>1000000U || value%12500U)) ||
		   (i==2 && (value<1U || value>9U))) return 0;
	}
	/* CPR corner indices are software state, not microvolts. */
	if(b10_power_get(p,104)<1 || b10_power_get(p,104)>6 || b10_power_get(p,108)!=1 ||
	   b10_power_get(p,112)<1 || b10_power_get(p,112)>3 || b10_power_get(p,116)>1) return 0;
	/* The snapshot contains exactly 16 PLL cells and 3 mux cells. */
	for(i=212;i<252;i++) if(p[i]) return 0;
	return 1;
}
#endif
