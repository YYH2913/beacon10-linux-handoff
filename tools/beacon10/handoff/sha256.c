// SPDX-License-Identifier: GPL-2.0-only
#include "sha256.h"
static const b10_word k[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static b10_word rotr(b10_word a, unsigned n) { return (a >> n) | (a << (32-n)); }
static void transform(struct b10_sha256 *s)
{
	b10_word w[64], a,b,c,d,e,f,g,h,x,y;
	unsigned i;
	for (i=0;i<16;i++) w[i]=(b10_word)s->block[4*i]<<24 | (b10_word)s->block[4*i+1]<<16 |
		(b10_word)s->block[4*i+2]<<8 | s->block[4*i+3];
	for (i=16;i<64;i++) w[i]=w[i-16]+(rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3))+
		w[i-7]+(rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10));
	a=s->h[0]; b=s->h[1]; c=s->h[2]; d=s->h[3]; e=s->h[4]; f=s->h[5]; g=s->h[6]; h=s->h[7];
	for (i=0;i<64;i++) {
		x=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
		y=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
		h=g; g=f; f=e; e=d+x; d=c; c=b; b=a; a=x+y;
	}
	s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
	s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}
void b10_sha256_init(struct b10_sha256 *s)
{
	static const b10_word h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
		0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	memset(s,0,sizeof(*s)); memcpy(s->h,h,sizeof(h));
}
void b10_sha256_update(struct b10_sha256 *s, const void *data, size_t size)
{
	const unsigned char *p=data;
	while (size) {
		size_t off=s->bytes%64, n=64-off;
		if (n>size) n=size;
		memcpy(s->block+off,p,n); s->bytes+=n; p+=n; size-=n;
		if (!(s->bytes%64)) transform(s);
	}
}
void b10_sha256_final(struct b10_sha256 *s, unsigned char out[32])
{
	unsigned char tail[128]={0x80};
	b10_count bits=s->bytes*8;
	size_t n=64-(s->bytes%64);
	unsigned i;
	if (n<9) n+=64;
	for (i=0;i<8;i++) tail[n-1-i]=(unsigned char)(bits>>(8*i));
	b10_sha256_update(s,tail,n);
	for (i=0;i<32;i++) out[i]=(unsigned char)(s->h[i/4]>>(24-8*(i%4)));
	memset(s,0,sizeof(*s));
}
void b10_digest(const void *data, size_t size, unsigned char out[32])
{
	struct b10_sha256 s;
	b10_sha256_init(&s); b10_sha256_update(&s,data,size); b10_sha256_final(&s,out);
}
