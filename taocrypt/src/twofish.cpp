/* twofish.cpp                                
 *
 * Copyright (C) 2003 Sawtooth Consulting Ltd.
 *
 * This file is part of yaSSL.
 *
 * yaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * yaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* based on Wei Dai's twofish.cpp from CryptoPP */

#include "runtime.hpp"
#include "twofish.hpp"
#include "block.hpp"


namespace TaoCrypt {


void Twofish::Process(byte* out, const byte* in, word32 sz)
{
    if (mode_ == ECB)
        ECB_Process(out, in, sz);
    else if (mode_ == CBC)
        if (dir_ == ENCRYPTION)
            CBC_Encrypt(out, in, sz);
        else
            CBC_Decrypt(out, in, sz);
}


namespace {     // locals

// compute (c * x^4) mod (x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) * x + 1)
// over GF(256)
static inline unsigned int Mod(unsigned int c)
{
	static const unsigned int modulus = 0x14d;
	unsigned int c2 = (c<<1) ^ ((c & 0x80) ? modulus : 0);
	unsigned int c1 = c2 ^ (c>>1) ^ ((c & 1) ? (modulus>>1) : 0);
	return c | (c1 << 8) | (c2 << 16) | (c1 << 24);
}

// compute RS(12,8) code with the above polynomial as generator
// this is equivalent to multiplying by the RS matrix
static word32 ReedSolomon(word32 high, word32 low)
{
	for (unsigned int i=0; i<8; i++) {
		high = Mod(high>>24) ^ (high<<8) ^ (low>>24);
		low <<= 8;
	}
	return high;
}

}  // local namespace



inline word32 Twofish::h0(word32 x, const word32* key, unsigned int kLen)
{
	x = x | (x<<8) | (x<<16) | (x<<24);
	switch(kLen)
	{
#define Q(a, b, c, d, t) q_[a][GETBYTE(t,0)] ^ (q_[b][GETBYTE(t,1)] << 8) ^  \
            (q_[c][GETBYTE(t,2)] << 16) ^ (q_[d][GETBYTE(t,3)] << 24)
	case 4: x = Q(1, 0, 0, 1, x) ^ key[6];
	case 3: x = Q(1, 1, 0, 0, x) ^ key[4];
	case 2: x = Q(0, 1, 0, 1, x) ^ key[2];
			x = Q(0, 0, 1, 1, x) ^ key[0];
	}
	return x;
}

inline word32 Twofish::h(word32 x, const word32* key, unsigned int kLen)
{
	x = h0(x, key, kLen);
	return mds_[0][GETBYTE(x,0)] ^ mds_[1][GETBYTE(x,1)] ^ 
        mds_[2][GETBYTE(x,2)] ^ mds_[3][GETBYTE(x,3)];
}


void Twofish::SetKey(const byte* userKey, word32 keylen, CipherDir /*dummy*/)
{
	assert(keylen >= 16 && keylen <= 32);

	unsigned int len = (keylen <= 16 ? 2 : (keylen <= 24 ? 3 : 4));
	Word32Block key(len*2);
	GetUserKey(LittleEndianOrder, key.begin(), len*2, userKey, keylen);

	unsigned int i;
	for (i=0; i<40; i+=2) {
		word32 a = h(i, key.get_buffer(), len);
		word32 b = rotlFixed(h(i+1, key+1, len), 8);
		k_[i] = a+b;
		k_[i+1] = rotlFixed(a+2*b, 9);
	}

	Word32Block svec(2*len);
	for (i=0; i<len; i++)
		svec[2*(len-i-1)] = ReedSolomon(key[2*i+1], key[2*i]);

	for (i=0; i<256; i++) {
		word32 t = h0(i, svec.get_buffer(), len);
		s_[0][i] = mds_[0][GETBYTE(t, 0)];
		s_[1][i] = mds_[1][GETBYTE(t, 1)];
		s_[2][i] = mds_[2][GETBYTE(t, 2)];
		s_[3][i] = mds_[3][GETBYTE(t, 3)];
	}
}


void Twofish::ProcessAndXorBlock(const byte* in, const byte* xOr, byte* out)
    const
{
    if (dir_ == ENCRYPTION)
        encrypt(in, xOr, out);
    else
        decrypt(in, xOr, out);
}

#define G1(x) (s_[0][GETBYTE(x,0)] ^ s_[1][GETBYTE(x,1)] ^ \
            s_[2][GETBYTE(x,2)] ^ s_[3][GETBYTE(x,3)])
#define G2(x) (s_[0][GETBYTE(x,3)] ^ s_[1][GETBYTE(x,0)] ^ \
            s_[2][GETBYTE(x,1)] ^ s_[3][GETBYTE(x,2)])

#define ENCROUND(n, a, b, c, d) \
	x = G1 (a); y = G2 (b); \
	x += y; y += x + k[2 * (n) + 1]; \
	(c) ^= x + k[2 * (n)]; \
	(c) = rotrFixed(c, 1); \
	(d) = rotlFixed(d, 1) ^ y

#define ENCCYCLE(n) \
	ENCROUND (2 * (n), a, b, c, d); \
	ENCROUND (2 * (n) + 1, c, d, a, b)

#define DECROUND(n, a, b, c, d) \
	x = G1 (a); y = G2 (b); \
	x += y; y += x; \
	(d) ^= y + k[2 * (n) + 1]; \
	(d) = rotrFixed(d, 1); \
	(c) = rotlFixed(c, 1); \
	(c) ^= (x + k[2 * (n)])

#define DECCYCLE(n) \
	DECROUND (2 * (n) + 1, c, d, a, b); \
	DECROUND (2 * (n), a, b, c, d)


typedef BlockGetAndPut<word32, LittleEndian> gpBlock;

void Twofish::encrypt(const byte* inBlock, const byte* xorBlock,
                  byte* outBlock) const
{
	word32 x, y, a, b, c, d;

	gpBlock::Get(inBlock)(a)(b)(c)(d);

	a ^= k_[0];
	b ^= k_[1];
	c ^= k_[2];
	d ^= k_[3];

	const word32 *k = k_+8;
	ENCCYCLE (0);
	ENCCYCLE (1);
	ENCCYCLE (2);
	ENCCYCLE (3);
	ENCCYCLE (4);
	ENCCYCLE (5);
	ENCCYCLE (6);
	ENCCYCLE (7);

	c ^= k_[4];
	d ^= k_[5];
	a ^= k_[6];
	b ^= k_[7]; 

	gpBlock::Put(xorBlock, outBlock)(c)(d)(a)(b);
}


void Twofish::decrypt(const byte* inBlock, const byte* xorBlock,
                  byte* outBlock) const
{
	word32 x, y, a, b, c, d;

	gpBlock::Get(inBlock)(c)(d)(a)(b);

	c ^= k_[4];
	d ^= k_[5];
	a ^= k_[6];
	b ^= k_[7];

	const word32 *k = k_+8;
	DECCYCLE (7);
	DECCYCLE (6);
	DECCYCLE (5);
	DECCYCLE (4);
	DECCYCLE (3);
	DECCYCLE (2);
	DECCYCLE (1);
	DECCYCLE (0);

	a ^= k_[0];
	b ^= k_[1];
	c ^= k_[2];
	d ^= k_[3];

	gpBlock::Put(xorBlock, outBlock)(a)(b)(c)(d);
}



} // namespace

