/* blowfish.cpp                                
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

/* based on Wei Dai's blowfish.cpp from CryptoPP */

#include "runtime.hpp"
#include "blowfish.hpp"


namespace TaoCrypt {


void Blowfish::Process(byte* out, const byte* in, word32 sz)
{
    if (mode_ == ECB)
        ECB_Process(out, in, sz);
    else if (mode_ == CBC)
        if (dir_ == ENCRYPTION)
            CBC_Encrypt(out, in, sz);
        else
            CBC_Decrypt(out, in, sz);
}


void Blowfish::SetKey(const byte* key_string, word32 keylength, CipherDir dir)
{
	assert(keylength >= 4 && keylength <= 56);

	unsigned i, j=0, k;
	word32 data, dspace[2] = {0, 0};

	memcpy(pbox_, p_init_, sizeof(p_init_));
	memcpy(sbox_, s_init_, sizeof(s_init_));

	// Xor key string into encryption key vector
	for (i=0 ; i<ROUNDS+2 ; ++i) {
		data = 0;
		for (k=0 ; k<4 ; ++k )
			data = (data << 8) | key_string[j++ % keylength];
		pbox_[i] ^= data;
	}

	crypt_block(dspace, pbox_);

	for (i=0; i<ROUNDS; i+=2)
		crypt_block(pbox_ + i, pbox_ + i + 2);

	crypt_block(pbox_ + ROUNDS, sbox_);

	for (i=0; i < 4*256-2; i+=2)
		crypt_block(sbox_ + i, sbox_ + i + 2);

	if (dir==DECRYPTION)
		for (i=0; i<(ROUNDS+2)/2; i++)
			mySTL::swap(pbox_[i], pbox_[ROUNDS+1-i]);
}


void Blowfish::ProcessAndXorBlock(const byte* in, const byte* xOr, byte* out)
    const
{
	typedef BlockGetAndPut<word32, BigEndian> gpBlock;

	word32 left, right;
	gpBlock::Get(in)(left)(right);

	const word32 *const s = sbox_;
	const word32*       p = pbox_;

	left ^= p[0];

	for (unsigned i=0; i<ROUNDS/2; i++) {
		right ^= (((s[GETBYTE(left,3)] + s[256+GETBYTE(left,2)])
			  ^ s[2*256+GETBYTE(left,1)]) + s[3*256+GETBYTE(left,0)])
			  ^ p[2*i+1];

		left ^= (((s[GETBYTE(right,3)] + s[256+GETBYTE(right,2)])
			 ^ s[2*256+GETBYTE(right,1)]) + s[3*256+GETBYTE(right,0)])
			 ^ p[2*i+2];
	}

	right ^= p[ROUNDS+1];

	gpBlock::Put(xOr, out)(right)(left);
}


void Blowfish::crypt_block(const word32 in[2], word32 out[2]) const
{
	word32 left  = in[0];
	word32 right = in[1];

	const word32 *const s = sbox_;
	const word32*       p = pbox_;

	left ^= p[0];

	for (unsigned i=0; i<ROUNDS/2; i++) {
		right ^= (((s[GETBYTE(left,3)] + s[256+GETBYTE(left,2)])
			  ^ s[2*256+GETBYTE(left,1)]) + s[3*256+GETBYTE(left,0)])
			  ^ p[2*i+1];

		left ^= (((s[GETBYTE(right,3)] + s[256+GETBYTE(right,2)])
			 ^ s[2*256+GETBYTE(right,1)]) + s[3*256+GETBYTE(right,0)])
			 ^ p[2*i+2];
	}

	right ^= p[ROUNDS+1];

	out[0] = right;
	out[1] = left;
}


} // namespace

