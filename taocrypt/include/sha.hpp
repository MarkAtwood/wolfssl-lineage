/* sha.hpp                                
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


#ifndef TAO_CRYPT_SHA_HPP__
#define TAO_CRYPT_SHA_HPP__

#include "hash.hpp"

namespace TaoCrypt {

class SHA : public HASH {
public:
    enum { BLOCK_SIZE = 64, DIGEST_SIZE = 20, PAD_SIZE = 56,
           BYTE_ORDER = BigEndianOrder};   // in Bytes
    SHA() : HASH(DIGEST_SIZE / sizeof(uint32), BLOCK_SIZE) { Init(); }

    ByteOrder getByteOrder()  const { return ByteOrder(BYTE_ORDER); }
    size_t    getBlockSize()  const { return BLOCK_SIZE; }
    size_t    getDigestSize() const { return DIGEST_SIZE; }
    size_t    getPadSize()    const { return PAD_SIZE; }

    void Init();

    SHA(const SHA&);
    SHA& operator= (const SHA&);

    void Swap(SHA&);
private:
    void Transform();
};


inline void swap(SHA& a, SHA& b)
{
    a.Swap(b);
}

} // namespace


#endif // TAO_CRYPT_SHA_HPP__

