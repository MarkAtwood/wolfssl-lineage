/* hash.hpp                                
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



#ifndef TAO_CRYPT_HASH_HPP__
#define TAO_CRYPT_HASH_HPP__

#include "misc.hpp"

namespace TaoCrypt {

class HASH {
public:
    HASH(size_t digSz, size_t buffSz) 
        : digest_(new uint32[digSz]), buffer_(new byte[buffSz]) {}
    virtual ~HASH() { delete[] buffer_; delete[] digest_; }

    virtual ByteOrder getByteOrder()  const = 0;
    virtual size_t    getBlockSize()  const = 0;
    virtual size_t    getDigestSize() const = 0;
    virtual size_t    getPadSize()    const = 0;

    virtual void Init() = 0;
    virtual void Update(const byte*, size_t);
    virtual void Final(byte*);
protected:
    size_t  buffLen_;
    size_t  length_;    // in Bits
    uint32* digest_;
    byte*   buffer_;

    virtual void Transform() = 0;
};


} // namespace

#endif // TAO_CRYPT_HASH_HPP__
