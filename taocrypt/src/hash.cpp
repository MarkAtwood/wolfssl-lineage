/* hash.cpp                                
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



#include <string.h>

#include "hash.hpp"

namespace TaoCrypt {

void HASH::Update(const byte* data, size_t len)
{
    // do block size increments
    size_t blockSz = getBlockSize();
    while (len) {
        size_t add = min(len, blockSz - buffLen_);
        memcpy(&buffer_[buffLen_], data, add);

        buffLen_ += add;
        data     += add;
        len      -= add;

        if (buffLen_ == blockSz) {
            ByteReverseIf(buffer_, buffer_, blockSz, getByteOrder());
            Transform();
        }
    }
}


void HASH::Final(byte* hash)
{
    size_t    blockSz   = getBlockSize();
    size_t    digestSz  = getDigestSize();
    size_t    padSz     = getPadSize();
    ByteOrder order     = getByteOrder();
    size_t    prePadLen = length_ + buffLen_ * 8;  // in bits

    buffer_[buffLen_++] = 0x80;  // add 1

    // pad with zeros
    if (buffLen_ > padSz) {
        while (buffLen_ < blockSz) buffer_[buffLen_++] = 0;
        ByteReverseIf(buffer_, buffer_, blockSz, order);
        Transform();
    }
    while (buffLen_ < padSz) buffer_[buffLen_++] = 0;

    ByteReverseIf(buffer_, buffer_, blockSz, order);
    write64Order(prePadLen, &buffer_[padSz], order);
    Transform();
    ByteReverseIf(digest_, digest_, digestSz, order);
    memcpy(hash, digest_, digestSz);

    Init();  // reset state
}

} // namespace
