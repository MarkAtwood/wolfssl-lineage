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

void HASH::Update(const byte* data, uint32 len)
{
    // do block size increments
    uint32 blockSz = getBlockSize();
    while (len) {
        uint32 add = min(len, blockSz - buffLen_);
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
    uint32    blockSz   = getBlockSize();
    uint32    digestSz  = getDigestSize();
    uint32    padSz     = getPadSize();
    ByteOrder order     = getByteOrder();
    uint32    prePadLen = length_ + buffLen_ * 8;  // in bits

    buffer_[buffLen_++] = 0x80;  // add 1

    // pad with zeros
    if (buffLen_ > padSz) {
        while (buffLen_ < blockSz) buffer_[buffLen_++] = 0;
        ByteReverseIf(buffer_, buffer_, blockSz, order);
        Transform();
    }
    while (buffLen_ < padSz) buffer_[buffLen_++] = 0;

    ByteReverseIf(buffer_, buffer_, blockSz, order);
    //write64Order(prePadLen, &buffer_[padSz], order);

    uint32 hiSize = 0;  // if using 64 bit length TODO: fix
    memcpy(&buffer_[padSz],   order ? &hiSize : &prePadLen, sizeof(prePadLen));
    memcpy(&buffer_[padSz+4], order ? &prePadLen : &hiSize, sizeof(prePadLen));


    Transform();
    ByteReverseIf(digest_, digest_, digestSz, order);
    memcpy(hash, digest_, digestSz);

    Init();  // reset state
}

} // namespace
