// hash.cpp

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
