// md5.hpp

#ifndef TAO_CRYPT_MD5_HPP__
#define TAO_CRYPT_MD5_HPP__

#include "hash.hpp"

namespace TaoCrypt {

class MD5 : public HASH {
public:
    enum { BLOCK_SIZE = 64, DIGEST_SIZE = 16, PAD_SIZE = 56,
           BYTE_ORDER = LittleEndianOrder };   // in Bytes
    MD5() : HASH(DIGEST_SIZE / sizeof(uint32), BLOCK_SIZE) { Init(); }

    ByteOrder getByteOrder()  const { return ByteOrder(BYTE_ORDER); }
    size_t    getBlockSize()  const { return BLOCK_SIZE; }
    size_t    getDigestSize() const { return DIGEST_SIZE; }
    size_t    getPadSize()    const { return PAD_SIZE; }

    void Init();
private:
    void Transform();
};


} // namespace

#endif // TAO_CRYPT_MD5_HPP__