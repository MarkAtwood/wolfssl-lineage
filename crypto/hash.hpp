// hash.hpp


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
private:
    size_t  buffLen_;
    size_t  length_;    // in Bits
    uint32* digest_;
    byte*   buffer_;

    virtual void Transform() = 0;

    friend class MD5;
    friend class SHA;
};


} // namespace

#endif // TAO_CRYPT_HASH_HPP__
