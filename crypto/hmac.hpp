// hmac.hpp

#ifndef TAO_CRYPT_HMAC_HPP__
#define TAO_CRYPT_HMAC_HPP__

#include "hash.hpp"

namespace TaoCrypt {

template <class T>
class HMAC {
public:
    enum { IPAD = 0x36, OPAD = 0x5C };

    HMAC() { Init(); }
    void Update(const byte*, size_t);
    void Final(byte*);
    void Init();

    void SetKey(const byte*, size_t);
private:
    byte ipad_[T::BLOCK_SIZE];
    byte opad_[T::BLOCK_SIZE];
    byte innerHash_[T::DIGEST_SIZE];
    bool innerHashKeyed_;
    T    mac_;

    void KeyInnerHash();
};


template <class T>
void HMAC<T>::Init()
{
    mac_.Init();
    innerHashKeyed_ = false;
}


template <class T>
void HMAC<T>::SetKey(const byte* key, size_t length)
{
    Init();

    if (length <= T::BLOCK_SIZE)
        memcpy(ipad_, key, length);
    else {
        mac_.Update(key, length);
        mac_.Final(ipad_);
        length = T::DIGEST_SIZE;
    }
    memset(ipad_ + length, 0, T::BLOCK_SIZE - length);

    for (size_t i = 0; i < T::BLOCK_SIZE; i++) {
        opad_[i] = ipad_[i] ^ OPAD;
        ipad_[i] ^= IPAD;
    }
}


template <class T>
void HMAC<T>::KeyInnerHash()
{
    mac_.Update(ipad_, T::BLOCK_SIZE);
    innerHashKeyed_ = true;
}


template <class T>
void HMAC<T>::Update(const byte *msg, size_t length)
{
    if (!innerHashKeyed_)
        KeyInnerHash();
    mac_.Update(msg, length);
}


template <class T>
void HMAC<T>::Final(byte *hash)
{
    if (!innerHashKeyed_)
        KeyInnerHash();
    mac_.Final(innerHash_);

    mac_.Update(opad_, T::BLOCK_SIZE);
    mac_.Update(innerHash_, T::DIGEST_SIZE);
    mac_.Final(hash);

    innerHashKeyed_ = false;
}


} // namespace

#endif // TAO_CRYPT_HMAC_HPP__