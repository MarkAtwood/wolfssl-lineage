// des.hpp

#ifndef TAO_CRYPT_DES_HPP__
#define TAO_CRYPT_DES_HPP__

#include <string.h>
#include "misc.hpp"

namespace TaoCrypt {


enum Mode { ECB, CBC };

template<CipherDir DIR, class T, Mode MODE>
class BlockCipher {
public:
    BlockCipher() : cipher_(DIR, MODE) {}

    void Process(byte* c, const byte* p, size_t sz) 
            { cipher_.Process(c, p, sz); }
    void SetKey(const byte* k, size_t sz)   
            { cipher_.SetKey(k, sz, DIR); }
    void SetKey(const byte* k, size_t sz, const byte* iv)   
            { cipher_.SetKey(k, sz, DIR); cipher_.SetIV(iv); }
private:
    T cipher_;
};


class DES_BASE {
public:
    enum { BLOCK_SIZE = 8, KEY_SIZE = 32, BOXES = 8, BOX_SIZE = 64 };

    DES_BASE(CipherDir DIR, Mode MODE) : dir_(DIR), mode_(MODE) {}
    void Process(byte*, const byte*, size_t);
    void ECB_Process(byte*, const byte*, size_t);
    void CBC_Encrypt(byte*, const byte*, size_t);
    void CBC_Decrypt(byte*, const byte*, size_t);
    void SetIV(const byte* iv) { memcpy(v_, iv, BLOCK_SIZE); }

    virtual void ProcessAndXorBlock(const byte*, const byte*, byte*) const = 0;
protected:
    uint32    k_[KEY_SIZE];
    byte      v_[BLOCK_SIZE];   // init vector plus continue
    byte      tmp_[BLOCK_SIZE]; // vector helper
    CipherDir dir_;
    Mode      mode_;
};

class DES : public DES_BASE {
public:
    DES(CipherDir DIR, Mode MODE) : DES_BASE(DIR, MODE) {}

    void SetKey(const byte*, size_t, CipherDir);
    void RawProcessBlock(uint32&, uint32&) const;
    void ProcessAndXorBlock(const byte*, const byte*, byte*) const;
};


class DES_EDE2 : public DES_BASE {
public:
    DES_EDE2(CipherDir DIR, Mode MODE) 
        : DES_BASE(DIR, MODE), des1_(DIR, MODE), des2_(DIR, MODE) {}

    void SetKey(const byte*, size_t, CipherDir);
    void ProcessAndXorBlock(const byte*, const byte*, byte*) const;
private:
    DES des1_;
    DES des2_;
};


class DES_EDE3 : public DES_BASE {
public:
    DES_EDE3(CipherDir DIR, Mode MODE) 
        : DES_BASE(DIR, MODE), des1_(DIR, MODE), des2_(DIR, MODE),
                               des3_(DIR, MODE) {}

    void SetKey(const byte*, size_t, CipherDir);
    void ProcessAndXorBlock(const byte*, const byte*, byte*) const;
private:
    DES des1_;
    DES des2_;
    DES des3_;
};


typedef BlockCipher<ENCRYPTION, DES, ECB> DES_ECB_Encryption;
typedef BlockCipher<DECRYPTION, DES, ECB> DES_ECB_Decryption;

typedef BlockCipher<ENCRYPTION, DES, CBC> DES_CBC_Encryption;
typedef BlockCipher<DECRYPTION, DES, CBC> DES_CBC_Decryption;

typedef BlockCipher<ENCRYPTION, DES_EDE2, ECB> DES_EDE2_ECB_Encryption;
typedef BlockCipher<DECRYPTION, DES_EDE2, ECB> DES_EDE2_ECB_Decryption;

typedef BlockCipher<ENCRYPTION, DES_EDE2, CBC> DES_EDE2_CBC_Encryption;
typedef BlockCipher<DECRYPTION, DES_EDE2, CBC> DES_EDE2_CBC_Decryption;

typedef BlockCipher<ENCRYPTION, DES_EDE3, ECB> DES_EDE3_ECB_Encryption;
typedef BlockCipher<DECRYPTION, DES_EDE3, ECB> DES_EDE3_ECB_Decryption;

typedef BlockCipher<ENCRYPTION, DES_EDE3, CBC> DES_EDE3_CBC_Encryption;
typedef BlockCipher<DECRYPTION, DES_EDE3, CBC> DES_EDE3_CBC_Decryption;


} // namespace


#endif // TAO_CRYPT_DES_HPP__
