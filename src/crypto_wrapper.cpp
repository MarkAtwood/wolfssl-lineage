/* crypto_wrapper.cpp  
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

/*  The crypto wrapper source implements the policies for the cipher
 *  components used by SSL.
 *
 *  The implementation relies on a specfic library, the default is CryptoPP.
 */


#include "crypto_wrapper.hpp"

#include "md5.h"
#include "sha.h"
#include "hmac.h"
#include "modes.h"
#include "des.h"
#include "arc4.h"
#include "rsa.h"
#include "dsa.h"
#include "dh.h"
#include "osrng.h"
#include "hex.h"
#include "files.h"
#include "base64.h"




// MD5 Implementation
struct MD5::MD5Impl {
    CryptoPP::MD5 md5_;
    MD5Impl() {}
    explicit MD5Impl(const CryptoPP::MD5& md5) : md5_(md5) {}
};


MD5::MD5() : pimpl_(new MD5Impl) {}

MD5::~MD5() { delete pimpl_; }

MD5::MD5(const MD5& that) : pimpl_(new MD5Impl(that.pimpl_->md5_)) {}

MD5& MD5::operator=(const MD5& that)
{
    pimpl_->md5_ = that.pimpl_->md5_;
    return *this;
}

// Fill out with MD5 digest from in that is sz bytes, out must be >= digest sz
void MD5::get_digest(byte* out, const byte* in, unsigned int sz)
{
    pimpl_->md5_.Update(in, sz);
    pimpl_->md5_.Final(out);
}

// Fill out with MD5 digest from previous updates
void MD5::get_digest(byte* out)
{
    pimpl_->md5_.Final(out);
}


// Update the current digest
void MD5::update(const byte* in, unsigned int sz)
{
    pimpl_->md5_.Update(in, sz);
}


// SHA Implementation
struct SHA::SHAImpl {
    CryptoPP::SHA sha_;
    SHAImpl() {}
    explicit SHAImpl(const CryptoPP::SHA& sha) : sha_(sha) {}
};


SHA::SHA() : pimpl_(new SHAImpl) {}

SHA::~SHA() { delete pimpl_; }

SHA::SHA(const SHA& that) : pimpl_(new SHAImpl(that.pimpl_->sha_)) {}

SHA& SHA::operator=(const SHA& that)
{
    pimpl_->sha_ = that.pimpl_->sha_;
    return *this;
}


// Fill out with SHA digest from in that is sz bytes, out must be >= digest sz
void SHA::get_digest(byte* out, const byte* in, unsigned int sz)
{
    pimpl_->sha_.Update(in, sz);
    pimpl_->sha_.Final(out);
}


// Fill out with SHA digest from previous updates
void SHA::get_digest(byte* out)
{
    pimpl_->sha_.Final(out);
}


// Update the current digest
void SHA::update(const byte* in, unsigned int sz)
{
    pimpl_->sha_.Update(in, sz);
}


// HMAC_MD5 Implementation
struct HMAC_MD5::HMAC_MD5Impl {
    CryptoPP::HMAC<CryptoPP::MD5> mac_;
    HMAC_MD5Impl() {}
    explicit HMAC_MD5Impl(const CryptoPP::HMAC<CryptoPP::MD5>& md5) 
        : mac_(md5) {}
};


HMAC_MD5::HMAC_MD5(const byte* secret, unsigned int len) 
    : pimpl_(new HMAC_MD5Impl) 
{
    pimpl_->mac_.SetKey(secret, len);
}

HMAC_MD5::~HMAC_MD5() { delete pimpl_; }

HMAC_MD5::HMAC_MD5(const HMAC_MD5& that) : 
    pimpl_(new HMAC_MD5Impl(that.pimpl_->mac_)) {}

HMAC_MD5& HMAC_MD5::operator=(const HMAC_MD5& that)
{
    pimpl_->mac_ = that.pimpl_->mac_;
    return *this;
}

// Fill out with MD5 digest from in that is sz bytes, out must be >= digest sz
void HMAC_MD5::get_digest(byte* out, const byte* in, unsigned int sz)
{
    pimpl_->mac_.Update(in, sz);
    pimpl_->mac_.Final(out);
}

// Fill out with MD5 digest from previous updates
void HMAC_MD5::get_digest(byte* out)
{
    pimpl_->mac_.Final(out);
}


// Update the current digest
void HMAC_MD5::update(const byte* in, unsigned int sz)
{
    pimpl_->mac_.Update(in, sz);
}


// HMAC_SHA Implementation
struct HMAC_SHA::HMAC_SHAImpl {
    CryptoPP::HMAC<CryptoPP::SHA> mac_;
    HMAC_SHAImpl() {}
    explicit HMAC_SHAImpl(const CryptoPP::HMAC<CryptoPP::SHA>& sha) 
        : mac_(sha) {}
};


HMAC_SHA::HMAC_SHA(const byte* secret, unsigned int len) 
    : pimpl_(new HMAC_SHAImpl) 
{
    pimpl_->mac_.SetKey(secret, len);
}

HMAC_SHA::~HMAC_SHA() { delete pimpl_; }

HMAC_SHA::HMAC_SHA(const HMAC_SHA& that) : 
    pimpl_(new HMAC_SHAImpl(that.pimpl_->mac_)) {}

HMAC_SHA& HMAC_SHA::operator=(const HMAC_SHA& that)
{
    pimpl_->mac_ = that.pimpl_->mac_;
    return *this;
}

// Fill out with SHA digest from in that is sz bytes, out must be >= digest sz
void HMAC_SHA::get_digest(byte* out, const byte* in, unsigned int sz)
{
    pimpl_->mac_.Update(in, sz);
    pimpl_->mac_.Final(out);
}

// Fill out with SHA digest from previous updates
void HMAC_SHA::get_digest(byte* out)
{
    pimpl_->mac_.Final(out);
}


// Update the current digest
void HMAC_SHA::update(const byte* in, unsigned int sz)
{
    pimpl_->mac_.Update(in, sz);
}


struct DES::DESImpl {
    CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption encryption;
    CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption decryption;
};


DES::DES() : pimpl_(new DESImpl) {}

DES::~DES() { delete pimpl_; }


void DES::set_encryptKey(const byte* k, const byte* iv)
{
    pimpl_->encryption.SetKeyWithIV(k, DES_KEY_SZ, iv);
}


void DES::set_decryptKey(const byte* k, const byte* iv)
{
    pimpl_->decryption.SetKeyWithIV(k, DES_KEY_SZ, iv);
}

// DES encrypt plain of length sz into cipher
void DES::encrypt(byte* cipher, const byte* plain, unsigned int sz)
{
    pimpl_->encryption.ProcessString(cipher, plain, sz);
}


// DES decrypt cipher of length sz into plain
void DES::decrypt(byte* plain, const byte* cipher, unsigned int sz)
{
    pimpl_->decryption.ProcessString(plain, cipher, sz);
}


struct DES_EDE::DES_EDEImpl {
    CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Encryption encryption;
    CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption decryption;
};


DES_EDE::DES_EDE() : pimpl_(new DES_EDEImpl) {}

DES_EDE::~DES_EDE() { delete pimpl_; }


void DES_EDE::set_encryptKey(const byte* k, const byte* iv)
{
    pimpl_->encryption.SetKeyWithIV(k, DES_EDE_KEY_SZ, iv);
}


void DES_EDE::set_decryptKey(const byte* k, const byte* iv)
{
    pimpl_->decryption.SetKeyWithIV(k, DES_EDE_KEY_SZ, iv);
}


// 3DES encrypt plain of length sz into cipher
void DES_EDE::encrypt(byte* cipher, const byte* plain, unsigned int sz)
{
    pimpl_->encryption.ProcessString(cipher, plain, sz);
}


// 3DES decrypt cipher of length sz into plain
void DES_EDE::decrypt(byte* plain, const byte* cipher, unsigned int sz)
{
    pimpl_->decryption.ProcessString(plain, cipher, sz);
}


// Implementation of alledged RC4
struct RC4::RC4Impl {
    CryptoPP::ARC4::Encryption encryption;
    CryptoPP::ARC4::Decryption decryption;
};


RC4::RC4() : pimpl_(new RC4Impl) {}

RC4::~RC4() { delete pimpl_; }


void RC4::set_encryptKey(const byte* k, const byte* iv)
{
    pimpl_->encryption.SetKey(k, RC4_KEY_SZ);
}


void RC4::set_decryptKey(const byte* k, const byte* iv)
{
    pimpl_->decryption.SetKey(k, RC4_KEY_SZ);
}


// RC4 encrypt plain of length sz into cipher
void RC4::encrypt(byte* cipher, const byte* plain, unsigned int sz)
{
    pimpl_->encryption.ProcessString(cipher, plain, sz);
}


// RC4 decrypt cipher of length sz into plain
void RC4::decrypt(byte* plain, const byte* cipher, unsigned int sz)
{
    pimpl_->decryption.ProcessString(plain, cipher, sz);
}


struct RandomPool::RandomImpl {
    CryptoPP::AutoSeededRandomPool RNG_;
};

RandomPool::RandomPool() : pimpl_(new RandomImpl) {}

RandomPool::~RandomPool() { delete pimpl_; }

void RandomPool::Fill(opaque* dst, size_t sz) const
{
    pimpl_->RNG_.GenerateBlock(dst, sz);
}


// Implementation of DSS Authentication
struct DSS::DSSImpl {
    void SetPublic (const byte*, unsigned int);
    void SetPrivate(const byte*, unsigned int);
    CryptoPP::DSA::PublicKey publicKey_;
    CryptoPP::DSA::PrivateKey privateKey_;
};


// Decode and store the public key
void DSS::DSSImpl::SetPublic(const byte* key, unsigned int sz)
{
    CryptoPP::StringSource public_str(key, sz, true);
    publicKey_.BERDecodeKey(public_str);
}


// Decode and store the public key
void DSS::DSSImpl::SetPrivate(const byte* key, unsigned int sz)
{
    CryptoPP::StringSource private_str(key, sz, true);
    privateKey_.BERDecodeKey(private_str);
    CryptoPP::DSA::Signer   priv(privateKey_);
    CryptoPP::DSA::Verifier pub(priv);
    publicKey_ = pub.GetKey();
}


// Set public or private key
DSS::DSS(const byte* key, unsigned int sz, bool publicKey) 
    : pimpl_(new DSSImpl)
{
    if (publicKey) 
        pimpl_->SetPublic(key, sz);
    else
        pimpl_->SetPrivate(key, sz);
}


DSS::~DSS()
{
    delete pimpl_;
}


// DSS Sign message of length sz into sig
void DSS::sign(byte* sig,  const byte* message, unsigned int sz,
               const RandomPool& random)
{
    using namespace CryptoPP;

    DSA::Signer signer(pimpl_->privateKey_);
    signer.SignMessage(random.pimpl_->RNG_, message, sz, sig);
}


// DSS Verify message of length sz against sig, is it correct?
bool DSS::verify(const byte* message, unsigned int sz, const byte* sig,
                 unsigned int sig_sz)
{
    using namespace CryptoPP;

    DSA::Verifier ver(pimpl_->publicKey_);
    return ver.VerifyMessage(message, sz, sig, sig_sz);
}


// Implementation of RSA key interface
struct RSA::RSAImpl {
    void SetPublic (const byte*, unsigned int);
    void SetPrivate(const byte*, unsigned int);
    CryptoPP::RSA::PublicKey publicKey_;
    CryptoPP::RSA::PrivateKey privateKey_;
};


// Decode and store the public key
void RSA::RSAImpl::SetPublic(const byte* key, unsigned int sz)
{
    CryptoPP::StringSource public_str(key, sz, true);
    publicKey_.BERDecodeKey(public_str);
}


// Decode and store the public key
void RSA::RSAImpl::SetPrivate(const byte* key, unsigned int sz)
{
    CryptoPP::StringSource private_str(key, sz, true);
    privateKey_.BERDecodeKey(private_str);
    publicKey_ = CryptoPP::RSA::PublicKey(privateKey_);
}


// Set public or private key
RSA::RSA(const byte* key, unsigned int sz, bool publicKey) 
    : pimpl_(new RSAImpl)
{
    if (publicKey) 
        pimpl_->SetPublic(key, sz);
    else
        pimpl_->SetPrivate(key, sz);
}

RSA::~RSA()
{
    delete pimpl_;
}


// get cipher text length, varies on key size
unsigned int RSA::get_cipherLength() const
{
    using namespace CryptoPP;

    RSAES_PKCS1v15_Encryptor enc(pimpl_->publicKey_);
    return enc.FixedCiphertextLength();
}


// RSA Sign message of length sz into sig
void RSA::sign(byte* sig,  const byte* message, unsigned int sz,
               const RandomPool& random)
{
    using namespace CryptoPP;

    RSASSA_PKCS1v15_MD5_Signer signer(pimpl_->privateKey_);
    signer.SignMessage(random.pimpl_->RNG_, message, sz, sig);
}


// RSA Verify message of length sz against sig, is it correct?
bool RSA::verify(const byte* message, unsigned int sz, const byte* sig,
                 unsigned int sig_sz)
{
    using namespace CryptoPP;

    RSASSA_PKCS1v15_MD5_Verifier ver(pimpl_->publicKey_);
    return ver.VerifyMessage(message, sz, sig, sig_sz);
}


// RSA public encrypt plain of length sz into cipher
void RSA::encrypt(byte* cipher, const byte* plain, unsigned int sz,
                  const RandomPool& random)
{
    using namespace CryptoPP;

    RSAES_PKCS1v15_Encryptor enc(pimpl_->publicKey_);
    enc.Encrypt(random.pimpl_->RNG_, plain, sz, cipher);
}


// RSA private decrypt cipher of length sz into plain
void RSA::decrypt(byte* plain, const byte* cipher, unsigned int sz,
                  const RandomPool& random)
{
    using namespace CryptoPP;

    RSAES_PKCS1v15_Decryptor dec(pimpl_->privateKey_);
    dec.Decrypt(random.pimpl_->RNG_, cipher, sz, plain);
}


struct DiffieHellman::DHImpl {
    CryptoPP::DH         dh_;
    CryptoPP::RandomPool ranPool_;
    byte* publicKey_;
    byte* privateKey_;
    byte* agreedKey_;

    DHImpl() : publicKey_(0), privateKey_(0), agreedKey_(0) {}
    ~DHImpl() {delete[] agreedKey_; delete[] privateKey_; delete[] publicKey_;}

    DHImpl(const DHImpl& that) : publicKey_(0), privateKey_(0), agreedKey_(0),
                                 dh_(that.dh_), ranPool_(that.ranPool_) {}

    void AllocKeys(unsigned int pubSz, unsigned int privSz, unsigned int agrSz)
    {
        publicKey_  = new byte[pubSz];
        privateKey_ = new byte[privSz];
        agreedKey_  = new byte[agrSz];
    }
};


// generate pair
DiffieHellman::DiffieHellman(const byte* p, unsigned int pSz, const byte* g,
                             unsigned int gSz, const RandomPool& random)
    : pimpl_(new DHImpl)
{
    using CryptoPP::Integer;
    pimpl_->ranPool_ = random.pimpl_->RNG_;
    pimpl_->dh_.AccessGroupParameters().Initialize(Integer(p, pSz),
                                                   Integer(g, gSz));
    unsigned int pubSz    = pimpl_->dh_.PublicKeyLength();
    unsigned int privSz   = pimpl_->dh_.PrivateKeyLength();
    unsigned int agreedSz = pimpl_->dh_.AgreedValueLength();
    pimpl_->AllocKeys(pubSz, privSz, agreedSz);

    pimpl_->dh_.GenerateKeyPair(pimpl_->ranPool_, pimpl_->privateKey_,
                                                  pimpl_->publicKey_);
}

DiffieHellman::~DiffieHellman() { delete pimpl_; }


DiffieHellman::DiffieHellman(const DiffieHellman& that) 
    : pimpl_(new DHImpl(*that.pimpl_))
{
    pimpl_->dh_.GenerateKeyPair(pimpl_->ranPool_, pimpl_->privateKey_,
                                                  pimpl_->publicKey_);
}


DiffieHellman& DiffieHellman::operator=(const DiffieHellman& that)
{
    pimpl_->dh_ = that.pimpl_->dh_;
    pimpl_->ranPool_ = that.pimpl_->ranPool_;

    pimpl_->dh_.GenerateKeyPair(pimpl_->ranPool_, pimpl_->privateKey_,
                                                  pimpl_->publicKey_);
    return *this;
}


void DiffieHellman::makeAgreement(const byte* otherPub)
{
    pimpl_->dh_.Agree(pimpl_->agreedKey_, pimpl_->privateKey_, otherPub);
}


size_t DiffieHellman::get_agreedKeyLength() const
{
    return pimpl_->dh_.AgreedValueLength();
}


const byte* DiffieHellman::get_agreedKey() const
{
    return pimpl_->agreedKey_;
}


const byte* DiffieHellman::get_publicKey() const
{
    return pimpl_->publicKey_;
}


void DiffieHellman::set_sizes(int& pSz, int& gSz, int& pubSz) const
{
    using CryptoPP::Integer;
    Integer p = pimpl_->dh_.AccessGroupParameters().GetModulus();
    Integer g = pimpl_->dh_.AccessGroupParameters().GetGenerator();

    pSz   = p.ByteCount();
    gSz   = g.ByteCount();
    pubSz = pimpl_->dh_.PublicKeyLength();
}


void DiffieHellman::get_parms(byte* bp, byte* bg, byte* bpub) const
{
    using CryptoPP::Integer;
    Integer p = pimpl_->dh_.AccessGroupParameters().GetModulus();
    Integer g = pimpl_->dh_.AccessGroupParameters().GetGenerator();

    p.Encode(bp, p.ByteCount());
    g.Encode(bg, g.ByteCount());
    memcpy(bpub, pimpl_->publicKey_, pimpl_->dh_.PublicKeyLength());
}


struct Integer::IntegerImpl {
    CryptoPP::Integer int_;
};

Integer::Integer() : pimpl_(new IntegerImpl) {}

Integer::~Integer() { delete pimpl_; }


void Integer::assign(const byte* num, unsigned int sz)
{
    pimpl_->int_ = CryptoPP::Integer(num, sz);
}


x509* PemToDer(const char* file, CertType type)
{
    using namespace CryptoPP;
    using namespace std;

    string header; 
    string footer;

    if (type == Cert) {
        header = "-----BEGIN CERTIFICATE-----\r\n";
        footer = "-----END CERTIFICATE-----\r\n";
    } else {
        header = "-----BEGIN RSA PRIVATE KEY-----\r\n";
        footer = "-----END RSA PRIVATE KEY-----\r\n";
    }

    string pem;
    FileSource(file, true, new StringSink(pem));

    if (pem.find(header) == -1) {
        header.replace(header.find("\r\n"), 2, "\n");
        footer.replace(footer.find("\r\n"), 2, "\n");

        if (pem.find(header) == -1)
            return 0;                   // bad format
    }
    pem.erase(0, pem.find(header) + header.length());
    pem.erase(pem.find(footer), footer.length());

    string der;
    StringSource(pem, true, new Base64Decoder(new StringSink(der)));

    size_t sz = der.length();
    auto_ptr<x509> x(new x509(sz));
    memcpy(x->set_buffer(), der.c_str(), sz);

    return x.release();
}
