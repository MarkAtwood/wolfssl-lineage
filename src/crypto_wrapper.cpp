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
 *  The implementation relies on a specfic library, taoCrypt.
 */

#if !defined(USE_CRYPTOPP_LIB)

#include "crypto_wrapper.hpp"
#include "cert_wrapper.hpp"

#include "md5.hpp"
#include "sha.hpp"
#include "hmac.hpp"
#include "modes.hpp"
#include "des.hpp"
#include "arc4.hpp"
#include "rsa.hpp"
#include "dh.hpp"
#include "random.hpp"
#include "file.hpp"
#include "coding.hpp"


namespace yaSSL {


// MD5 Implementation
struct MD5::MD5Impl {
    TaoCrypt::MD5 md5_;
    MD5Impl() {}
    explicit MD5Impl(const TaoCrypt::MD5& md5) : md5_(md5) {}
};


MD5::MD5() : pimpl_(new MD5Impl) {}


MD5::~MD5() { delete pimpl_; }


MD5::MD5(const MD5& that) : pimpl_(new MD5Impl(that.pimpl_->md5_)) {}


MD5& MD5::operator=(const MD5& that)
{
    pimpl_->md5_ = that.pimpl_->md5_;
    return *this;
}


uint MD5::get_digestSize() const
{
    return MD5_LEN;
}


uint MD5::get_padSize() const
{
    return PAD_MD5;
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
    TaoCrypt::SHA sha_;
    SHAImpl() {}
    explicit SHAImpl(const TaoCrypt::SHA& sha) : sha_(sha) {}
};


SHA::SHA() : pimpl_(new SHAImpl) {}


SHA::~SHA() { delete pimpl_; }


SHA::SHA(const SHA& that) : pimpl_(new SHAImpl(that.pimpl_->sha_)) {}


SHA& SHA::operator=(const SHA& that)
{
    pimpl_->sha_ = that.pimpl_->sha_;
    return *this;
}


uint SHA::get_digestSize() const
{
    return SHA_LEN;
}


uint SHA::get_padSize() const
{
    return PAD_SHA;
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
    TaoCrypt::HMAC<TaoCrypt::MD5> mac_;
    HMAC_MD5Impl() {}
};


HMAC_MD5::HMAC_MD5(const byte* secret, unsigned int len) 
    : pimpl_(new HMAC_MD5Impl) 
{
    pimpl_->mac_.SetKey(secret, len);
}


HMAC_MD5::~HMAC_MD5() { delete pimpl_; }


uint HMAC_MD5::get_digestSize() const
{
    return MD5_LEN;
}


uint HMAC_MD5::get_padSize() const
{
    return PAD_MD5;
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
    TaoCrypt::HMAC<TaoCrypt::SHA> mac_;
    HMAC_SHAImpl() {}
};


HMAC_SHA::HMAC_SHA(const byte* secret, unsigned int len) 
    : pimpl_(new HMAC_SHAImpl) 
{
    pimpl_->mac_.SetKey(secret, len);
}


HMAC_SHA::~HMAC_SHA() { delete pimpl_; }


uint HMAC_SHA::get_digestSize() const
{
    return SHA_LEN;
}


uint HMAC_SHA::get_padSize() const
{
    return PAD_SHA;
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
    TaoCrypt::DES_CBC_Encryption encryption;
    TaoCrypt::DES_CBC_Decryption decryption;
};


DES::DES() : pimpl_(new DESImpl) {}

DES::~DES() { delete pimpl_; }


void DES::set_encryptKey(const byte* k, const byte* iv)
{
    pimpl_->encryption.SetKey(k, DES_KEY_SZ, iv);
}


void DES::set_decryptKey(const byte* k, const byte* iv)
{
    pimpl_->decryption.SetKey(k, DES_KEY_SZ, iv);
}

// DES encrypt plain of length sz into cipher
void DES::encrypt(byte* cipher, const byte* plain, unsigned int sz)
{
    pimpl_->encryption.Process(cipher, plain, sz);
}


// DES decrypt cipher of length sz into plain
void DES::decrypt(byte* plain, const byte* cipher, unsigned int sz)
{
    pimpl_->decryption.Process(plain, cipher, sz);
}


struct DES_EDE::DES_EDEImpl {
    TaoCrypt::DES_EDE3_CBC_Encryption encryption;
    TaoCrypt::DES_EDE3_CBC_Decryption decryption;
};


DES_EDE::DES_EDE() : pimpl_(new DES_EDEImpl) {}

DES_EDE::~DES_EDE() { delete pimpl_; }


void DES_EDE::set_encryptKey(const byte* k, const byte* iv)
{
    pimpl_->encryption.SetKey(k, DES_EDE_KEY_SZ, iv);
}


void DES_EDE::set_decryptKey(const byte* k, const byte* iv)
{
    pimpl_->decryption.SetKey(k, DES_EDE_KEY_SZ, iv);
}


// 3DES encrypt plain of length sz into cipher
void DES_EDE::encrypt(byte* cipher, const byte* plain, unsigned int sz)
{
    pimpl_->encryption.Process(cipher, plain, sz);
}


// 3DES decrypt cipher of length sz into plain
void DES_EDE::decrypt(byte* plain, const byte* cipher, unsigned int sz)
{
    pimpl_->decryption.Process(plain, cipher, sz);
}


// Implementation of alledged RC4
struct RC4::RC4Impl {
    TaoCrypt::ARC4::Encryption encryption;
    TaoCrypt::ARC4::Decryption decryption;
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
    pimpl_->encryption.Process(cipher, plain, sz);
}


// RC4 decrypt cipher of length sz into plain
void RC4::decrypt(byte* plain, const byte* cipher, unsigned int sz)
{
    pimpl_->decryption.Process(plain, cipher, sz);
}


struct RandomPool::RandomImpl {
    TaoCrypt::RandomNumberGenerator RNG_;
};

RandomPool::RandomPool() : pimpl_(new RandomImpl) {}

RandomPool::~RandomPool() { delete pimpl_; }

void RandomPool::Fill(opaque* dst, uint sz) const
{
    pimpl_->RNG_.GenerateBlock(dst, sz);
}


/*
// Implementation of DSS Authentication
struct DSS::DSSImpl {
    void SetPublic (const byte*, unsigned int);
    void SetPrivate(const byte*, unsigned int);
    TaoCrypt::DSA::PublicKey publicKey_;
    TaoCrypt::DSA::PrivateKey privateKey_;
};


// Decode and store the public key
void DSS::DSSImpl::SetPublic(const byte* key, unsigned int sz)
{
    TaoCrypt::StringSource public_str(key, sz, true);
    publicKey_.BERDecodeKey(public_str);
}


// Decode and store the public key
void DSS::DSSImpl::SetPrivate(const byte* key, unsigned int sz)
{
    TaoCrypt::StringSource private_str(key, sz, true);
    privateKey_.BERDecodeKey(private_str);
    TaoCrypt::DSA::Signer   priv(privateKey_);
    TaoCrypt::DSA::Verifier pub(priv);
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
    using namespace TaoCrypt;

    DSA::Signer signer(pimpl_->privateKey_);
    signer.SignMessage(random.pimpl_->RNG_, message, sz, sig);
}


// DSS Verify message of length sz against sig, is it correct?
bool DSS::verify(const byte* message, unsigned int sz, const byte* sig,
                 unsigned int sig_sz)
{
    using namespace TaoCrypt;

    DSA::Verifier ver(pimpl_->publicKey_);
    return ver.VerifyMessage(message, sz, sig, sig_sz);
}
*/

// Implementation of RSA key interface
struct RSA::RSAImpl {
    void SetPublic (const byte*, unsigned int);
    void SetPrivate(const byte*, unsigned int);
    TaoCrypt::RSA_PublicKey publicKey_;
    TaoCrypt::RSA_PrivateKey privateKey_;
};


// Decode and store the public key
void RSA::RSAImpl::SetPublic(const byte* key, unsigned int sz)
{
    TaoCrypt::Sink sink(key, sz);
    publicKey_.Initialize(sink);
}


// Decode and store the private key
void RSA::RSAImpl::SetPrivate(const byte* key, unsigned int sz)
{
    TaoCrypt::Sink sink(key, sz);
    privateKey_.Initialize(sink);
    publicKey_ = TaoCrypt::RSA_PublicKey(privateKey_);
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
    return pimpl_->publicKey_.FixedCiphertextLength();
}


// RSA Sign message of length sz into sig
void RSA::sign(byte* sig,  const byte* message, unsigned int sz,
               const RandomPool& random)
{
    TaoCrypt::RSAES_Decryptor dec(pimpl_->privateKey_);
    dec.SSL_Sign(message, sz, sig, random.pimpl_->RNG_);
}


// RSA Verify message of length sz against sig
bool RSA::verify(const byte* message, unsigned int sz, const byte* sig,
                 unsigned int sig_sz)
{
    TaoCrypt::RSAES_Encryptor enc(pimpl_->publicKey_);
    return enc.SSL_Verify(message, sz, sig);
}


// RSA public encrypt plain of length sz into cipher
void RSA::encrypt(byte* cipher, const byte* plain, unsigned int sz,
                  const RandomPool& random)
{
  
    TaoCrypt::RSAES_Encryptor enc(pimpl_->publicKey_);
    enc.Encrypt(plain, sz, cipher, random.pimpl_->RNG_);
}


// RSA private decrypt cipher of length sz into plain
void RSA::decrypt(byte* plain, const byte* cipher, unsigned int sz,
                  const RandomPool& random)
{
    TaoCrypt::RSAES_Decryptor dec(pimpl_->privateKey_);
    dec.Decrypt(cipher, sz, plain, random.pimpl_->RNG_);
}


struct DiffieHellman::DHImpl {
    TaoCrypt::DH                     dh_;
    TaoCrypt::RandomNumberGenerator& ranPool_;
    byte* publicKey_;
    byte* privateKey_;
    byte* agreedKey_;

    DHImpl(TaoCrypt::RandomNumberGenerator& r) : ranPool_(r), publicKey_(0),
                                               privateKey_(0), agreedKey_(0) {}
    ~DHImpl() {delete[] agreedKey_; delete[] privateKey_; delete[] publicKey_;}

    DHImpl(const DHImpl& that) : dh_(that.dh_), ranPool_(that.ranPool_),
                                 publicKey_(0), privateKey_(0), agreedKey_(0)
    {
        uint length = dh_.GetByteLength();
        AllocKeys(length, length, length);
    }

    void AllocKeys(unsigned int pubSz, unsigned int privSz, unsigned int agrSz)
    {
        publicKey_  = new byte[pubSz];
        privateKey_ = new byte[privSz];
        agreedKey_  = new byte[agrSz];
    }
};


// server Side DH, server's view
DiffieHellman::DiffieHellman(const char* file, const RandomPool& random)
    : pimpl_(new DHImpl(random.pimpl_->RNG_))
{
    using namespace TaoCrypt;
    Sink sink;
    FileSource(file, sink);
    HexDecoder hd(sink);

    pimpl_->dh_.Initialize(sink);

    uint length = pimpl_->dh_.GetByteLength();

    pimpl_->AllocKeys(length, length, length);
    pimpl_->dh_.GenerateKeyPair(pimpl_->ranPool_, pimpl_->privateKey_,
                                                  pimpl_->publicKey_);
}

// server Side DH, client's view
DiffieHellman::DiffieHellman(const byte* p, unsigned int pSz, const byte* g,
                             unsigned int gSz, const byte* pub,
                             unsigned int pubSz, const RandomPool& random)
    : pimpl_(new DHImpl(random.pimpl_->RNG_))
{
    using TaoCrypt::Integer;

    pimpl_->dh_.Initialize(Integer(p, pSz).Ref(), Integer(g, gSz).Ref());
    pimpl_->publicKey_ = new opaque[pubSz];
    memcpy(pimpl_->publicKey_, pub, pubSz);
}

DiffieHellman::~DiffieHellman() { delete pimpl_; }


// Client side and view, use server that for p and g
DiffieHellman::DiffieHellman(const DiffieHellman& that) 
    : pimpl_(new DHImpl(*that.pimpl_))
{   
    pimpl_->dh_.GenerateKeyPair(pimpl_->ranPool_, pimpl_->privateKey_,
                                                  pimpl_->publicKey_);
}


DiffieHellman& DiffieHellman::operator=(const DiffieHellman& that)
{
    pimpl_->dh_ = that.pimpl_->dh_;
    pimpl_->dh_.GenerateKeyPair(pimpl_->ranPool_, pimpl_->privateKey_,
                                                  pimpl_->publicKey_);
    return *this;
}


void DiffieHellman::makeAgreement(const byte* other)
{
    pimpl_->dh_.Agree(pimpl_->agreedKey_, pimpl_->privateKey_, other); 
}


uint DiffieHellman::get_agreedKeyLength() const
{
    return pimpl_->dh_.GetByteLength();
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
    using TaoCrypt::Integer;
    Integer p = pimpl_->dh_.GetP();
    Integer g = pimpl_->dh_.GetG();

    pSz   = p.ByteCount();
    gSz   = g.ByteCount();
    pubSz = pimpl_->dh_.GetByteLength();
}


void DiffieHellman::get_parms(byte* bp, byte* bg, byte* bpub) const
{
    using TaoCrypt::Integer;
    Integer p = pimpl_->dh_.GetP();
    Integer g = pimpl_->dh_.GetG();

    p.Encode(bp, p.ByteCount());
    g.Encode(bg, g.ByteCount());
    memcpy(bpub, pimpl_->publicKey_, pimpl_->dh_.GetByteLength());
}


struct Integer::IntegerImpl {
    TaoCrypt::Integer int_;
};

Integer::Integer() : pimpl_(new IntegerImpl) {}

Integer::~Integer() { delete pimpl_; }


void Integer::assign(const byte* num, unsigned int sz)
{
    pimpl_->int_ = TaoCrypt::Integer(num, sz);
}


x509* PemToDer(const char* file, CertType type)
{
    using namespace TaoCrypt;
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

    Sink sink;
    FileSource(file, sink);
    string pem((const char*)sink.get_buffer(), sink.size());

    if (pem.find(header) == std::string::npos) {
        header.replace(header.find("\r\n"), 2, "\n");
        footer.replace(footer.find("\r\n"), 2, "\n");

        if (pem.find(header) == std::string::npos)
            return 0;                   // bad format
    }
    pem.erase(0, pem.find(header) + header.length());
    pem.erase(pem.find(footer), footer.length());

    Sink der((const unsigned char*)pem.c_str(), pem.size());
    throw std::runtime_error("add Base64Decoder(der)");
    // Base64Decoder(der);

    uint sz = der.size();
    auto_ptr<x509> x(new x509(sz));
    memcpy(x->use_buffer(), der.get_buffer(), sz);

    return x.release();
}


} // namespace

#endif // !USE_CRYPTOPP_LIB
