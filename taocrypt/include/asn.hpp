/* asn.hpp                                
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

/* asn.hpp provides ASN1 BER, PublicKey, and x509v3 decoding 
*/


#ifndef TAO_CRYPT_ASN_HPP
#define TAO_CRYPT_ASN_HPP


#include "misc.hpp"
#include "block.hpp"
#include <list>



namespace TaoCrypt {

// these tags and flags are not complete
enum ASNTag
{
    BOOLEAN             = 0x01,
    INTEGER             = 0x02,
    BIT_STRING          = 0x03,
    OCTET_STRING        = 0x04,
    TAG_NULL            = 0x05,
    OBJECT_IDENTIFIER   = 0x06,
    OBJECT_DESCRIPTOR   = 0x07,
    EXTERNAL            = 0x08,
    REAL                = 0x09,
    ENUMERATED          = 0x0a,
    UTF8_STRING         = 0x0c,
    SEQUENCE            = 0x10,
    SET                 = 0x11,
    NUMERIC_STRING      = 0x12,
    PRINTABLE_STRING    = 0x13,
    T61_STRING          = 0x14,
    VIDEOTEXT_STRING    = 0x15,
    IA5_STRING          = 0x16,
    UTC_TIME            = 0x17,
    GENERALIZED_TIME    = 0x18,
    GRAPHIC_STRING      = 0x19,
    VISIBLE_STRING      = 0x1a,
    GENERAL_STRING      = 0x1b,
    LONG_LENGTH         = 0x80
};

enum ASNIdFlag
{
    UNIVERSAL           = 0x00,
    DATA                = 0x01,
    HEADER              = 0x02,
    CONSTRUCTED         = 0x20,
    APPLICATION         = 0x40,
    CONTEXT_SPECIFIC    = 0x80,
    PRIVATE             = 0xc0
};


enum DNTags
{
    COMMON_NAME         = 0x03,
};


enum Constants
{
    MIN_DATE_SZ = 13,
    MAX_DATE_SZ = 15,
};


class Sink;
class RSA_PublicKey;
class RSA_PrivateKey;
class Integer;
class DH;


// General BER decoding
class BER_Decoder {
protected:
    Sink& sink_;
public:
    explicit BER_Decoder(Sink& s) : sink_(s) {}
    virtual ~BER_Decoder() {}

    Integer& GetInteger(Integer&);
    word32   GetSequence();
    word32   GetSet();
    word32   GetVersion();
    word32   GetExplicitVersion();
private:
    virtual void ReadHeader() = 0;

    BER_Decoder(const BER_Decoder&);            // hide copy
    BER_Decoder& operator=(const BER_Decoder&); // and assign
};


// RSA Private Key BER Decoder
class RSA_Private_Decoder : public BER_Decoder {
public:
    explicit RSA_Private_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(RSA_PrivateKey&);
private:
    void ReadHeader();
};


// RSA Public Key BER Decoder
class RSA_Public_Decoder : public BER_Decoder {
public:
    explicit RSA_Public_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(RSA_PublicKey&);
private:
    void ReadHeader();
};


// DH Key BER Decoder
class DH_Decoder : public BER_Decoder {
public:
    explicit DH_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(DH&);
private:
    void ReadHeader();
};


// General PublicKey
class PublicKey {
    byte*  key_;
    word32 sz_;
public:
    explicit PublicKey(const byte* k = 0, word32 s = 0);
    ~PublicKey() { delete[] key_; }

    const byte* GetKey() const { return key_; }
    word32      size()   const { return sz_; }

    void SetKey(const byte*);
    void SetSize(word32 s);
private:
    PublicKey(const PublicKey&);            // hide copy
    PublicKey& operator=(const PublicKey&); // and assign
};


enum { SHA_SIZE = 20 };


// A Signing Authority
class Signer {
    PublicKey key_;
    char*     name_;
    byte      hash_[SHA_SIZE];
public:
    Signer(const byte* k, word32 kSz, const char* n, const byte* h);
    ~Signer();

    const PublicKey& GetPublicKey()  const { return key_; }
    const char*      GetCommonName() const { return name_; }
    const byte*      GetHash()       const { return hash_; }

private:
    Signer(const Signer&);              // hide copy
    Signer& operator=(const Signer&);   // and assign
};


typedef std::list<Signer*> SignerList;


// an x509v Certificate BER Decoder
class CertDecoder : public BER_Decoder {
public:
    explicit CertDecoder(Sink&, bool decode = true, SignerList* = 0);
    ~CertDecoder();

    const PublicKey& GetPublicKey()  const { return key_; }
    const char*      GetCommonName() const { return subject_; }
    const byte*      GetHash()       const { return subjectHash_; }

    enum DateType { BEFORE, AFTER };   
    enum NameType { ISSUER, SUBJECT };
    enum SigType  { MD5wRSA = 648, SHAwRSA = 649 }; // sum of algo OID
private:
    PublicKey key_;
    word32    certBegin_;               // offset to start of cert
    word32    sigIndex_;                // offset to start of signature
    word32    signatureOID_;            // sum of algorithm object id
    byte      subjectHash_[SHA_SIZE];   // hash of all Names
    byte      issuerHash_[SHA_SIZE];    // hash of all Names
    byte*     signature_;
    char*     issuer_;                  // CommonName
    char*     subject_;                 // CommonName

    void   ReadHeader();
    void   Decode(SignerList*);
    void   StoreKey();
    void   ValidateSelfSignature();
    void   ValidateSignature(SignerList*);
    void   ConfirmSignature(Sink&);
    void   GetKey();
    void   GetName(NameType);
    void   GetValidity();
    void   GetDate(DateType);
    void   GetCompareHash(const byte*, word32, byte*, word32);
    word32 GetAlgoId();
    word32 GetSignature();
};



word32 GetLength(Sink&);


} // namespace


#endif // TAO_CRYPT_ASN_HPP
