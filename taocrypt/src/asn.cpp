/* asn.cpp                                
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

/* asn.cpp implements ASN1 BER, PublicKey, and x509v3 decoding 
*/



#include "asn.hpp"
#include "file.hpp"
#include "integer.hpp"
#include "rsa.hpp"
#include "dh.hpp"
#include "md5.hpp"
#include "sha.hpp"
#include "coding.hpp"
#include <time.h>     // gmtime();

namespace TaoCrypt {

namespace { // locals


// to the minute
bool operator>(tm& a, tm& b)
{
    if (a.tm_year > b.tm_year)
        return true;

    if (a.tm_year == b.tm_year && a.tm_mon > b.tm_mon)
        return true;
    
    if (a.tm_year == b.tm_year && a.tm_mon == b.tm_mon && a.tm_mday >b.tm_mday)
        return true;

    if (a.tm_year == b.tm_year && a.tm_mon == b.tm_mon &&
        a.tm_mday == b.tm_mday && a.tm_hour > b.tm_hour)
        return true;

    if (a.tm_year == b.tm_year && a.tm_mon == b.tm_mon &&
        a.tm_mday == b.tm_mday && a.tm_hour == b.tm_hour &&
        a.tm_min > b.tm_min)
        return true;

    return false;
}


bool operator<(tm& a, tm&b)
{
    return !(a>b);
}


// like atoi but only use first byte
word32 btoi(byte b)
{
    return b - 0x30;
}


// two byte date/time, add to value
void GetTime(int& value, const byte* date, int& i)
{
    value += btoi(date[i++]) * 10;
    value += btoi(date[i++]);
}


// Make sure before and after dates are valid
void ValidateDate(const byte* date, byte format, CertDecoder::DateType dt)
{
    tm certTime;
    memset(&certTime, 0, sizeof(certTime));
    int i = 0;

    if (format == UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime.tm_year = 1900;
        else
            certTime.tm_year = 2000;
    }
    else  { // format == GENERALIZED_TIME
        certTime.tm_year += btoi(date[i++]) * 1000;
        certTime.tm_year += btoi(date[i++]) * 100;
    }

    GetTime(certTime.tm_year, date, i);     certTime.tm_year -= 1900; // adjust
    GetTime(certTime.tm_mon,  date, i);     certTime.tm_mon  -= 1;    // adjust
    GetTime(certTime.tm_mday, date, i);
    GetTime(certTime.tm_hour, date, i); 
    GetTime(certTime.tm_min,  date, i); 
    GetTime(certTime.tm_sec,  date, i); 

    assert(date[i] == 'Z');     // only Zulu supported for this profile

    time_t ltime = time(0);
    tm* localTime = gmtime(&ltime);

    if (dt == CertDecoder::BEFORE)
        assert(*localTime > certTime);
    else
        assert(*localTime < certTime); 
}


class BadCertificate {};

} // local namespace



// used by Integer as well
word32 GetLength(Sink& sink)
{
    word32 length = 0;

    byte b = sink.next();
    if (b >= LONG_LENGTH) {        
        word32 bytes = b & 0x7F;

        while (bytes--) {
            b = sink.next();
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    return length;
}


PublicKey::PublicKey(const byte* k, word32 s) : key_(0), sz_(0)
{
    if (s) {
        SetSize(s);
        SetKey(k);
    }
}


void PublicKey::SetSize(word32 s)
{
    sz_ = s;
    key_ = new byte[sz_];
}


void PublicKey::SetKey(const byte* k)
{
    memcpy(key_, k, sz_);
}


Signer::Signer(const byte* k, word32 kSz, const char* n, const byte* h)
    : key_(k, kSz), name_(new char[strlen(n) + 1])
{
    int sz = strlen(n);
    memcpy(name_, n, sz);
    name_[sz] = 0;

    memcpy(hash_, h, SHA::DIGEST_SIZE);
}

Signer::~Signer()
{
    delete[] name_;
}


Integer& BER_Decoder::GetInteger(Integer& integer)
{
    integer.Decode(sink_);
    return integer;
}

  
// Read a Sequence, return length
word32 BER_Decoder::GetSequence()
{
    byte b = sink_.next();
    if (b != (SEQUENCE | CONSTRUCTED)) throw BadCertificate();

    return GetLength(sink_);
}


// Read a Sequence, return length
word32 BER_Decoder::GetSet()
{
    byte b = sink_.next();
    if (b != (SET | CONSTRUCTED)) throw BadCertificate();

    return GetLength(sink_);
}


// Read Version, return it
word32 BER_Decoder::GetVersion()
{
    byte b = sink_.next();
    if (b != INTEGER) throw BadCertificate();

    b = sink_.next();
    if (b != 0x01) throw BadCertificate();  // version length not 1

    return sink_.next();
}


// Read ExplicitVersion, return it or 0 if not there (not an error)
word32 BER_Decoder::GetExplicitVersion()
{
    byte b = sink_.next();

    if (b == (CONTEXT_SPECIFIC | CONSTRUCTED)) { // not an error if not here
        sink_.next();
        return GetVersion();
    }
    else 
        sink_.prev(); // put back
  
    return 0;
}


// Decode a BER encoded RSA Private Key
void RSA_Private_Decoder::Decode(RSA_PrivateKey& key)
{
    ReadHeader();

    // public
    key.SetModulus(GetInteger(Integer().Ref()));
    key.SetPublicExponent(GetInteger(Integer().Ref()));

    // private
    key.SetPrivateExponent(GetInteger(Integer().Ref()));
    key.SetPrime1(GetInteger(Integer().Ref()));
    key.SetPrime2(GetInteger(Integer().Ref()));
    key.SetModPrime1PrivateExponent(GetInteger(Integer().Ref()));
    key.SetModPrime2PrivateExponent(GetInteger(Integer().Ref()));
    key.SetMultiplicativeInverseOfPrime2ModPrime1(GetInteger(Integer().Ref()));
}


void RSA_Private_Decoder::ReadHeader()
{
    GetSequence();
    GetVersion();
}


// Decode a BER encoded RSA Public Key
void RSA_Public_Decoder::Decode(RSA_PublicKey& key)
{
    ReadHeader();

    // public key
    key.SetModulus(GetInteger(Integer().Ref()));
    key.SetPublicExponent(GetInteger(Integer().Ref()));
}


void RSA_Public_Decoder::ReadHeader()
{
    GetSequence();
}


void DH_Decoder::ReadHeader()
{
    GetSequence();
}


// Decode a BER encoded Diffie-Hellman Key
void DH_Decoder::Decode(DH& key)
{
    ReadHeader();

    // group parms
    key.SetP(GetInteger(Integer().Ref()));
    key.SetG(GetInteger(Integer().Ref()));
}


CertDecoder::CertDecoder(Sink& s, bool decode, SignerList* signers)
    : BER_Decoder(s), certBegin_(0), sigIndex_(0), signature_(0), issuer_(0),
      subject_(0)
{ 
    if (decode)
        Decode(signers); 
}


CertDecoder::~CertDecoder()
{
    delete[] subject_;
    delete[] issuer_;
    delete[] signature_;
}


// process certificate header, set signature offset
void CertDecoder::ReadHeader()
{
    GetSequence();  // total
    certBegin_ = sink_.get_index();

    sigIndex_ = GetSequence();  // this cert
    sigIndex_ += sink_.get_index();

    GetExplicitVersion(); // version
    GetVersion();         // serial number
}


// Decode a x509v3 Certificate
void CertDecoder::Decode(SignerList* signers)
{
    ReadHeader();
    signatureOID_ = GetAlgoId();
    GetName(ISSUER);   
    GetValidity();
    GetName(SUBJECT);   
    GetKey();

    if (sink_.get_index() != sigIndex_)
        sink_.set_index(sigIndex_);

    word32 confirmOID = GetAlgoId();
    GetSignature();

    if ( confirmOID != signatureOID_ )
        throw BadCertificate();

    if ( memcmp(issuerHash_, subjectHash_, SHA::DIGEST_SIZE) == 0 )
        ValidateSelfSignature();
    else
        ValidateSignature(signers);
}


// Read public key
void CertDecoder::GetKey()
{
    GetSequence();    
    GetAlgoId();

    byte b = sink_.next();
    if (b != BIT_STRING) throw BadCertificate();
    b = sink_.next();      // length, future
    b = sink_.next(); 
    while(b != 0)
        b = sink_.next();

    StoreKey();
}


// Save public key
void CertDecoder::StoreKey()
{
    word32 read = sink_.get_index();
    word32 length = GetSequence();

    read = sink_.get_index() - read;
    length += read;

    while (read--) sink_.prev();

    key_.SetSize(length);
    key_.SetKey(sink_.get_current());
    sink_.advance(length);
}


// process algo OID by summing, return it
word32 CertDecoder::GetAlgoId()
{
    word32 length = GetSequence();
    
    byte b = sink_.next();
    if (b != OBJECT_IDENTIFIER) throw BadCertificate();

    length = GetLength(sink_);
    word32 oid = 0;
    
    while(length--)
        oid += sink_.next();        // just sum it up for now

    b = sink_.next();                       // should have NULL tag and 0
    if (b != TAG_NULL) throw BadCertificate();

    b = sink_.next();
    if (b != 0) throw BadCertificate();

    return oid;
}


// read cert signature, store in signature_
word32 CertDecoder::GetSignature()
{
    byte b = sink_.next();

    if (b != BIT_STRING && b != OCTET_STRING) throw BadCertificate();

    word32 length = GetLength(sink_);

    if (b == BIT_STRING) {
        b = sink_.next();
        if (b != 0) throw BadCertificate();  // first byte always 0
        length--;
    }

    signature_ = new byte[length];
    memcpy(signature_, sink_.get_current(), length);
    sink_.advance(length);

    return length;
}


// process NAME, either issuer or subject
void CertDecoder::GetName(NameType nt)
{
    SHA    sha;
    word32 length = GetSequence();  // length of all distinguished names
    length += sink_.get_index();

    while (sink_.get_index() < length) {
        GetSet();
        GetSequence();

        byte b = sink_.next();
        if (b != OBJECT_IDENTIFIER)
            throw BadCertificate();

        word32 oidSz = GetLength(sink_);
        byte joint[2];
        memcpy(joint, sink_.get_current(), sizeof(joint));

        // v1 name types
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            sink_.advance(2);
            byte   id      = sink_.next();  
            b              = sink_.next();    // strType
            word32 strLen  = GetLength(sink_);

            if (id == COMMON_NAME) {
                char*& ptr = (nt == ISSUER) ? issuer_ : subject_;
                ptr = new char[strLen + 1];
                memcpy(ptr, sink_.get_current(), strLen);
                ptr[strLen] = 0;
            }
            sha.Update(sink_.get_current(), strLen);
            sink_.advance(strLen);
        }
        else {
            // skip
            sink_.advance(oidSz + 1);
            word32 length = GetLength(sink_);
            sink_.advance(length);
        }
    }
    if (nt == ISSUER)
        sha.Final(issuerHash_);
    else
        sha.Final(subjectHash_);
}


// process a Date, either BEFORE or AFTER
void CertDecoder::GetDate(DateType dt)
{
    byte b = sink_.next();
    if (b != UTC_TIME && b != GENERALIZED_TIME)
        throw BadCertificate();

    word32 length = GetLength(sink_);
    byte date[MAX_DATE_SZ];
    if (length > MAX_DATE_SZ || length < MIN_DATE_SZ)
        throw BadCertificate();

    memcpy(date, sink_.get_current(), length);
    sink_.advance(length);

    ValidateDate(date, b, dt);
}


void CertDecoder::GetValidity()
{
    GetSequence();
    GetDate(BEFORE);
    GetDate(AFTER);
}


void CertDecoder::ValidateSelfSignature()
{
    Sink pub(key_.GetKey(), key_.size());
    ConfirmSignature(pub);
}


// extract compare signature hash from plain and place into digest
void CertDecoder::GetCompareHash(const byte* plain, word32 sz, byte* digest,
                                 word32 digSz)
{
    Sink s(plain, sz);
    CertDecoder dec(s, false);

    dec.GetSequence();
    dec.GetAlgoId();
    word32 sigLen = dec.GetSignature();

    if (sigLen > digSz)
        throw BadCertificate();

    memcpy(digest, dec.signature_, sigLen);
}


// validate signature signed by someone else
void CertDecoder::ValidateSignature(SignerList* signers)
{
    assert(signers);

    SignerList::iterator first = signers->begin();
    SignerList::iterator last  = signers->end();

    while (first != last) {
        if ( memcmp(issuerHash_, (*first)->GetHash(), SHA::DIGEST_SIZE) == 0) {
      
            const PublicKey& iKey = (*first)->GetPublicKey();
            Sink pub(iKey.GetKey(), iKey.size());
            ConfirmSignature(pub);

            return;
        }   
        ++first;
    }
    assert(0);  // couldn't validate
}


// RSA confirm
void CertDecoder::ConfirmSignature(Sink& pub)
{
    std::auto_ptr<HASH> hasher;

    if (signatureOID_ == MD5wRSA)
        hasher = std::auto_ptr<HASH>(new MD5);
    else if (signatureOID_ == SHAwRSA)
        hasher = std::auto_ptr<HASH>(new SHA);
    else
        throw BadCertificate();

    byte digest[SHA::DIGEST_SIZE];      // largest size
    byte compare[SHA::DIGEST_SIZE];

    hasher->Update(sink_.get_buffer() + certBegin_, sigIndex_ - certBegin_);
    hasher->Final(digest);

    RSA_PublicKey pubKey(pub);
    std::auto_ptr<byte> plain(new byte[pubKey.FixedCiphertextLength()]);

    word32 plainSz = SSL_Decrypt(pubKey, signature_, plain.get());
    if (plainSz)
        GetCompareHash(plain.get(), plainSz, compare, sizeof(compare));

    assert( memcmp(digest, compare, hasher->getDigestSize()) == 0 );
}


} // namespace
