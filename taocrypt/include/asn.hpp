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


#ifndef TAO_CRYPT_ASN_HPP__
#define TAO_CRYPT_ASN_HPP__


#include "misc.hpp"
#include "block.hpp"



namespace TaoCrypt {

// these tags and flags are not complete
enum ASNTag
{
    BOOLEAN 			= 0x01,
    INTEGER 			= 0x02,
    BIT_STRING			= 0x03,
    OCTET_STRING		= 0x04,
    TAG_NULL			= 0x05,
    OBJECT_IDENTIFIER	= 0x06,
    OBJECT_DESCRIPTOR	= 0x07,
    EXTERNAL			= 0x08,
    REAL				= 0x09,
    ENUMERATED			= 0x0a,
    UTF8_STRING			= 0x0c,
    SEQUENCE			= 0x10,
    SET 				= 0x11,
    NUMERIC_STRING		= 0x12,
    PRINTABLE_STRING 	= 0x13,
    T61_STRING			= 0x14,
    VIDEOTEXT_STRING 	= 0x15,
    IA5_STRING			= 0x16,
    UTC_TIME 			= 0x17,
    GENERALIZED_TIME 	= 0x18,
    GRAPHIC_STRING		= 0x19,
    VISIBLE_STRING		= 0x1a,
    GENERAL_STRING		= 0x1b,
    LONG_LENGTH         = 0x80
};

enum ASNIdFlag
{
    UNIVERSAL			= 0x00,
    DATA				= 0x01,
    HEADER				= 0x02,
    CONSTRUCTED 		= 0x20,
    APPLICATION 		= 0x40,
    CONTEXT_SPECIFIC	= 0x80,
    PRIVATE 			= 0xc0
};


class Sink;
class RSA_PublicKey;
class RSA_PrivateKey;
class Integer;
class DH;


class BER_Decoder {
protected:
    Sink& sink_;
public:
    explicit BER_Decoder(Sink& s) : sink_(s) {}

    Integer& GetInteger(Integer&);
    size_t   GetSequence();
    size_t   GetVersion();
    size_t   GetExplicitVersion();
private:
    virtual void ReadHeader() = 0;
};

class RSA_Private_Decoder : public BER_Decoder {
public:
    explicit RSA_Private_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(RSA_PrivateKey&);
private:
    void ReadHeader();
};



class RSA_Public_Decoder : public BER_Decoder {
public:
    explicit RSA_Public_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(RSA_PublicKey&);
private:
    void ReadHeader();
};



class DH_Decoder : public BER_Decoder {
public:
    explicit DH_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(DH&);
private:
    void ReadHeader();
};


class PublicKey {
    const byte* key_;
    size_t      sz_;
public:
    PublicKey(const byte* k, size_t s) : key_(k), sz_(s) {}
    PublicKey() : key_(0), sz_(0) {}

    const byte* GetKey() const { return key_; }
    size_t      size()   const { return sz_; }

    void SetKey(const byte* k) { key_ = k; }
    void SetSize(size_t s) { sz_ = s; }
};


class CertDecoder : public BER_Decoder {
public:
    explicit CertDecoder(Sink& s) : BER_Decoder(s) { Decode(); }
    PublicKey& GetPublicKey() { return key_; }
private:
    PublicKey key_;

    void ReadHeader();
    void Decode();
    void SetPublicKey();
    void StoreSequence();
    void GetAlgoId();
    void GetName();
    void GetValidity();
};



} // namespace


#endif // TAO_CRYPT_ASN_HPP__
