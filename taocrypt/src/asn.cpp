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

/* based on Wei Dai's asn.cpp from CryptoPP */

#include "asn.hpp"
#include "file.hpp"
#include "integer.hpp"
#include "rsa.hpp"
#include "dh.hpp"


namespace TaoCrypt {


Integer& BER_Decoder::GetInteger(Integer& integer)
{
    integer.Decode(sink_);
    return integer;
}

class BadHeader {};

word32 BER_Decoder::GetSequence()
{
    word32 length(0);

    byte b = sink_.next();
    if (b != (SEQUENCE | CONSTRUCTED)) throw BadHeader();

    b = sink_.next();
    if (b >= LONG_LENGTH) {        
        word32 bytes = b & 0x7F;

        while (bytes--) {
            b = sink_.next();
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    return length;
}


word32 BER_Decoder::GetVersion()
{
    word32 version(0);

    byte b = sink_.next();
    if (b != INTEGER) throw BadHeader();

    b = sink_.next();
    if (b != 0x01) throw BadHeader();  // version length not 1

    return version = sink_.next();
}


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


void DH_Decoder::Decode(DH& key)
{
    ReadHeader();

    // group parms
    key.SetP(GetInteger(Integer().Ref()));
    key.SetG(GetInteger(Integer().Ref()));
}


void CertDecoder::ReadHeader()
{
    GetSequence();  // total
    GetSequence();  // this cert
    GetExplicitVersion(); // version
    GetVersion();         // serial number
}


void CertDecoder::Decode()
{
    ReadHeader();
    GetAlgoId();
    GetName();      // issuer
    GetValidity();
    GetName();      // subject

    SetPublicKey();
}


void CertDecoder::SetPublicKey()
{
    GetSequence();    
    GetAlgoId();

    byte b = sink_.next();
    if (b != BIT_STRING) throw BadHeader();
    b = sink_.next();      // length, future
    b = sink_.next(); 
    while(b != 0)
        b = sink_.next();

    StoreSequence();
}


void CertDecoder::StoreSequence()
{
    word32 read(0);
    word32 length(0);

    byte b = sink_.next();
    ++read;
    if (b != (SEQUENCE | CONSTRUCTED)) throw BadHeader();

    b = sink_.next();
    ++read;
    if (b >= LONG_LENGTH) {        
        word32 bytes = b & 0x7F;

        while (bytes--) {
            b = sink_.next();
            ++read;
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    length += read;
    while (read--) sink_.prev();

    key_.SetSize(length);
    key_.SetKey(sink_.get_current());
    sink_.prev();
}


void CertDecoder::GetAlgoId()
{
    sink_.advance(GetSequence());
}


void CertDecoder::GetName()
{
    sink_.advance(GetSequence());
}


void CertDecoder::GetValidity()
{
    sink_.advance(GetSequence());
}



} // namespace
