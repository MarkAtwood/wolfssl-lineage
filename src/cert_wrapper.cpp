/* cert_wrapper.cpp                          
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


/*  The certificate wrapper source implements certificate management functions
 *
 */


#include "cert_wrapper.hpp"

#if defined(USE_CML_LIB)
    #include "cmapi_cpp.h"
#else
    #include "asn.hpp"
    #include "file.hpp"
#endif // USE_CML_LIB


namespace yaSSL {


x509::x509(const x509& that) : length_(that.length_),
                               buffer_(new opaque[length_])
{
    memcpy(buffer_, that.buffer_, length_);
}


void x509::Swap(x509& that)
{
    std::swap(length_, that.length_);
    std::swap(buffer_, that.buffer_);
}


x509& x509::operator=(const x509& that)
{
    x509 temp(that);
    Swap(temp);
    return *this;
}


#if defined(USE_CML_LIB)

// Get the peer's certificate, extract and save public key
void CertManager::SetKey()
{
    // first cert is the peer's
    x509* main = list_.front();

    Bytes_struct cert;
    cert.num  = main->get_length();
    cert.data = main->set_buffer();

    CML::Certificate cm(cert);
    const CML::ASN::Cert& raw = cm.base();
    CTIL::CSM_Buffer key = raw.pubKeyInfo.key;

    uint sz;
    opaque* key_buffer = reinterpret_cast<opaque*>(key.Get(sz));
    publicKey_.allocate(sz);
    publicKey_.assign(key_buffer, sz);
}

#else // USE_CML_LIB

// Get the peer's certificate, extract and save public key
void CertManager::SetKey()
{
    // first cert is the peer's
    x509* main = list_.front();
    TaoCrypt::Sink sink(main->get_buffer(), main->get_length());
    TaoCrypt::CertDecoder cert(sink);

    uint sz = cert.GetPublicKey().size();
    publicKey_.allocate(sz);
    publicKey_.assign(cert.GetPublicKey().GetKey(), sz);
}

#endif // USE_CML_LIB

// Validate the peer's certificate list
bool CertManager::Validate() const
{
    bool valid = false;

    return valid;
}


// Set the private key
void CertManager::SetPrivateKey(const x509& key)
{
    privateKey_.allocate(key.get_length());
    privateKey_.assign(key.get_buffer(), key.get_length());
}


} // namespace
