/* cert_wrapper.hpp                          
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


/*  The certificate wrapper header defines certificate management functions
 *
 */


#ifndef yaSSL_CERT_WRAPPER_HPP
#define yaSSL_CERT_WRAPPER_HPP

#ifdef _MSC_VER
    // disable truncated debug symbols
    #pragma warning(disable:4786)
#endif

#include "yassl_types.hpp"  // x509
#include "buffer.hpp"       // input_buffer
#include <list>             // std::list
#include <algorithm>        // std::for_each


namespace yaSSL {


// Certificate Manager keeps a list of thhe cert chain and public key
class CertManager {
    std::list<x509*> list_;
    input_buffer     publicKey_;
    input_buffer     privateKey_;       // if server or client auth
public:
    CertManager() {}
    ~CertManager() 
    {
        std::for_each(list_.begin(), list_.end(), del_ptr_zero()) ;
    }

    void AddCert(x509* x) { list_.push_back(x); }  // take ownership
    void CopyCert(const x509* x) { if (x) list_.push_back(new x509(*x)); }
    bool Validate() const;

    void SetKey();
    void SetPrivateKey(const x509&);

    const x509*   get_cert()       const { return list_.front(); }
    const opaque* get_Key()        const { return publicKey_.get_buffer(); }
    const opaque* get_privateKey() const { return privateKey_.get_buffer(); }

    uint get_KeyLength()           const { return publicKey_.get_size(); }
    uint get_privateKeyLength()    const { return privateKey_.get_size(); }
private:
    CertManager(const CertManager&);            // hide copy
    CertManager& operator=(const CertManager&); // and assign
};


} // naemspace

#endif // yaSSL_CERT_WRAPPER_HPP
