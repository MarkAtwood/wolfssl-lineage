/* dh.hpp                                
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


#ifndef TAO_CRYPT_DH_HPP__
#define TAO_CRYPT_DH_HPP__

#include "misc.hpp"
#include "integer.hpp"

namespace TaoCrypt {


class Sink;


class DH {
public:
    DH() {}
    DH(Integer& p, Integer& g) : p_(p), g_(g) {}
    explicit DH(Sink&);

    DH(const DH& that) : p_(that.p_), g_(that.g_) {}
    DH& operator=(const DH& that) 
    {
        DH tmp(that);
        swap(tmp);
        return *this;
    }

    void swap(DH& other)
    {
        p_.swap(other.p_);
        g_.swap(other.g_);
    }

    void Initialize(Sink&);
    void Initialize(Integer& p, Integer& g)
    {
        SetP(p);
        SetG(g);
    }

    void GenerateKeyPair(RandomNumberGenerator&, byte*, byte*);
    void Agree(byte*, const byte*, const byte*);

    void SetP(const Integer& p) { p_ = p; }
    void SetG(const Integer& g) { g_ = g; }

    Integer& GetP() { return p_; }
    Integer& GetG() { return g_; }

    // for p and agree
    size_t GetByteLength() const { return p_.ByteCount(); }
private:
    // group parms
    Integer p_;
    Integer g_;

    void GeneratePrivate(RandomNumberGenerator&, byte*);
    void GeneratePublic(RandomNumberGenerator&, const byte*, byte*);    
};


} // namespace

#endif // TAO_CRYPT_DH_HPP__
