/* dh.cpp                                
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




#include "dh.hpp"
#include "asn.hpp"
#include <cmath>

namespace TaoCrypt {


void DH::GenerateKeyPair(RandomNumberGenerator& rng, byte* priv, byte* pub)
{
    GeneratePrivate(rng, priv);
    GeneratePublic(rng, priv, pub);
}


void DH::GeneratePrivate(RandomNumberGenerator& rng, byte* priv)
{
    Integer x(rng, Integer::One(), p_ - 1);
    x.Encode(priv, p_.ByteCount());
}


void DH::GeneratePublic(RandomNumberGenerator& rng, const byte* priv,
                        byte* pub)
{
    const size_t bc(p_.ByteCount());
    Integer x(priv, bc);
    Integer y(a_exp_b_mod_c(g_, x, p_));
    y.Encode(pub, bc);
}


void DH::Agree(byte* agree, const byte* priv, const byte* otherPub)
{
    const size_t bc(p_.ByteCount());
    Integer x(priv, bc);
    Integer y(otherPub, bc);

    Integer z(a_exp_b_mod_c(y, x, p_));
    z.Encode(agree, bc);
}


DH::DH(Sink& sink)
{
    Initialize(sink);
}


void DH::Initialize(Sink& sink)
{
    DH_Decoder decoder(sink);
    decoder.Decode(*this);
}


} // namespace
