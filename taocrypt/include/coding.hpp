/* coding.hpp                                
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


#ifndef TAO_CRYPT_CODING_HPP__
#define TAO_CRYPT_CODING_HPP__

#include "misc.hpp"
#include "block.hpp"

namespace TaoCrypt {

class Sink;

class HexEncoder {


};


class HexDecoder {
    ByteBlock decoded_;
    Sink&     coded_;
public:
    explicit HexDecoder(Sink& s) : coded_(s) { Decode(); }
private:
    void Decode();

    HexDecoder(const HexDecoder&);              // hide copy
    HexDecoder& operator=(const HexDecoder&);   // and assign
};


class Base64Encoder {



};


class Base64Decoder {




};


}  // namespace

#endif // TAO_CRYPT_CODING_HPP__
