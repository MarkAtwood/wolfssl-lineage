/* coding.cpp                                
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


#include "coding.hpp"
#include "file.hpp"


namespace TaoCrypt {

byte GetAlpha(byte b)
{
    return b - 7;   
}

byte GetHex(byte b, byte b2)
{
    if (b < 0x10 && b2 < 0x10)
        return (b << 4) | b2;
    else if (b > 0x9 && b2 > 0x9)
        return (GetAlpha(b) << 4) | GetAlpha(b2);
    else if (b2 > 0x9)
        return (b << 4) | GetAlpha(b2);
    else
        return (GetAlpha(b) << 4) | b2;
}

void HexDecoder::Decode()
{
    size_t bytes = coded_.size();
    decoded_.New(bytes / 2);
    size_t i(0);

    while (bytes) {
        byte b  = coded_.next() - 0x30;
        byte b2 = coded_.next() - 0x30;
        decoded_[i++] = GetHex(b, b2);
        bytes -= 2;
    }

    coded_.reset(decoded_);
}

} // namespace
