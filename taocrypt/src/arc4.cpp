/* arc4.cpp                                
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

/* based on Wei Dai's arc4.cpp from CryptoPP */

#include "arc4.hpp"


namespace TaoCrypt {

void ARC4::SetKey(const byte* key, size_t length)
{
    x_ = 1;
    y_ = 0;

    size_t i;

    for (i = 0; i < STATE_SIZE; i++)
        state_[i] = i;

    size_t keyIndex = 0, stateIndex = 0;

    for (i = 0; i < STATE_SIZE; i++) {
        size_t a = state_[i];
        stateIndex += key[keyIndex] + a;
        stateIndex &= 0xFF;
        state_[i] = state_[stateIndex];
        state_[stateIndex] = a;

        if (++keyIndex >= length)
            keyIndex = 0;
    }
}


template <class T>
static inline unsigned int MakeByte(T& x, T& y, byte* s)
{
    size_t a = s[x];
    y = (y+a) & 0xff;

    size_t b = s[y];
    s[x] = b;
    s[y] = a;
    x = (x+1) & 0xff;

    return s[(a+b) & 0xff];
}


void ARC4::Process(byte* out, const byte* in, size_t length)
{
    if (length == 0) return;

    byte *const s = state_;
    size_t x = x_;
    size_t y = y_;

    if (in == out)
        while (length--)
            *out++ ^= MakeByte(x, y, s);
    else
        while(length--)
            *out++ = *in++ ^ MakeByte(x, y, s);
    x_ = x;
    y_ = y;
}


}  // namespace
