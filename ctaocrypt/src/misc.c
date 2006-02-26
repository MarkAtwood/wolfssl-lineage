/* misc.c
 *
 * Copyright (C) 2006 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#include "types.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>



#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */



#ifdef INTEL_INTRINSICS

    #pragma intrinsic(_lrotl, _lrotr)

    static INLINE word32 rotlFixed(word32 x, word32 y)
    {
        assert(y < 32);
        return y ? _lrotl(x, y) : x;
    }

    static INLINE word32 rotrFixed(word32 x, word32 y)
    {
        assert(y < 32);
        return y ? _lrotr(x, y) : x;
    }

#else /* generic */

    static INLINE word32 rotlFixed(word32 x, word32 y)
    {
        assert(y < 32);
        return (x << y) | (x >> (sizeof(y) * 8 - y));
    }   


    static INLINE word32 rotrFixed(word32 x, word32 y)
    {
        assert(y < 32);
        return (x >> y) | (x << (sizeof(y) * 8 - y));
    }

#endif


static INLINE word32 ByteReverseWord32(word32 value)
{
#ifdef PPC_INTRINSICS
    /* PPC: load reverse indexed instruction */
    return (word32)__lwbrx(&value,0);
#elif defined(FAST_ROTATE)
    /* 5 instructions with rotate instruction, 9 without */
    return (rotrFixed(value, 8U) & 0xff00ff00) |
           (rotlFixed(value, 8U) & 0x00ff00ff);
#else
    /* 6 instructions with rotate instruction, 8 without */
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return rotlFixed(value, 16U);
#endif
}


static INLINE void ByteReverseWords(word32* out, const word32* in,
                                    word32 byteCount)
{
    word32 count = byteCount/sizeof(word32), i;

    assert(byteCount % sizeof(word32) == 0);

    for (i = 0; i < count; i++)
        out[i] = ByteReverseWord32(in[i]);

}


static INLINE void ByteReverseBytes(byte* out, const byte* in, word32 byteCount)
{
    word32* op       = (word32*)out;
    const word32* ip = (const word32*)in;

    ByteReverseWords(op, ip, byteCount);
}


static INLINE void XorWords(word* r, const word* a, word32 n)
{
    word32 i;

    for (i = 0; i < n; i++) r[i] ^= a[i];
}


static INLINE void xorbuf(byte* buf, const byte* mask, word32 count)
{
    if (((size_t)buf | (size_t)mask | count) % WORD_SIZE == 0)
        XorWords( (word*)buf, (const word*)mask, count / WORD_SIZE);
    else {
        word32 i;
        for (i = 0; i < count; i++) buf[i] ^= mask[i];
    }
}

