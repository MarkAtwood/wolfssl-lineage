/* modes.hpp                                
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



#ifndef TAO_CRYPT_MODES_HPP__
#define TAO_CRYPT_MODES_HPP__

#include <string.h>
#include "misc.hpp"

namespace TaoCrypt {


enum Mode { ECB, CBC };

template<CipherDir DIR, class T, Mode MODE>
class BlockCipher {
public:
    BlockCipher() : cipher_(DIR, MODE) {}

    void Process(byte* c, const byte* p, size_t sz) 
            { cipher_.Process(c, p, sz); }
    void SetKey(const byte* k, size_t sz)   
            { cipher_.SetKey(k, sz, DIR); }
    void SetKey(const byte* k, size_t sz, const byte* iv)   
            { cipher_.SetKey(k, sz, DIR); cipher_.SetIV(iv); }
private:
    T cipher_;
};


template<int BLOCK_SIZE>
class Mode_BASE {
public:
    virtual void ProcessAndXorBlock(const byte*, const byte*, byte*) const = 0;

    void ECB_Process(byte*, const byte*, size_t);
    void CBC_Encrypt(byte*, const byte*, size_t);
    void CBC_Decrypt(byte*, const byte*, size_t);

    void SetIV(const byte* iv) { memcpy(reg_, iv, BLOCK_SIZE); }
protected:
    byte reg_[BLOCK_SIZE];
    byte tmp_[BLOCK_SIZE];
};


template<int BLOCK_SIZE>
void Mode_BASE<BLOCK_SIZE>::ECB_Process(byte* out, const byte* in, size_t sz)
{
    size_t blocks = sz / BLOCK_SIZE;

    while (blocks--) {
        ProcessAndXorBlock(in, 0, out);
        out += BLOCK_SIZE;
        in  += BLOCK_SIZE;
    }
}


template<int BLOCK_SIZE>
void Mode_BASE<BLOCK_SIZE>::CBC_Encrypt(byte* out, const byte* in, size_t sz)
{
    size_t blocks = sz / BLOCK_SIZE;

    while (blocks--) {
        xorbuf(reg_, in, BLOCK_SIZE);
        ProcessAndXorBlock(reg_, 0, reg_);
        memcpy(out, reg_, BLOCK_SIZE);
        out += BLOCK_SIZE;
        in  += BLOCK_SIZE;
    }
}


template<int BLOCK_SIZE>
void Mode_BASE<BLOCK_SIZE>::CBC_Decrypt(byte* out, const byte* in, size_t sz)
{
    size_t blocks = sz / BLOCK_SIZE;
    byte   hold[BLOCK_SIZE];

    while (blocks--) {
        memcpy(tmp_, in, BLOCK_SIZE);
        ProcessAndXorBlock(tmp_, 0, out);
        xorbuf(out,  reg_, BLOCK_SIZE);
        memcpy(hold, reg_,   BLOCK_SIZE); // swap reg_ and tmp_
        memcpy(reg_,   tmp_, BLOCK_SIZE);
        memcpy(tmp_, hold, BLOCK_SIZE);
        out += BLOCK_SIZE;
        in  += BLOCK_SIZE;
    }
}


} // namespace

#endif  // TAO_CRYPT_MODES_HPP__
