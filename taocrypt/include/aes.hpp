/* aes.hpp                                
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

/* aes.hpp defines AES
*/


#ifndef TAO_CRYPT_AES_HPP
#define TAO_CRYPT_AES_HPP

#include "misc.hpp"
#include "modes.hpp"

namespace TaoCrypt {


enum { AES_BLOCK_SIZE = 16 };


// AES encryption and decryption, see FIPS-197
class AES {
public:
    enum { BLOCK_SIZE = AES_BLOCK_SIZE };

    AES(CipherDir DIR, Mode MODE) : dir_(DIR), mode_(MODE) {}

    void Process(byte*, const byte*, word32);
    void SetKey(const byte* key, word32 sz, CipherDir fake = ENCRYPTION);
    void SetIV(const byte* iv) { memcpy(r_, iv, BLOCK_SIZE); }
private:
    CipherDir dir_;
    Mode      mode_;

    static const word32 rcon_[];

    word32      rounds_;
    word32      key_[60];                        // max size
    word32      r_[BLOCK_SIZE / sizeof(word32)]; // for CBC mode

    void encrypt(const byte*, const byte*, byte*) const;
    void AsmEncrypt(const byte*, byte*) const;
    void decrypt(const byte*, const byte*, byte*) const;
    void AsmDecrypt(const byte*, byte*) const;

    AES(const AES&);            // hide copy
    AES& operator=(const AES&); // and assign
};


typedef BlockCipher<ENCRYPTION, AES, ECB> AES_ECB_Encryption;
typedef BlockCipher<DECRYPTION, AES, ECB> AES_ECB_Decryption;

typedef BlockCipher<ENCRYPTION, AES, CBC> AES_CBC_Encryption;
typedef BlockCipher<DECRYPTION, AES, CBC> AES_CBC_Decryption;



#ifndef __CYGWIN__                  // for special linkage and prefix
    extern const word32 lTe0[256];
    extern const word32 lTe1[256];
    extern const word32 lTe2[256];
    extern const word32 lTe3[256];
    extern const word32 lTe4[256];

    extern const word32 lTd0[256];
    extern const word32 lTd1[256];
    extern const word32 lTd2[256];
    extern const word32 lTd3[256];
    extern const word32 lTd4[256];
#else
    extern "C" const word32 lTe0[256];
    extern "C" const word32 lTe1[256];
    extern "C" const word32 lTe2[256];
    extern "C" const word32 lTe3[256];
    extern "C" const word32 lTe4[256];

    extern "C" const word32 lTd0[256];
    extern "C" const word32 lTd1[256];
    extern "C" const word32 lTd2[256];
    extern "C" const word32 lTd3[256];
    extern "C" const word32 lTd4[256];
#endif



} // naemspace

#endif // TAO_CRYPT_AES_HPP
