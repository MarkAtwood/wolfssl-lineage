/* random.hpp                                
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



#ifndef TAO_CRYPT_RANDOM_HPP__
#define TAO_CRYPT_RANDOM_HPP__

#include "arc4.hpp"

namespace TaoCrypt {


#if defined(WIN32)

// Windows
class OS_Seed  {
public:
    OS_Seed();
    ~OS_Seed();

    void GenerateSeed(byte*, size_t sz);

#if defined(_WIN64)
    typedef unsigned __int64 ProviderHandle;
    // type HCRYPTPROV, avoid #include <windows.h>
#else
    typedef unsigned long ProviderHandle;
#endif

private:
    ProviderHandle handle_;

    OS_Seed(const OS_Seed&);            // hide copy
    OS_Seed& operator=(const OS_Seed&); // hide assign
};


#else // WIN32

// UNIX
class OS_Seed {
public:
    OS_Seed();
    ~OS_Seed();

    void GenerateSeed(byte*, size_t sz);
private:
    int fd_;

    OS_Seed(const OS_Seed&);              // hide copy
    OS_Seed& operator=(const OS_Seed&);   // hide assign
};

#endif // WIN32


class RandomNumberGenerator {
public:
    RandomNumberGenerator();
    ~RandomNumberGenerator() {}

    void GenerateBlock(byte*, size_t sz);
    byte GenerateByte();
private:
    OS_Seed seed_;
    ARC4    cipher_;

    RandomNumberGenerator(const RandomNumberGenerator&);           // hide copy
    RandomNumberGenerator operator=(const RandomNumberGenerator&); // && assign
};




}  // namespace

#endif // TAO_CRYPT_RANDOM_HPP__

