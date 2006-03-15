/* hmac.c
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


#include "hmac.h"
#include <assert.h>
#include <string.h>



static void InitHmac(Hmac* hmac, int type)
{
    hmac->innerHashKeyed = 0;
    hmac->macType = type;

    assert(type == MD5 || type == SHA);

    if (type == MD5)
        InitMd5(&hmac->hash.md5);
    else if (type == SHA)
        InitSha(&hmac->hash.sha);
}


void HmacSetKey(Hmac* hmac, int type, const byte* key, word32 length)
{
    byte*  ip = (byte*) hmac->ipad;
    byte*  op = (byte*) hmac->opad;
    word32 i;

    InitHmac(hmac, type);

    if (length <= HMAC_BLOCK_SIZE)
        memcpy(ip, key, length);
    else {
        if (hmac->macType == MD5) {
            Md5Update(&hmac->hash.md5, key, length);
            Md5Final(&hmac->hash.md5, ip);
            length = MD5_DIGEST_SIZE;
        }
        else /* SHA */ {
            ShaUpdate(&hmac->hash.sha, key, length);
            ShaFinal(&hmac->hash.sha, ip);
            length = SHA_DIGEST_SIZE;
        }
    }
    memset(ip + length, 0, HMAC_BLOCK_SIZE - length); 

    for(i = 0; i < HMAC_BLOCK_SIZE; i++) {
        op[i] = ip[i] ^ OPAD;
        ip[i] ^= IPAD;
    }
}


static void HmacKeyInnerHash(Hmac* hmac)
{
    if (hmac->macType == MD5)
        Md5Update(&hmac->hash.md5, (byte*) hmac->ipad, HMAC_BLOCK_SIZE);
    else
        ShaUpdate(&hmac->hash.sha, (byte*) hmac->ipad, HMAC_BLOCK_SIZE);

    hmac->innerHashKeyed = 1;
}


void HmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    if (!hmac->innerHashKeyed)
        HmacKeyInnerHash(hmac);

    if (hmac->macType == MD5)
        Md5Update(&hmac->hash.md5, msg, length);
    else
        ShaUpdate(&hmac->hash.sha, msg, length);
}


void HmacFinal(Hmac* hmac, byte* hash)
{
    if (!hmac->innerHashKeyed)
        HmacKeyInnerHash(hmac);

    if (hmac->macType == MD5) {
        Md5Final(&hmac->hash.md5, (byte*) hmac->innerHash);

        Md5Update(&hmac->hash.md5, (byte*) hmac->opad, HMAC_BLOCK_SIZE);
        Md5Update(&hmac->hash.md5, (byte*) hmac->innerHash, MD5_DIGEST_SIZE);

        Md5Final(&hmac->hash.md5, hash);
    }
    else {
        ShaFinal(&hmac->hash.sha, (byte*) hmac->innerHash);

        ShaUpdate(&hmac->hash.sha, (byte*) hmac->opad, HMAC_BLOCK_SIZE);
        ShaUpdate(&hmac->hash.sha, (byte*) hmac->innerHash, SHA_DIGEST_SIZE);

        ShaFinal(&hmac->hash.sha, hash);
    }
    hmac->innerHashKeyed = 0;
}



