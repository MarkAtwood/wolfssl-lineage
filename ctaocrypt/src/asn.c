/* asn.c
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


#include "asn.h"
#include "sha.h"
#include "md5.h"
#include "error.h"
#include <time.h> 
#include <assert.h>


#define NO_DH   /* remove for now */
#define NO_DSA  /* remove for now */


enum {
    ISSUER  = 0,
    SUBJECT = 1,

    BEFORE  = 0,
    AFTER   = 1
};


int GetLength(const byte* input, word32* inOutIdx, int* len)
{
    int     length = 0;
    word32  i = *inOutIdx;

    byte b = input[i++];
    if (b >= ASN_LONG_LENGTH) {        
        word32 bytes = b & 0x7F;

        while (bytes--) {
            b = input[i++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;
    
    *inOutIdx = i;
    *len      = length;

    return length;
}


int GetSequence(const byte* input, word32* inOutIdx, int* len)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


int GetSet(const byte* input, word32* inOutIdx, int* len)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SET | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


int GetVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}


/* May not have one, not an error */
int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    if (input[idx++] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetVersion(input, inOutIdx, version);
    }

    /* go back as is */
    *version = 0;

    return 0;
}


int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx )
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    mp_init(mpi); 
    if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

    *inOutIdx = i + length;
    return 0;
}


int RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    int    version, length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetInt(&key->n,  input, inOutIdx) < 0 ||
        GetInt(&key->e,  input, inOutIdx) < 0 ||
        GetInt(&key->d,  input, inOutIdx) < 0 ||
        GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx) < 0 ||
        GetInt(&key->dP, input, inOutIdx) < 0 ||
        GetInt(&key->dQ, input, inOutIdx) < 0 ||
        GetInt(&key->u,  input, inOutIdx) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}


int RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    key->type = RSA_PUBLIC;

    if (GetInt(&key->n,  input, inOutIdx) < 0 ||
        GetInt(&key->e,  input, inOutIdx) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}


#ifndef NO_DH

int DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx) < 0 )  return ASN_DH_KEY_E;

    return 0;
}

#endif /* NO_DH */


#ifndef NO_DSA

int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx) < 0 ||
        GetInt(&key->y,  input, inOutIdx) < 0 )  return ASN_DH_KEY_E;

    return 0;
}


int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length, version;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx) < 0 ||
        GetInt(&key->y,  input, inOutIdx) < 0 ||
        GetInt(&key->x,  input, inOutIdx) < 0 )  return ASN_DH_KEY_E;

    return 0;
}

#endif /* NO_DSA */


void InitDecodedCert(DecodedCert* cert, byte* source)
{
    cert->publicKey = 0;
    cert->signature = 0;
    cert->issuer    = 0;
    cert->subject   = 0;
    cert->source    = source;  /* don't own */
    cert->srcIdx    = 0;
}


void FreeDecodedCert(DecodedCert* cert)
{
    free(cert->subject);
    free(cert->issuer);
    free(cert->signature);
    free(cert->publicKey);
}


static int GetCertHeader(DecodedCert* cert, word32 inSz)
{
    int    ret = 0, version, len;
    word32 begin = cert->srcIdx;
    mp_int mpi;

    if (GetSequence(cert->source, &cert->srcIdx, &len) < 0)
        return ASN_PARSE_E;

    if ((word32)len > (inSz - (cert->srcIdx - begin))) return ASN_INPUT_E;

    cert->certBegin = cert->srcIdx;

    GetSequence(cert->source, &cert->srcIdx, &len);
    cert->sigIndex = len + cert->srcIdx;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetInt(&mpi, cert->source, &cert->srcIdx) < 0) 
        ret = ASN_PARSE_E;

    mp_clear(&mpi);
    return ret;
}


static int GetAlgoId(DecodedCert* cert, word32* oid)
{
    int    length;
    byte   b;
    *oid = 0;

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;
    
    b = cert->source[cert->srcIdx++];
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;

    if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;
    
    while(length--)
        *oid += cert->source[cert->srcIdx++];
        /* just sum it up for now */

    if (*oid != SHAwDSA && *oid != DSAk) {
        b = cert->source[cert->srcIdx++];     /* should have NULL tag and 0 */

        if (b != ASN_TAG_NULL) 
            return ASN_TAG_NULL_E;

        b = cert->source[cert->srcIdx++];   
        if (b != 0) 
            return ASN_EXPECT_0_E;
    }
 
    return 0;
}


static int StoreKey(DecodedCert* cert)
{
    int    length;
    word32 read = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;
   
    read = cert->srcIdx - read;
    length += read;

    while (read--)
       cert->srcIdx--;

    cert->pubKeySize = length;
    if ( !(cert->publicKey = (byte*) malloc(length)) )
        return MEMORY_E;

    memcpy(cert->publicKey, cert->source + cert->srcIdx, length);
    cert->srcIdx += length;

    return 0;
}


static int GetKey(DecodedCert* cert)
{
    int length;

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;
    
    if (GetAlgoId(cert, &cert->keyOID) < 0)
        return ASN_PARSE_E;

    if (cert->keyOID == RSAk) {
        byte b = cert->source[cert->srcIdx++];
        if (b != ASN_BIT_STRING)
            return ASN_BITSTR_E;

        b = cert->source[cert->srcIdx++];  /* length, future */
        b = cert->source[cert->srcIdx++];
        
        while (b != 0)
            b = cert->source[cert->srcIdx++];
    }
    else if (cert->keyOID == DSAk )
        ;   /* do nothing */
    else
        return ASN_UNKNOWN_OID_E;
    
    return StoreKey(cert);
}


/* process NAME, either issuer or subject */
static int GetName(DecodedCert* cert, int nameType)
{
    Sha    sha;
    int    length;  /* length of all distinguished names */
    int    dummy;

    InitSha(&sha);

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    length += cert->srcIdx;

    while (cert->srcIdx < (word32)length) {
        byte   b;
        byte   joint[2];
        int    oidSz;

        if (GetSet(cert->source, &cert->srcIdx, &dummy) < 0)
            return ASN_PARSE_E;

        if (GetSequence(cert->source, &cert->srcIdx, &dummy) < 0)
            return ASN_PARSE_E;

        b = cert->source[cert->srcIdx++];
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;

        if (GetLength(cert->source, &cert->srcIdx, &oidSz) < 0)
            return ASN_PARSE_E;

        memcpy(joint, &cert->source[cert->srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            byte   id;
            int    strLen;

            cert->srcIdx += 2;
            id = cert->source[cert->srcIdx++]; 
            b  = cert->source[cert->srcIdx++];    /* strType */

            if (GetLength(cert->source, &cert->srcIdx, &strLen) < 0)
                return ASN_PARSE_E;

            if (id == ASN_COMMON_NAME) {
                char** pp = (nameType == ISSUER) ? 
                    &cert->issuer : &cert->subject;
                *pp = (char*) malloc(strLen + 1);
                if (!*pp)
                    return MEMORY_E;
                memcpy(*pp, &cert->source[cert->srcIdx], strLen);
                (*pp)[strLen] = 0;
            }
            ShaUpdate(&sha, &cert->source[cert->srcIdx], strLen);
            cert->srcIdx += strLen;
        }
        else {
            /* skip */
            int adv;
            cert->srcIdx += oidSz + 1;

            if (GetLength(cert->source, &cert->srcIdx, &adv) < 0)
                return ASN_PARSE_E;

            cert->srcIdx += adv;
        }
    }
    if (nameType == ISSUER)
        ShaFinal(&sha, cert->issuerHash);
    else
        ShaFinal(&sha, cert->subjectHash);

    return 0;
}


/* to the minute */
static int DateGreaterThan(const struct tm* a, const struct tm* b)
{
    if (a->tm_year > b->tm_year)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon > b->tm_mon)
        return 1;
    
    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
           a->tm_mday > b->tm_mday)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour > b->tm_hour)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min > b->tm_min)
        return 1;

    return 0; /* false */
}


static INLINE int DateLessThan(const struct tm* a, const struct tm* b)
{
    return !DateGreaterThan(a,b);
}


/* like atoi but only use first byte */
static INLINE word32 btoi(byte b)
{
    return b - 0x30;
}


/* two byte date/time, add to value */
static INLINE void GetTime(int* value, const byte* date, int* idx)
{
    int i = *idx;

    *value += btoi(date[i++]) * 10;
    *value += btoi(date[i++]);

    *idx = i;
}


/* Make sure before and after dates are valid */
static int ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime = time(0);
    struct tm  certTime;
    struct tm* localTime;
    int    i = 0;

    memset(&certTime, 0, sizeof(certTime));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime.tm_year = 1900;
        else
            certTime.tm_year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        certTime.tm_year += btoi(date[i++]) * 1000;
        certTime.tm_year += btoi(date[i++]) * 100;
    }

    GetTime(&certTime.tm_year, date, &i); certTime.tm_year -= 1900; /* adjust */
    GetTime(&certTime.tm_mon,  date, &i); certTime.tm_mon  -= 1;    /* adjust */
    GetTime(&certTime.tm_mday, date, &i);
    GetTime(&certTime.tm_hour, date, &i); 
    GetTime(&certTime.tm_min,  date, &i); 
    GetTime(&certTime.tm_sec,  date, &i); 

    assert(date[i] == 'Z');     /* only Zulu supported for this profile */

    localTime = gmtime(&ltime);

    if (dateType == BEFORE) {
        if (DateLessThan(localTime, &certTime))
            return 0;
    }
    else
        if (DateGreaterThan(localTime, &certTime))
            return 0;

    return 1;
}


static int GetDate(DecodedCert* cert, int dateType)
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b = cert->source[cert->srcIdx++];

    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    memcpy(date, &cert->source[cert->srcIdx], length);
    cert->srcIdx += length;

    if (!ValidateDate(date, b, dateType)) {
        if (dateType == BEFORE)
            return ASN_BEFORE_DATE_E;
        else
            return ASN_AFTER_DATE_E;
    }

    return 0;
}


static int GetValidity(DecodedCert* cert, int verify)
{
    int length;

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    if (GetDate(cert, BEFORE) < 0 && verify)
        return ASN_BEFORE_DATE_E;
    
    if (GetDate(cert, AFTER) < 0 && verify)
        return ASN_AFTER_DATE_E;
    
    return 0;
}


static int DecodeToKey(DecodedCert* cert, word32 inSz, int verify)
{
    int ret;

    if ( (ret = GetCertHeader(cert, inSz)) < 0)
        return ret;

    if ( (ret = GetAlgoId(cert, &cert->signatureOID)) < 0)
        return ret;

    if ( (ret = GetName(cert, ISSUER)) < 0)
        return ret;

    if ( (ret = GetValidity(cert, verify)) < 0)
        return ret;

    if ( (ret = GetName(cert, SUBJECT)) < 0)
        return ret;

    if ( (ret = GetKey(cert)) < 0)
        return ret;

    return ret;
}


static int GetSignature(DecodedCert* cert)
{
    int    length;
    byte   b = cert->source[cert->srcIdx++];

    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    cert->sigLength = length;

    b = cert->source[cert->srcIdx++];
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    cert->sigLength--;

    cert->signature = (byte*) malloc(cert->sigLength);
    if (!cert->signature)
        return MEMORY_E;
    
    memcpy(cert->signature, &cert->source[cert->srcIdx], cert->sigLength);
    cert->srcIdx += cert->sigLength;

    return 0;
}


static word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = digSz;
    memcpy(&output[2], digest, digSz);

    return digSz + 2;
} 


static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> (i - 1) * 8)
            break;

    return i;
}


static word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = length;
    else {
        output[i++] = BytePrecision(length) | ASN_LONG_LENGTH;
      
        for (j = BytePrecision(length); j; --j) {
            output[i] = length >> (j - 1) * 8;
            i++;
        }
    }

    return i;
}


static word32 SetSequence(word32 len, byte* output)
{
    output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}


static word32 SetAlgoID(int algoOID, byte* output)
{
    /* adding TAG_NULL and 0 to end */
    static const byte shaAlgoID[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                                      0x05, 0x00 };
    static const byte md5AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x02, 0x05, 0x05, 0x00  };
    static const byte md2AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x02, 0x02, 0x05, 0x00};

    int    algoSz = 0;
    word32 idSz, seqSz;
    const  byte* algoName = 0;
    byte ID_Length[MAX_LENGTH_SZ];
    byte seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

    switch (algoOID) {
    case SHAh:
        algoSz = sizeof(shaAlgoID);
        algoName = shaAlgoID;
        break;

    case MD2h:
        algoSz = sizeof(md2AlgoID);
        algoName = md2AlgoID;
        break;

    case MD5h:
        algoSz = sizeof(md5AlgoID);
        algoName = md5AlgoID;
        break;

    default:
        return 0;  /* UNKOWN_HASH_E; */
    }


    idSz  = SetLength(algoSz - 2, ID_Length); /* don't include TAG_NULL/0 */
    seqSz = SetSequence(idSz + algoSz + 1, seqArray);
    seqArray[seqSz++] = ASN_OBJECT_ID;

    memcpy(output, seqArray, seqSz);
    memcpy(output + seqSz, ID_Length, idSz);
    memcpy(output + seqSz + idSz, algoName, algoSz);

    return seqSz + idSz + algoSz;

}


static word32 EncodeSignature(byte* out, const byte* digest, word32 digSz,
                              int hashOID)
{
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word32 encDigSz, algoSz, seqSz; 

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    memcpy(out, seqArray, seqSz);
    memcpy(out + seqSz, algoArray, algoSz);
    memcpy(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
}
                           

/* return true (1) for Confirmation */
static int ConfirmSignature(DecodedCert* cert, const byte* key, word32 keySz)
{
    byte digest[SHA_DIGEST_SIZE]; /* max size */
    int  hashType, digestSz, ret;

    if (cert->signatureOID == MD5wRSA) {
        Md5 md5;
        InitMd5(&md5);
        Md5Update(&md5, cert->source + cert->certBegin,
                  cert->sigIndex - cert->certBegin);
        Md5Final(&md5, digest);
        hashType = MD5h;
        digestSz = MD5_DIGEST_SIZE;
    }
    else if (cert->signatureOID == SHAwRSA || cert->signatureOID == SHAwDSA) {
        Sha sha;
        InitSha(&sha);
        ShaUpdate(&sha, cert->source + cert->certBegin,
                  cert->sigIndex - cert->certBegin);
        ShaFinal(&sha, digest);
        hashType = SHAh;
        digestSz = SHA_DIGEST_SIZE;
    }
    else
        return 0; /* ASN_SIG_HASH_E; */

    if (cert->keyOID == RSAk) {
        RsaKey pubKey;
        byte   encodedSig[MAX_ENCODED_SIG_SZ];
        byte   plain[MAX_SIG_SZ];
        word32 idx = 0;
        int    sigSz, verifySz;

        InitRsaKey(&pubKey);
        if (RsaPublicKeyDecode(key, &idx, &pubKey, keySz) < 0)
            return 0; /* ASN_KEY_DECODE_E; */

        sigSz = EncodeSignature(encodedSig, digest, digestSz, hashType);
        
        if ( (verifySz = RsaSSL_Verify(cert->signature, cert->sigLength, plain,
                                       sizeof(plain), &pubKey)) < 0)
            ret = 0; /* ASN_VERIFY_E; */
        else {
            /* make sure we're right justified */
            if (sigSz != verifySz || memcmp(plain, encodedSig, sigSz) != 0)
                ret = 0; /* ASN_VERIFY_MATCH_E; */
            else
                ret = 1; /* match */
        }
        FreeRsaKey(&pubKey);
        return ret;
    }
    else
        return 0; /* ASN_SIG_KEY_E; */

    return 0;  /* not confirmed */
}


int ParseCert(DecodedCert* cert, word32 inSz, int type, int verify,
              Signer* signers)
{
    word32 confirmOID;
    int    ret;
    int    confirm = 0;

    if ((ret = DecodeToKey(cert, inSz, verify)) < 0)
        return ret;

    if (cert->srcIdx != cert->sigIndex)
        cert->srcIdx =  cert->sigIndex;

    if ((ret = GetAlgoId(cert, &confirmOID)) < 0)
        return ret;

    if ((ret = GetSignature(cert)) < 0)
        return ret;

    if (confirmOID != cert->signatureOID)
        return ASN_SIG_OID_E;

    if (verify && type != CA_TYPE) {
        while (signers) {
            if (memcmp(cert->issuerHash, signers->hash, SHA_DIGEST_SIZE)
                       == 0) {
                /* other confirm */
                if (!ConfirmSignature(cert, signers->publicKey,
                                      signers->pubKeySize))
                    return ASN_SIG_CONFIRM_E;
                else {
                    confirm = 1;
                    break;
                }
            }
            signers = signers->next;
        }
        if (!confirm)
            return ASN_SIG_CONFIRM_E;
    }

    return 0;
}


Signer* MakeSigner(void)
{
    Signer* signer = (Signer*) malloc(sizeof(Signer));
    if (signer) {
        signer->name      = 0;
        signer->publicKey = 0;
        signer->next      = 0;
    }

    return signer;
}


void FreeSigners(Signer* signer)
{
    Signer* next = signer;

    while( (signer = next) ) {
        next = signer->next;
        free(signer->name);
        free(signer->publicKey);
        free(signer);
    }
}


