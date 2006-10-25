/* cyassl_int.c
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



#include "cyassl_int.h"
#include "cyassl_error.h"
#include "asn.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef _WIN32
    #include <sys/time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <errno.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/ioctl.h>
#endif // _WIN32

#ifdef __sun
    #include <sys/filio.h>
#endif


#ifdef _WIN32
    const int SOCKET_EINVAL = WSAEINVAL;
    const int SOCKET_EWOULDBLOCK = WSAEWOULDBLOCK;
    const int SOCKET_EAGAIN = WSAEWOULDBLOCK;
#else
    const int SOCKET_EINVAL = EINVAL;
    const int SOCKET_EWOULDBLOCK = EWOULDBLOCK;
    const int SOCKET_EAGAIN = EAGAIN;

    SOCKET_T INVALID_SOCKET = -1;
#endif // _WIN32


#ifndef NO_CYASSL_CLIENT
    static int DoServerHello(SSL* ssl, const byte* input, word32*);
    static int DoCertificateRequest(SSL* ssl, const byte* input, word32*);
    static int DoServerKeyExchange(SSL* ssl, const byte* input, word32*);
#endif


#ifndef NO_CYASSL_SERVER
    static int DoClientHello(SSL* ssl, const byte* input, word32*, word32,
                             word32);
    static int ProcessOldClientHello(SSL*, const byte*, word32*, word32);
    static int DoClientKeyExchange(SSL* ssl, const byte* input, word32*);
#endif


static void Hmac(SSL* ssl, byte* digest, const byte* buffer, word32 sz,
                 int content, int verify);


void BuildTlsFinished(SSL* ssl, Hashes* hashes, const byte* sender);
int  DeriveTlsKeys(SSL* ssl);


#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


void InitSSL_Method(SSL_METHOD* method, ProtocolVersion pv)
{
    method->version    = pv;
    method->side       = CLIENT_END;
    method->verifyPeer = 0;
    method->verifyNone = 0;
    method->failNoCert = 0;
}


void InitSSL_Ctx(SSL_CTX* ctx, SSL_METHOD* method)
{
    ctx->method = method;
    ctx->certificate.buffer = 0;
    ctx->privateKey.buffer  = 0;

    ctx->caList = 0;
    InitSuites(&ctx->suites, method->version);

    ctx->verifyPeer = 0;
    ctx->verifyNone = 0;
    ctx->failNoCert = 0;
    ctx->sessionCacheOff = 0;  /* initially on */
}


void FreeSSL_Ctx(SSL_CTX* ctx)
{
    free(ctx->privateKey.buffer);
    free(ctx->certificate.buffer);
    free(ctx->method);

    FreeSigners(ctx->caList);
    
    free(ctx);
}


void InitSuites(Suites* suites, ProtocolVersion pv)
{
    word32 idx = 0;
    int    tls = pv.major == 3 && pv.minor == 1;
    (void)tls;  /* shut up compiler */

    suites->setSuites = 0;  /* user hasn't set yet */

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    if (tls) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    if (tls) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    suites->suites[idx++] = 0; 
    suites->suites[idx++] = SSL_RSA_WITH_RC4_128_SHA;
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    suites->suites[idx++] = 0; 
    suites->suites[idx++] = SSL_RSA_WITH_RC4_128_MD5;
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    suites->suites[idx++] = 0; 
    suites->suites[idx++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
#endif

    suites->suiteSz = idx;
}


int InitSSL(SSL* ssl, SSL_CTX* ctx)
{
    ssl->version = ctx->method->version;
    ssl->suites  = ctx->suites;
    ssl->socket  = INVALID_SOCKET;
   
    ssl->certificate.buffer   = 0;
    ssl->key.buffer           = 0;
    ssl->peerCert.buffer      = 0;
    ssl->peerKey.buffer       = 0;
    ssl->bufferedData.buffer  = 0;
    ssl->bufferedInput.buffer = 0;
    ssl->domainName.buffer    = 0;

    InitRng(&ssl->rng);
    InitMd5(&ssl->hashMd5);
    InitSha(&ssl->hashSha);

    ssl->side  = ctx->method->side;
    ssl->error = 0;

    ssl->serverState = NULL_STATE;
    ssl->clientState = NULL_STATE;

    ssl->keys.encryptionOn = 0;     /* initially off */
    ssl->sessionCacheOff = ctx->sessionCacheOff;

    ssl->verifyPeer = ctx->verifyPeer;
    ssl->verifyNone = ctx->verifyNone;
    ssl->failNoCert = ctx->failNoCert;
    
    ssl->resuming = 0;
    ssl->hmac = Hmac;    /* default to SSLv3 */
    ssl->tls  = 0;

    /* SSL_CTX still owns certificate, key, and caList buffers */
    ssl->certificate = ctx->certificate;
    ssl->key = ctx->privateKey;
    ssl->caList = ctx->caList;

    return 0;
}


void FreeSSL(SSL* ssl)
{
    free(ssl->domainName.buffer);
    free(ssl->bufferedInput.buffer);
    free(ssl->bufferedData.buffer);
    free(ssl->peerKey.buffer);
    free(ssl->peerCert.buffer);

    free(ssl);
}


ProtocolVersion MakeSSLv3()
{
    ProtocolVersion pv;
    pv.major = 3;
    pv.minor = 0;

    return pv;
}


static INLINE void c32to24(word32 in, word24 out)
{
    out[0] = (in >> 16) & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] =  in & 0xff;
}


/* convert 16 bit integer to opaque */
static void INLINE c16toa(word16 u16, byte* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}


/* convert 32 bit integer to opaque */
static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


/* convert a 24 bit integer into a 32 bit one */
static INLINE void c24to32(const word24 u24, word32* u32)
{
    *u32 = 0;
    *u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}


/* convert opaque to 16 bit integer */
static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = 0;
    *u16 = (c[0] << 8) | (c[1]);
}


#ifdef _WIN32

    timer_d Timer()
    {
        static int           init = 0;
        static LARGE_INTEGER freq;
        LARGE_INTEGER        count;
    
        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (double)count.QuadPart / freq.QuadPart;
    }


    word32 LowResTimer()
    {
        return (word32)Timer();
    }

#else /* _WIN32 */

    #include <sys/time.h>

    timer_d Timer()
    {
        struct timeval tv;
        gettimeofday(&tv, 0);

        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
    }


    word32 LowResTimer()
    {
        struct timeval tv;
        gettimeofday(&tv, 0);

        return tv.tv_sec; 
    }


#endif /* _WIN32 */


/* add output to md5 and sha handshake hashes, exclude record header */
static void HashOutput(SSL*ssl, const byte* output, int sz)
{
    const byte* buffer = output + RECORD_HEADER_SZ;
    sz -= RECORD_HEADER_SZ;

    Md5Update(&ssl->hashMd5, buffer, sz);
    ShaUpdate(&ssl->hashSha, buffer, sz);
}


/* add input to md5 and sha handshake hashes, include handshake header */
static void HashInput(SSL*ssl, const byte* input, int sz)
{
    const byte* buffer = input - HANDSHAKE_HEADER_SZ;
    sz += HANDSHAKE_HEADER_SZ;

    Md5Update(&ssl->hashMd5, buffer, sz);
    ShaUpdate(&ssl->hashSha, buffer, sz);
}


static INLINE int LastError()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}


static word32 Receive(SOCKET_T socket, byte* buf, word32 sz, int flags)
{
    int recvd;

    assert(socket != INVALID_SOCKET);
    recvd = recv(socket, (char *)buf, sz, flags);

    /* idea to seperate error from would block by arnetheduck@gmail.com */
    if (recvd == -1) {
        if (LastError() == SOCKET_EWOULDBLOCK || 
            LastError() == SOCKET_EAGAIN)
            return 0;
    }
    else if (recvd == 0)
        return (word32) -1;

    return recvd;
}


/* wait if blocking for input, return false(0) for error */
static int Wait(SOCKET_T socket)
{
    byte b;
    return Receive(socket, &b, 1, MSG_PEEK) != (word32) -1;
}


/* find out how much data is waiting */
static word32 GetReady(SOCKET_T socket)
{
    unsigned long ready = 0;

#ifdef _WIN32
    ioctlsocket(socket, FIONREAD, &ready);
#else
    ioctl(socket, FIONREAD, &ready);
#endif

    return ready;
}


/* Send tcp data in a loop if needed */
int Send(SOCKET_T socket, const byte* buf, int sz, int flags)
{
    const byte* pos = buf;
    const byte* end = pos + sz;

    assert(socket != INVALID_SOCKET);

    while (pos != end) {
        int sent = send(socket, (const char *)pos, (int)(end - pos), flags);

        if (sent == -1)
            return 0;

        pos += sent;
    }

    return sz;
}


static int GetRecordHeader(SSL* ssl, const byte* input, word32* inOutIdx,
                           RecordLayerHeader* rh)
{
    memcpy(rh, input + *inOutIdx, RECORD_HEADER_SZ);
    *inOutIdx += RECORD_HEADER_SZ;
    ato16(rh->length, &rh->size);

    return 0;
}


static int GetHandShakeHeader(SSL* ssl, const byte* input, word32* inOutIdx,
                              HandShakeHeader* hs)
{
    memcpy(hs, input + *inOutIdx, HANDSHAKE_HEADER_SZ);
    *inOutIdx += HANDSHAKE_HEADER_SZ;
    c24to32(hs->length, &hs->size);

    return 0;
}


/* fill with MD5 pad size since biggest required */
static const byte PAD1[PAD_MD5] = 
                              { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
                              };
static const byte PAD2[PAD_MD5] =
                              { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };

/* calculate MD5 hash for finished */
static void BuildMD5(SSL* ssl, Hashes* hashes, const byte* sender)
{
    byte md5_result[MD5_DIGEST_SIZE];
    byte md5_inner[SIZEOF_SENDER + SECRET_LEN + PAD_MD5];
    byte md5_outer[SECRET_LEN + PAD_MD5 + MD5_DIGEST_SIZE];

    /* make md5 inner */
    memcpy(md5_inner, sender, SIZEOF_SENDER);
    memcpy(&md5_inner[SIZEOF_SENDER], ssl->masterSecret, SECRET_LEN);
    memcpy(&md5_inner[SIZEOF_SENDER + SECRET_LEN], PAD1, PAD_MD5);
    
    Md5Update(&ssl->hashMd5, md5_inner, sizeof(md5_inner));
    Md5Final(&ssl->hashMd5, md5_result);

    /* make md5 outer */
    memcpy(md5_outer, ssl->masterSecret, SECRET_LEN);
    memcpy(&md5_outer[SECRET_LEN], PAD2, PAD_MD5);
    memcpy(&md5_outer[SECRET_LEN + PAD_MD5], md5_result, MD5_DIGEST_SIZE);

    Md5Update(&ssl->hashMd5, md5_outer, sizeof(md5_outer));
    Md5Final(&ssl->hashMd5, hashes->md5);
}


/* calculate SHA hash for finished */
static void BuildSHA(SSL* ssl, Hashes* hashes, const byte* sender)
{
    byte sha_result[SHA_DIGEST_SIZE];
    byte sha_inner[SIZEOF_SENDER + SECRET_LEN + PAD_SHA];
    byte sha_outer[SECRET_LEN + PAD_SHA + SHA_DIGEST_SIZE];

    /* make sha inner */
    memcpy(sha_inner, sender, SIZEOF_SENDER);
    memcpy(&sha_inner[SIZEOF_SENDER], ssl->masterSecret, SECRET_LEN);
    memcpy(&sha_inner[SIZEOF_SENDER + SECRET_LEN], PAD1, PAD_SHA);
    
    ShaUpdate(&ssl->hashSha, sha_inner, sizeof(sha_inner));
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    memcpy(sha_outer, ssl->masterSecret, SECRET_LEN);
    memcpy(&sha_outer[SECRET_LEN], PAD2, PAD_SHA);
    memcpy(&sha_outer[SECRET_LEN + PAD_SHA], sha_result, SHA_DIGEST_SIZE);

    ShaUpdate(&ssl->hashSha, sha_outer, sizeof(sha_outer));
    ShaFinal(&ssl->hashSha, hashes->sha);
}


static void BuildFinished(SSL* ssl, Hashes* hashes, const byte* sender)
{
    /* store current states, building requires get_digest which resets state */
    Md5 md5 = ssl->hashMd5;
    Sha sha = ssl->hashSha;

    if (ssl->tls)
        BuildTlsFinished(ssl, hashes, sender);
    else {
        BuildMD5(ssl, hashes, sender);
        BuildSHA(ssl, hashes, sender);
    }
    
    /* restore */
    ssl->hashMd5 = md5;
    ssl->hashSha = sha;
}


static int DoCertificate(SSL* ssl, const byte* input, word32* inOutIdx)
{
    word32 listSz, i = *inOutIdx;
    byte   tmp[3];
    int    ret = 0;

    tmp[0] = input[i++];
    tmp[1] = input[i++];
    tmp[2] = input[i++];
    c24to32(tmp, &listSz);
    
    while (listSz && ret == 0) {
        /* cert size */
        buffer      myCert;
        word32      certSz;
        DecodedCert dCert;

        tmp[0] = input[i++];
        tmp[1] = input[i++];
        tmp[2] = input[i++];
        c24to32(tmp, &certSz);
        
        myCert.length = certSz;
        myCert.buffer = (byte*) malloc(certSz);
        if (!myCert.buffer) {
            ret = MEMORY_ERROR;
            break;
        }
        memcpy(myCert.buffer, input + i, certSz); i += certSz;
        
        ssl->peerCert = myCert; /* takes ownership */

        listSz -= certSz + CERT_HEADER_SZ;

        InitDecodedCert(&dCert, ssl->peerCert.buffer);
        ret = ParseCert(&dCert, ssl->peerCert.length, CERT_TYPE,
                        !ssl->verifyNone, ssl->caList);

        if (ret == 0 && listSz == 0) {  /* last one has peer's key */
            if ( (ssl->peerKey.buffer = (byte*)malloc(dCert.pubKeySize))) {
                memcpy(ssl->peerKey.buffer, dCert.publicKey, dCert.pubKeySize);
                ssl->peerKey.length = dCert.pubKeySize;

                if (!ssl->verifyNone && ssl->domainName.buffer)
                    if (strncmp(ssl->domainName.buffer, dCert.subject,
                                ssl->domainName.length - 1))
                        ret = DOMAIN_NAME_MISMATCH;
            }
            else
                ret = MEMORY_ERROR;
        }

        FreeDecodedCert(&dCert);
        if (listSz) {   /* more to come, release */
            free(myCert.buffer);
            ssl->peerCert.buffer = 0;
        }
    }

    if (ret == 0 && ssl->side == CLIENT_END)
        ssl->serverState = SERVER_CERT_COMPLETE;

    if (ret != 0)
        ssl->error = ret;

    *inOutIdx = i;
    return ret;
}


static int DoFinished(SSL* ssl, const byte* input, word32* inOutIdx)
{
    byte   verifyMAC[SHA_DIGEST_SIZE],
           mac[SHA_DIGEST_SIZE],
           fill;
    int    finishedSz = ssl->tls ? TLS_FINISHED_SZ : FINISHED_SZ;
    word32 macSz = finishedSz + HANDSHAKE_HEADER_SZ,
           idx = *inOutIdx,
           padSz = ssl->keys.encryptSz - HANDSHAKE_HEADER_SZ - finishedSz -
                   ssl->specs.hash_size,
           i;

    if (memcmp(input + idx, &ssl->verifyHashes, finishedSz))
        return VERIFY_FINISHED_ERROR;

    ssl->hmac(ssl, verifyMAC, input + idx - HANDSHAKE_HEADER_SZ, macSz,
         handshake, 1);
    idx += finishedSz;

    /* read mac and fill */
    memcpy(mac, input + idx, ssl->specs.hash_size);
    idx += ssl->specs.hash_size;

    for (i = 0; i < padSz; i++) 
        fill = input[idx++];

    /* verify mac */
    if (memcmp(mac, verifyMAC, ssl->specs.hash_size))
        return VERIFY_MAC_ERROR;

    if (ssl->side == CLIENT_END) {
        ssl->serverState = SERVER_FINISHED_COMPLETE;
        if (!ssl->resuming)
            ssl->handShakeState = HANDSHAKE_DONE;
    }
    else {
        ssl->clientState = CLIENT_FINISHED_COMPLETE;
        if (ssl->resuming)
            ssl->handShakeState = HANDSHAKE_DONE;
    }

    *inOutIdx = idx;
    return 0;
}


static int DoHandShakeMsg(SSL* ssl, const byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    HandShakeHeader hs;

    if (GetHandShakeHeader(ssl, input, inOutIdx, &hs) != 0)
        return PARSE_ERROR;

    if (*inOutIdx + hs.size > totalSz)
        return INCOMPLETE_DATA;
    
    HashInput(ssl, input + *inOutIdx, hs.size);

    switch (hs.type) {

#ifndef NO_CYASSL_CLIENT
    case server_hello:
        return DoServerHello(ssl, input, inOutIdx);
        break;

    case certificate_request:
        return DoCertificateRequest(ssl, input, inOutIdx);
        break;

    case server_key_exchange:
        return DoServerKeyExchange(ssl, input, inOutIdx);
        break;
#endif

    case certificate:
        return DoCertificate(ssl, input, inOutIdx);
        break;

    case server_hello_done:
        ssl->serverState = SERVER_HELLODONE_COMPLETE;
        break;

    case finished:
        return DoFinished(ssl, input, inOutIdx);
        break;

#ifndef NO_CYASSL_SERVER
    case client_hello:
        return DoClientHello(ssl, input, inOutIdx, totalSz, hs.size);
        break;

    case client_key_exchange:
        return DoClientKeyExchange(ssl, input, inOutIdx);
        break;
#endif

    default:
        return UNKNOWN_HANDSHAKE_TYPE;
    }

    return 0;
}


static INLINE void Encrypt(SSL* ssl, byte* out, const byte* input, word32 sz)
{
    switch (ssl->specs.bulk_cipher_algorithm) {
        #ifdef BUILD_ARC4
            case rc4:
                Arc4Process(&ssl->encrypt.arc4, out, input, sz);
                break;
        #endif

        #ifdef BUILD_DES3
            case triple_des:
                Des3_CbcEncrypt(&ssl->encrypt.des3, out, input, sz);
                break;
        #endif

        #ifdef BUILD_AES
            case aes:
                AesCbcEncrypt(&ssl->encrypt.aes, out, input, sz);
                break;
        #endif
    }
}


static INLINE void Decrypt(SSL* ssl, byte* plain, const byte* input, word32 sz)
{
    switch (ssl->specs.bulk_cipher_algorithm) {
        #ifdef BUILD_ARC4
            case rc4:
                Arc4Process(&ssl->decrypt.arc4, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_DES3
            case triple_des:
                Des3_CbcDecrypt(&ssl->decrypt.des3, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_AES
            case aes:
                AesCbcDecrypt(&ssl->decrypt.aes, plain, input, sz);
                break;
        #endif
    }
}


/* decrypt input message in place */
static int DecryptMessage(SSL* ssl, byte* input, word32 sz)
{
    byte* plain = (byte*)malloc(sz);
    if (!plain) return MEMORY_ERROR;

    Decrypt(ssl, plain, input, sz);
    memcpy(input, plain, sz);
    ssl->keys.encryptSz = sz;

    free(plain);
    return 0;
}


static INLINE word32 GetSEQIncrement(SSL* ssl, int verify)
{
    if (verify)
        return ssl->keys.peer_sequence_number++; 
    else
        return ssl->keys.sequence_number++; 
}


static int DoApplicationData(SSL* ssl, byte* input, word32* inOutIdx)
{
    word32 msgSz   = ssl->keys.encryptSz;
    word32 pad     = 0, 
           padByte = 0,
           idx     = *inOutIdx,
           digestSz = ssl->specs.hash_size,
           i;
    int    dataSz;

    byte verify[SHA_DIGEST_SIZE];
    byte mac[SHA_DIGEST_SIZE];
    byte fill;

    if (ssl->specs.cipher_type == block) {
        pad = *(input + idx + msgSz - 1);
        padByte = 1;
    }

    dataSz = msgSz - digestSz - pad - padByte;   

    /* read data */
    if (dataSz) {
        word32 oldSz = ssl->bufferedData.buffer ? ssl->bufferedData.length : 0;
        byte* data = (byte*) malloc(dataSz + oldSz);
        if (!data) return MEMORY_ERROR;

        if (oldSz)
            memcpy(data, ssl->bufferedData.buffer, oldSz);

        memcpy(data + oldSz, input + idx, dataSz);
        idx += dataSz;

        if (oldSz)
            free(ssl->bufferedData.buffer);
        ssl->bufferedData.buffer = data;
        ssl->bufferedData.length = dataSz + oldSz;

        ssl->hmac(ssl, verify, data + oldSz, dataSz, application_data, 1);
    }

    /* read mac and fill */
    memcpy(mac, input + idx, digestSz);
    idx += digestSz;
   
    for (i = 0; i < pad; i++) 
        fill = input[idx++];
    if (padByte)
        fill = input[idx++];    

    /* verify */
    if (dataSz) {
        if (memcmp(mac, verify, digestSz))
            return VERIFY_MAC_ERROR;
    }
    else 
        GetSEQIncrement(ssl, 1);  /* even though no data, increment verify */

    *inOutIdx = idx;
    return 0;
}


/* process alert, return level */
static int DoAlert(SSL* ssl, byte* input, word32* inOutIdx)
{
    byte level, type;

    level = input[(*inOutIdx)++];
    type  = input[(*inOutIdx)++];

    if (ssl->keys.encryptionOn) {
        int  aSz = ALERT_SIZE, i;
        byte verify[SHA_DIGEST_SIZE];
        byte mac[SHA_DIGEST_SIZE];
        byte fill;
        int  padSz = ssl->keys.encryptSz - aSz - ssl->specs.hash_size;
        
        ssl->hmac(ssl, verify, input + *inOutIdx - aSz, aSz, alert, 1);

        /* read mac and fill */
        memcpy(mac, input + *inOutIdx, ssl->specs.hash_size);
        *inOutIdx += ssl->specs.hash_size;
        for (i = 0; i < padSz; i++)
            fill = input[(*inOutIdx)++];

        /* verify */
        if (memcmp(mac, verify, ssl->specs.hash_size))
            return VERIFY_MAC_ERROR;
    }

    return level;
}


int DoProcessReply(SSL* ssl)
{
    byte*  input = 0;
    word32 inSz,
           idx = 0, 
           offset = 0,
           bufferedSz;

    #define ERROR_OUT(x) { free(input); return x; }

    if (!Wait(ssl->socket))
        return SOCKET_ERROR_E;

    if (!(inSz = GetReady(ssl->socket)))
        return SOCKET_NODATA;

    bufferedSz = ssl->bufferedInput.buffer ? ssl->bufferedInput.length : 0;
    input = (byte*) malloc(inSz + bufferedSz);
    if (!input) return MEMORY_ERROR;
    if ( (inSz = Receive(ssl->socket, input + bufferedSz, inSz, 0)) == -1)
        ERROR_OUT(SOCKET_ERROR_E);

    if (bufferedSz) {
        /* prepend old data */
        memcpy(input, ssl->bufferedInput.buffer, ssl->bufferedInput.length);

        free(ssl->bufferedInput.buffer);
        ssl->bufferedInput.buffer = 0;
        ssl->bufferedInput.length = 0;

        inSz += bufferedSz;
    }

#ifndef NO_CYASSL_SERVER
    if ( ssl->side == SERVER_END && ssl->clientState == NULL_STATE)
        /* see if sending SSLv2 client hello */
        if (input[idx] != handshake)
            if (ProcessOldClientHello(ssl, input, &idx, inSz - idx) != 0)
                ERROR_OUT(BAD_HELLO);
#endif

    while (idx < inSz) {
        /* each record */
        int needHdr = 0;
        RecordLayerHeader rh;

        /* make sure enough data left */
        if ( (inSz - idx) < RECORD_HEADER_SZ)
            needHdr = 1;
        else if (GetRecordHeader(ssl, input, &idx, &rh) != 0)
            ERROR_OUT(PARSE_ERROR);

        /* make sure enough data left */
        if ( needHdr || (inSz - idx) < rh.size) {
            /* buffer for next call */
            word32 extra = needHdr ? 0 : RECORD_HEADER_SZ;
            word32 sz = inSz - idx + extra;

            byte*  data = (byte*)malloc(sz);
            if (!data) ERROR_OUT(MEMORY_ERROR);
            memcpy(data, input + idx - extra, sz);

            assert(ssl->bufferedInput.buffer == 0);
            ssl->bufferedInput.buffer = data;
            ssl->bufferedInput.length = sz;
            
            /* let caller decide */
            ERROR_OUT(INCOMPLETE_DATA);
        }

        /* each message in record, can be more than 1 */
        while ( idx < rh.size + RECORD_HEADER_SZ + offset) {
            if (ssl->keys.encryptionOn)
                if (DecryptMessage(ssl, input + idx, rh.size) < 0)
                    ERROR_OUT(DECRYPT_ERROR);
            switch (rh.type) {
                case handshake :
                    if (DoHandShakeMsg(ssl, input, &idx, inSz) != 0)
                        ERROR_OUT(PARSE_ERROR);
                    break;

                case change_cipher_spec:
                    idx++;
                    ssl->keys.encryptionOn = 1;
                    if (ssl->resuming && ssl->side == CLIENT_END)
                        BuildFinished(ssl, &ssl->verifyHashes, server);
                    else if (!ssl->resuming && ssl->side == SERVER_END)
                        BuildFinished(ssl, &ssl->verifyHashes, client);
                    break;

                case application_data:
                    if (DoApplicationData(ssl, input, &idx) != 0)
                        ERROR_OUT(PARSE_ERROR);
                    break;

                case alert:
                    if (DoAlert(ssl, input, &idx) == alert_fatal)
                        ERROR_OUT(FATAL_ERROR);
                    break;
            
                default:
                    ERROR_OUT(UNKOWN_RECORD_TYPE);
            }
        }
        offset += rh.size + RECORD_HEADER_SZ;
    }

    free(input);
    return 0;
}


int ProcessReply(SSL* ssl)
{
    int ret;

    while( (ret = DoProcessReply(ssl)) == INCOMPLETE_DATA)
        ; /* nothing */

    return ret;
}


int SendChangeCipher(SSL* ssl)
{
    byte              output[RECORD_HEADER_SZ + ENUM_LEN];
    RecordLayerHeader rl;
    int               sendSz = sizeof(output);

    rl.type      = change_cipher_spec;
    rl.version   = ssl->version;
    rl.length[0] = 0;
    rl.length[1] = 1;

    memcpy(output, &rl, RECORD_HEADER_SZ);
    output[RECORD_HEADER_SZ] = 1;             /* turn it on */

    if (Send(ssl->socket, output, sendSz, 0) != sendSz)
        return SOCKET_ERROR_E;

    return 0;
}


static INLINE const byte* GetMacSecret(SSL* ssl, int verify)
{
    if ( (ssl->side == CLIENT_END && !verify) ||
         (ssl->side == SERVER_END &&  verify) )
        return ssl->keys.client_write_MAC_secret;
    else
        return ssl->keys.server_write_MAC_secret;
}


static void Hmac(SSL* ssl, byte* digest, const byte* buffer, word32 sz,
                 int content, int verify)
{
    byte inner[SHA_DIGEST_SIZE + PAD_MD5 + SEQ_SZ + ENUM_LEN + LENGTH_SZ];
    byte outer[SHA_DIGEST_SIZE + PAD_MD5 + SHA_DIGEST_SIZE]; 
    byte result[SHA_DIGEST_SIZE];                      /* max possible sizes */

    word32 digestSz = ssl->specs.hash_size;            /* actual sizes */
    word32 padSz    = ssl->specs.pad_size;
    word32 innerSz  = digestSz + padSz + SEQ_SZ + ENUM_LEN + LENGTH_SZ;
    word32 outerSz  = digestSz + padSz + digestSz;

    Md5 md5;
    Sha sha;

    /* data */
    byte seq[SEQ_SZ] = { 0x00, 0x00, 0x00, 0x00 };
    byte length[LENGTH_SZ];
    const byte* macSecret = GetMacSecret(ssl, verify);
    c16toa((word16)sz, length);
    c32toa(GetSEQIncrement(ssl, verify), &seq[sizeof(word32)]);

    /* make inner */
    memcpy(inner, macSecret, digestSz);
    memcpy(&inner[digestSz], PAD1, padSz);
    memcpy(&inner[digestSz + padSz], seq, SEQ_SZ);
    inner[digestSz + padSz + SEQ_SZ] = content;
    memcpy(&inner[digestSz + padSz + SEQ_SZ + ENUM_LEN], length, LENGTH_SZ);

    /* append content buffer */
    if (ssl->specs.mac_algorithm == md5_mac) {
        InitMd5(&md5);
        Md5Update(&md5, inner, innerSz);
        Md5Update(&md5, buffer, sz);
        Md5Final(&md5, result);
    }
    else {
        InitSha(&sha);
        ShaUpdate(&sha, inner, innerSz);
        ShaUpdate(&sha, buffer, sz);
        ShaFinal(&sha, result);
    }

    /* make outer */
    memcpy(outer, macSecret, digestSz);
    memcpy(&outer[digestSz], PAD2, padSz);
    memcpy(&outer[digestSz + padSz], result, digestSz);

    if (ssl->specs.mac_algorithm == md5_mac) {
        Md5Update(&md5, outer, outerSz);
        Md5Final(&md5, digest);
    }
    else {
        ShaUpdate(&sha, outer, outerSz);
        ShaFinal(&sha, digest);
    }
}


/* Build SSL Message, encrypted */
static int BuildMessage(SSL* ssl, byte* output, const byte* input, int inSz,
                        int type)
{
    word32 digestSz = ssl->specs.hash_size;
    word32 sz = RECORD_HEADER_SZ + inSz + digestSz;                
    word32 pad = 0;
    word32 idx = 0, i;
    byte              digest[SHA_DIGEST_SIZE];  /* max size */
    byte              alen[BYTE3_LEN];
    RecordLayerHeader rl;

    if (ssl->specs.cipher_type == block) {
        word32 blockSz = ssl->specs.block_size;
        sz += 1;       /* pad byte */
        pad = (sz - RECORD_HEADER_SZ) % blockSz;
        pad = blockSz - pad;
        sz += pad;
    }
    
    /* record layer header */
    rl.type    = type;
    rl.version = ssl->version;
    rl.size    = sz - RECORD_HEADER_SZ;          /* includes mac and digest */
    c16toa((word16)rl.size, alen);      
    memcpy(&rl.length, alen, sizeof(rl.length));

    /* write to output */
    memcpy(output, &rl, RECORD_HEADER_SZ);
    idx += RECORD_HEADER_SZ;
    memcpy(output + idx, input, inSz);
    idx += inSz;

    if (type == handshake)
        HashOutput(ssl, output, RECORD_HEADER_SZ + inSz);
    ssl->hmac(ssl, digest, output + RECORD_HEADER_SZ, inSz, type, 0);
           
    memcpy(output + idx, digest, digestSz);
    idx += digestSz;

    if (ssl->specs.cipher_type == block)
        for (i = 0; i <= pad; i++) output[idx++] = pad; /* pad byte gets */
                                                        /* pad value too */

    Encrypt(ssl, output + RECORD_HEADER_SZ, output + RECORD_HEADER_SZ,
            rl.size);

    return sz;
}


int SendFinished(SSL* ssl)
{
    int             sendSz, 
                    finishedSz = ssl->tls ? TLS_FINISHED_SZ : FINISHED_SZ;
    byte            input[FINISHED_SZ + HANDSHAKE_HEADER_SZ];   /* max size */
    byte            output[sizeof(input) + MAX_MSG_EXTRA];
    byte            alen[BYTE3_LEN];
    Hashes          hashes;
    HandShakeHeader hs;

    BuildFinished(ssl, &hashes, ssl->side == CLIENT_END ? client : server);

    /* make handshake header */
    hs.type = finished;
    c32to24(finishedSz, alen);
    memcpy(&hs.length, alen, sizeof(hs.length));

    /* write to input for message */
    memcpy(input, &hs, HANDSHAKE_HEADER_SZ);
    memcpy(input + HANDSHAKE_HEADER_SZ, &hashes, finishedSz);

    if ( (sendSz = BuildMessage(ssl, output, input, HANDSHAKE_HEADER_SZ +
                                finishedSz, handshake)) == -1)
        return BUILD_MSG_ERROR;

    if (Send(ssl->socket, output, sendSz, 0) != sendSz)
        return SOCKET_ERROR_E;

    if (!ssl->resuming) {
        AddSession(ssl);    /* just try */
        if (ssl->side == CLIENT_END)
            BuildFinished(ssl, &ssl->verifyHashes, server);
        else
            ssl->handShakeState = HANDSHAKE_DONE;
    }
    else {
        if (ssl->side == CLIENT_END)
            ssl->handShakeState = HANDSHAKE_DONE;
        else
            BuildFinished(ssl, &ssl->verifyHashes, client);
    }

    return 0;
}


int SendCertificate(SSL* ssl)
{
    int    sendSz, ret = 0;
    word32 i = 0;
    byte   tmp[CERT_HEADER_SZ];
    byte*  output = 0;
    byte   alen[BYTE3_LEN];

    RecordLayerHeader rl;
    HandShakeHeader   hs;

    /* list + cert size */
    sendSz = ssl->certificate.length + 2 * CERT_HEADER_SZ + RECORD_HEADER_SZ +
        HANDSHAKE_HEADER_SZ;

    output = (byte*) malloc(sendSz);
    if (!output) return MEMORY_ERROR;

    /* record layer header */
    rl.type    = handshake;
    rl.version = ssl->version;
    rl.size    = sendSz - RECORD_HEADER_SZ;  
    c16toa((word16)rl.size, alen);      
    memcpy(&rl.length, alen, sizeof(rl.length));

    /* make handshake header */
    hs.type = certificate;
    c32to24(ssl->certificate.length + 2 * CERT_HEADER_SZ, alen);
    memcpy(&hs.length, alen, sizeof(hs.length));

    /* write to output */
    memcpy(output, &rl, RECORD_HEADER_SZ);
    i += RECORD_HEADER_SZ;

    memcpy(output + i, &hs, HANDSHAKE_HEADER_SZ);
    i += HANDSHAKE_HEADER_SZ;

    /* list total */
    c32to24(ssl->certificate.length + CERT_HEADER_SZ, tmp);
    memcpy(output + i, tmp, CERT_HEADER_SZ);
    i += CERT_HEADER_SZ;

    /* member */
    c32to24(ssl->certificate.length, tmp);
    memcpy(output + i, tmp, CERT_HEADER_SZ);
    i += CERT_HEADER_SZ;
    memcpy(output + i, ssl->certificate.buffer, ssl->certificate.length);
    i += ssl->certificate.length;

    HashOutput(ssl, output, sendSz);
    if (Send(ssl->socket, output, sendSz, 0) != sendSz)
        ret = SOCKET_ERROR_E;

    if (ssl->side == SERVER_END)
        ssl->serverState = SERVER_CERT_COMPLETE;
    free(output);
    return 0;
}


int SendData(SSL* ssl, const void* buffer, int sz)
{
    int sent = 0,
        sendSz;

    if (ssl->handShakeState != HANDSHAKE_DONE)
        return 0;  /* not ready */

    for (;;) {
        int len = min(sz - sent, MAX_RECORD_SIZE);
        byte* out = (byte*) malloc(len + MAX_MSG_EXTRA);

        if (!out) return MEMORY_ERROR;

        sendSz = BuildMessage(ssl, out, (byte*)buffer + sent, len,
                              application_data);
        if (Send(ssl->socket, out, sendSz, 0) != sendSz) {
            free(out);
            return SOCKET_ERROR_E;
        }

        free(out);
        sent += len;
        if (sent == sz) break;
    }
 
    return sent;
}


static int FillData(SSL* ssl, byte* output, int sz)
{
    int   dataSz = min(sz, (int)ssl->bufferedData.length);
    int   leftSz = 0;
    byte* left   = 0;

    if (dataSz == 0) return 0;

    memcpy(output, ssl->bufferedData.buffer, dataSz);

    /* did we leave any */
    if (dataSz < (int)ssl->bufferedData.length) {   
        leftSz = ssl->bufferedData.length - dataSz;
        left   = (byte*) malloc(leftSz);

        if (!left) return MEMORY_ERROR;

        memcpy(left, ssl->bufferedData.buffer + dataSz, leftSz);
    }

    free(ssl->bufferedData.buffer);
    ssl->bufferedData.buffer = left;
    ssl->bufferedData.length = leftSz;

    return dataSz;
}


/* process input data */
int ReceiveData(SSL* ssl, byte* output, int sz)
{
    if (ssl->handShakeState != HANDSHAKE_DONE)
        return -1;  /* not ready */

    if (!ssl->bufferedData.buffer)
        if ( (ssl->error = ProcessReply(ssl)) != 0)
            return -1;  /* error */

    return FillData(ssl, output, sz);
}


/* send alert message */
int SendAlert(SSL* ssl, int severity, int type)
{
    byte input[ALERT_SIZE];
    byte output[ALERT_SIZE + MAX_MSG_EXTRA];
    int  sendSz;

    input[0] = severity;
    input[1] = type;

    if (ssl->keys.encryptionOn)
        sendSz = BuildMessage(ssl, output, input, sizeof(input), alert);
    else {
        byte              alen[BYTE3_LEN];
        RecordLayerHeader rl;

        /* record layer header */
        rl.type    = alert;
        rl.version = ssl->version;
        c16toa(ALERT_SIZE, alen);      
        memcpy(&rl.length, alen, sizeof(rl.length));

        memcpy(output, &rl, RECORD_HEADER_SZ);
        memcpy(output + RECORD_HEADER_SZ, input, sizeof(input));

        sendSz = RECORD_HEADER_SZ + sizeof(input);
    }

    if (Send(ssl->socket, output, sendSz, 0) != sendSz)
        return SOCKET_ERROR_E;

    return 0;
}



void SetErrorString(int error, char* buffer)
{
    const int max = MAX_ERROR_SZ;  /* shorthand */

#ifdef NO_ERROR_STRINGS

    strncpy(buffer, "no support for error strings built in", max);

#else

    switch (error) {

    case UNSUPPORTED_SUITE :
        strncpy(buffer, "unsupported cipher suite", max);
        break;

    case PREFIX_ERROR :
        strncpy(buffer, "bad index to key rounds", max);
        break;

    case MEMORY_ERROR :
        strncpy(buffer, "out of memory", max);
        break;

    case VERIFY_FINISHED_ERROR :
        strncpy(buffer, "verify problem on finished", max);
        break;

    case VERIFY_MAC_ERROR :
        strncpy(buffer, "verify mac problem", max);
        break;

    case PARSE_ERROR :
        strncpy(buffer, "parse error on header", max);
        break;

    case UNKNOWN_HANDSHAKE_TYPE :
        strncpy(buffer, "weird handshake type", max);
        break;

    case SOCKET_ERROR_E :
        strncpy(buffer, "error state on socket", max);
        break;

    case SOCKET_NODATA :
        strncpy(buffer, "expected data, not there", max);
        break;

    case INCOMPLETE_DATA :
        strncpy(buffer, "don't have enough data to complete task", max);
        break;

    case UNKOWN_RECORD_TYPE :
        strncpy(buffer, "unknown type in record hdr", max);
        break;

    case DECRYPT_ERROR :
        strncpy(buffer, "error during decryption", max);
        break;

    case FATAL_ERROR :
        strncpy(buffer, "revcd alert fatal error", max);
        break;

    case ENCRYPT_ERROR :
        strncpy(buffer, "error during encryption", max);
        break;

    case FREAD_ERROR :
        strncpy(buffer, "fread problem", max);
        break;

    case NO_PEER_KEY :
        strncpy(buffer, "need peer's key", max);
        break;

    case NO_PRIVATE_KEY :
        strncpy(buffer, "need the private key", max);
        break;

    case RSA_PRIVATE_ERROR :
        strncpy(buffer, "error during rsa priv op", max);
        break;

    case MATCH_SUITE_ERROR :
        strncpy(buffer, "can't match cipher suite", max);
        break;

    case BUILD_MSG_ERROR :
        strncpy(buffer, "build message failure", max);
        break;

    case BAD_HELLO :
        strncpy(buffer, "client hello malformed", max);
        break;

    case DOMAIN_NAME_MISMATCH :
        strncpy(buffer, "peer subject name mismatch", max);
        break;

    default :
        strncpy(buffer, "unknown error number", max);
    }

#endif /* NO_ERROR_STRINGS */
}



/* be sure to add to cipher_name_idx too !!!! */
const char* const cipher_names[] = 
{
#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    "RC4-SHA",
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    "RC4-MD5",
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    "DES-CBC3-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    "AES128-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    "AES256-SHA",
#endif

};



/* cipher suite number that matches above name table */
int cipher_name_idx[] =
{

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    SSL_RSA_WITH_RC4_128_SHA,
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    SSL_RSA_WITH_RC4_128_MD5,
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA,    
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA,
#endif

};


/* return true if set, else false */
/* only supports full name from cipher_name[] delimited by : */
int SetCipherList(SSL_CTX* ctx, const char* list)
{
    int  ret = 0, i;
    char name[MAX_SUITE_NAME];

    char  needle[] = ":";
    char* haystack = (char*)list;
    char* prev;

    const int suiteSz = sizeof(cipher_names) / sizeof(cipher_names[0]);
    int idx = 0;

    if (!list)
        return 0;

    for(;;) {
        int len;
        prev = haystack;
        haystack = strstr(haystack, needle);

        if (!haystack)    /* last cipher */
            len = min(sizeof(name), strlen(prev));
        else
            len = min(sizeof(name), (size_t)(haystack - prev));

        strncpy(name, prev, len);
        name[(len == sizeof(name)) ? len - 1 : len] = 0;

        for (i = 0; i < suiteSz; i++)
            if (strncmp(name, cipher_names[i], sizeof(name)) == 0) {

                ctx->suites.suites[idx++] = 0x00;  /* first byte always zero */
                ctx->suites.suites[idx++] = cipher_name_idx[i];

                if (!ret) ret = 1;   /* found at least one */
                break;
            }
        if (!haystack) break;
        haystack++;
    }

    if (ret) {
        ctx->suites.setSuites = 1;
        ctx->suites.suiteSz   = idx;
    }

    return ret;
}


/* client only parts */
#ifndef NO_CYASSL_CLIENT

    int SendClientHello(SSL* ssl)
    {
        RecordLayerHeader rl;
        HandShakeHeader   hs;
        word32            length, idx = 0;
        byte              alen[BYTE3_LEN];        /* for byte output lengths */
        byte              output[MAX_HELLO_SZ];
        int               sendSz;
        int               idSz = ssl->resuming ? ID_LEN : 0;

        length = sizeof(ProtocolVersion) + RAN_LEN
               + idSz + ENUM_LEN                      
               + ssl->suites.suiteSz + SUITE_LEN
               + COMP_LEN  + ENUM_LEN;

        /* handshake header */
        hs.type = client_hello;
        c32to24(length, alen);
        memcpy(&hs.length, alen, sizeof(hs.length));

        /* record layer header */
        rl.type    = handshake;
        rl.version = ssl->version;
        c16toa((word16)(length + HANDSHAKE_HEADER_SZ), alen);
        memcpy(&rl.length, alen, sizeof(rl.length));

        /* now write to output */
        memcpy(output, &rl, RECORD_HEADER_SZ);
        idx += RECORD_HEADER_SZ;
        memcpy(output + idx, &hs, HANDSHAKE_HEADER_SZ);
        idx += HANDSHAKE_HEADER_SZ;

            /* client hello, first version */
        memcpy(output + idx, &ssl->version, sizeof(ProtocolVersion));
        idx += sizeof(ProtocolVersion);

            /* then random */
        RNG_GenerateBlock(&ssl->rng, output + idx, RAN_LEN);
        memcpy(ssl->clientRandom, output + idx, RAN_LEN);    /* store random */
        idx += RAN_LEN;

            /* then session id */
        output[idx++] = idSz;
        if (idSz) {
            memcpy(output + idx, ssl->session.sessionID, ID_LEN);
            idx += ID_LEN;
        }
            /* then cipher suites */
        c16toa(ssl->suites.suiteSz, output + idx);
        idx += 2;
        memcpy(output + idx, &ssl->suites.suites, ssl->suites.suiteSz);
        idx += ssl->suites.suiteSz;

            /* last, compression */
        output[idx++] = COMP_LEN;
        output[idx++] = NO_COMPRESSION;
            
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        HashOutput(ssl, output, sendSz);

        if (Send(ssl->socket, output, sendSz, 0) != sendSz)
            return SOCKET_ERROR_E;

        ssl->clientState = CLIENT_HELLO_COMPLETE;

        return 0;
    }


    static int DoServerHello(SSL* ssl, const byte* input, word32* inOutIdx)
    {
        byte b;
        ProtocolVersion pv;
        word32 i = *inOutIdx;

        memcpy(&pv, input + i, sizeof(pv));
        i += sizeof(pv);
        memcpy(ssl->serverRandom, input + i, RAN_LEN);
        i += RAN_LEN;
        b = input[i++];
        if (b) {
            memcpy(ssl->sessionID, input + i, b);
            i += b;
        }
        ssl->cipherSuite = input[++i];  
        i++;  /* 2nd byte */
        i++;  /* ignore compression for now */

        ssl->serverState = SERVER_HELLO_COMPLETE;

        *inOutIdx = i;

        if (ssl->resuming) {
            if (memcmp(ssl->sessionID, ssl->session.sessionID, ID_LEN) == 0) {
                if (SetCipherSpecs(ssl) == 0) {
                    memcpy(ssl->masterSecret, ssl->session.masterSecret,
                           SECRET_LEN);
                    if (ssl->tls)
                        DeriveTlsKeys(ssl);
                    else
                        DeriveKeys(ssl);
                    ssl->serverState = SERVER_HELLODONE_COMPLETE;
                    return 0;
                }
                else
                    return UNSUPPORTED_SUITE;
            }
            else
                ssl->resuming = 0;  /* server denied resumption attempt */
        }

        return SetCipherSpecs(ssl);
    }


    /* just read in and ignore for now TODO: */
    static int DoCertificateRequest(SSL* ssl, const byte* input, word32*
                                    inOutIdx)
    {
        word16 len, i;
        byte   tmp[REQUEST_HEADER];
        byte   b;

        len = input[(*inOutIdx)++];

        /* types */
        for (i = 0; i < len; i++)
            b = input[(*inOutIdx)++];

        tmp[0] = input[(*inOutIdx)++];
        tmp[1] = input[(*inOutIdx)++];
    
        ato16(tmp, &len);

        /* authorities */
        while (len) {
            word16 dnSz;
       
            tmp[0] = input[(*inOutIdx)++];
            tmp[1] = input[(*inOutIdx)++];
            ato16(tmp, &dnSz);
        
            *inOutIdx += dnSz;
            len -= dnSz + REQUEST_HEADER;
        }

        return 0;
    }


    static int DoServerKeyExchange(SSL* ssl, const byte* input, word32*
                                   inOutIdx)
    {


        return -1;  /* not supported yet TODO: */
    }


    int SendClientKeyExchange(SSL* ssl)
    {
        byte   encSecret[ENCRYPT_LEN];
        word32 encSz;
        RsaKey key;
        word32 idx = 0;
        int    ret = 0;

        /* RSA for now */
        RNG_GenerateBlock(&ssl->rng, ssl->preMasterSecret, SECRET_LEN);
        ssl->preMasterSecret[0] = ssl->version.major;
        ssl->preMasterSecret[1] = ssl->version.minor;
        InitRsaKey(&key);

        if (ssl->peerKey.buffer)
            ret = RsaPublicKeyDecode(ssl->peerKey.buffer, &idx, &key,
                                     ssl->peerKey.length);
        else
            return NO_PEER_KEY;

        if (ret == 0) {
            ret = RsaPublicEncrypt(ssl->preMasterSecret, SECRET_LEN, encSecret,
                                   sizeof(encSecret), &key, &ssl->rng);
            /* success */
            if (ret > 0) {
                byte              output[sizeof(encSecret) + MAX_MSG_EXTRA];
                byte              alen[BYTE3_LEN];
                int               sendSz;
                RecordLayerHeader rl;
                HandShakeHeader   hs;
                word32            tlsSz = ssl->tls ? 2 : 0;

                encSz = ret;
                ret   = 0;
                idx   = 0;

                /* handshake header */
                hs.type = client_key_exchange;
                c32to24(encSz + tlsSz, alen);
                memcpy(&hs.length, alen, sizeof(hs.length));

                /* record layer header */
                rl.type    = handshake;
                rl.version = ssl->version;
                c16toa((word16)(encSz + tlsSz + HANDSHAKE_HEADER_SZ), alen);
                memcpy(&rl.length, alen, sizeof(rl.length));

                /* now write to output */
                memcpy(output, &rl, RECORD_HEADER_SZ);
                idx += RECORD_HEADER_SZ;
                memcpy(output + idx, &hs, HANDSHAKE_HEADER_SZ);
                idx += HANDSHAKE_HEADER_SZ;
                if (tlsSz) {
                    c16toa((word16)encSz, alen);
                    output[idx++] = alen[0];
                    output[idx++] = alen[1];
                }
                memcpy(output + idx, encSecret, encSz);
                idx += encSz;

                sendSz = encSz + tlsSz + HANDSHAKE_HEADER_SZ +RECORD_HEADER_SZ;
                HashOutput(ssl, output, sendSz);

                if (Send(ssl->socket, output, sendSz, 0) != sendSz)
                    ret = SOCKET_ERROR_E;
            }
        }

        if (ret == 0) {
            ssl->clientState = CLIENT_KEYEXCHANGE_COMPLETE;
            ret = MakeMasterSecret(ssl);
        }
        FreeRsaKey(&key);

        return ret;
    }



#endif /* NO_CYASSL_CLIENT */


#ifndef NO_CYASSL_SERVER

    int SendServerHello(SSL* ssl)
    {
        RecordLayerHeader rl;
        HandShakeHeader   hs;
        word32            length, idx = 0;
        int               sendSz;
        byte              alen[BYTE3_LEN];        /* for byte output lengths */
        byte              output[MAX_HELLO_SZ];

        length = sizeof(ProtocolVersion) + RAN_LEN
               + ID_LEN + ENUM_LEN                 
               + SUITE_LEN 
               + ENUM_LEN;

        /* handshake header */
        hs.type = server_hello;
        c32to24(length, alen);
        memcpy(&hs.length, alen, sizeof(hs.length));

        /* record layer header */
        rl.type    = handshake;
        rl.version = ssl->version;
        c16toa((word16)(length + HANDSHAKE_HEADER_SZ), alen);
        memcpy(&rl.length, alen, sizeof(rl.length));

        /* now write to output */
        memcpy(output, &rl, RECORD_HEADER_SZ);
        idx += RECORD_HEADER_SZ;
        memcpy(output + idx, &hs, HANDSHAKE_HEADER_SZ);
        idx += HANDSHAKE_HEADER_SZ;

            /* first version */
        memcpy(output + idx, &ssl->version, sizeof(ProtocolVersion));
        idx += sizeof(ProtocolVersion);

            /* then random */
        if (!ssl->resuming)         
            RNG_GenerateBlock(&ssl->rng, ssl->serverRandom, RAN_LEN);
        memcpy(output + idx, ssl->serverRandom, RAN_LEN);
        idx += RAN_LEN;

            /* then session id */
        output[idx++] = ID_LEN;
        if (!ssl->resuming)
            RNG_GenerateBlock(&ssl->rng, ssl->sessionID, ID_LEN);
        memcpy(output + idx, ssl->sessionID, ID_LEN);
        idx += ID_LEN;

            /* then cipher suite */
        output[idx++] = 0x00; 
        output[idx++] = ssl->cipherSuite;

            /* last, compression */
        output[idx++] = NO_COMPRESSION;
            
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        HashOutput(ssl, output, sendSz);

        if (Send(ssl->socket, output, sendSz, 0) != sendSz)
            return SOCKET_ERROR_E;

        ssl->serverState = SERVER_HELLO_COMPLETE;

        return 0;
    }


    static int MatchSuite(SSL* ssl, Suites* peerSuites)
    {
        word16 i, j;
        int    match = 0;

        if (peerSuites->suiteSz == 0 || peerSuites->suiteSz % 2)
            return MATCH_SUITE_ERROR;

        /* start with best, if a match we are good, Ciphers are at odd index
           since all SSL and TLS ciphers have 0x00 first byte               */
        for (i = 1; !match && i < ssl->suites.suiteSz; i += 2)
            for (j = 1; j < peerSuites->suiteSz; j += 2)
                if (ssl->suites.suites[i] == peerSuites->suites[j]) {
                    ssl->cipherSuite = ssl->suites.suites[i];
                    match = 1;
                    break;
                }

        if (!match) return MATCH_SUITE_ERROR;

        return SetCipherSpecs(ssl);
    }


    /* process alert, return level */
    static int ProcessOldClientHello(SSL* ssl, const byte* input,
                                     word32* inOutIdx, word32 inSz)
    {
        word32          idx = *inOutIdx;
        word16          sessionSz;
        word16          randomSz;
        word16          i, j;
        ProtocolVersion pv;
        Suites          clSuites;

        byte b0 = input[idx++];
        byte b1 = input[idx++];
        byte len[2];

        word16 sz = ((b0 & 0x7f) << 8) | b1;
        if (sz > inSz - 2)
            return INCOMPLETE_DATA;

        /* manually hash input since different format */
        Md5Update(&ssl->hashMd5, input + idx, sz);
        ShaUpdate(&ssl->hashSha, input + idx, sz);

        b1 = input[idx++];  /* does this value mean client_hello? */

        /* version */
        pv.major = input[idx++];
        pv.minor = input[idx++];

        if (ssl->version.minor > 0 && pv.minor == 0) {
            /* turn off tls */
            ssl->tls = 0;
            ssl->version.minor = 0;
            InitSuites(&ssl->suites, ssl->version);
        }

        /* suite size */
        len[0] = input[idx++];
        len[1] = input[idx++];
        ato16(len, &clSuites.suiteSz);

        /* session size */
        len[0] = input[idx++];
        len[1] = input[idx++];
        ato16(len, &sessionSz);
    
        /* random size */
        len[0] = input[idx++];
        len[1] = input[idx++];
        ato16(len, &randomSz);

        /* suites */
        for (i = 0, j = 0; i < clSuites.suiteSz; i += 3) {    
            byte first = input[idx++];
            if (first) { /* sslv2 type */
                len[0] = input[idx++];  /* skip */
                len[1] = input[idx++];
            }
            else {
                clSuites.suites[j++] = input[idx++];
                clSuites.suites[j++] = input[idx++];
            }
        }
        clSuites.suiteSz = j;

        /* session id */
        if (sessionSz) {
            memcpy(ssl->sessionID, input + idx, sessionSz);
            idx += sessionSz;
            ssl->resuming = 1;
        }

        /* random */
        if (randomSz < RAN_LEN)
            memset(ssl->clientRandom, 0, RAN_LEN - randomSz);
        memcpy(&ssl->clientRandom[RAN_LEN - randomSz], input + idx, randomSz);
        idx += randomSz;

        ssl->clientState = CLIENT_HELLO_COMPLETE;
        *inOutIdx = idx;

        /* DoClientHello uses same resume code */
        while (ssl->resuming) {  /* let's try */
            SSL_SESSION* session = GetSession(ssl);
            if (!session) {
                ssl->resuming = 0;
                break;   /* session lookup failed */
            }
            if (MatchSuite(ssl, &clSuites) < 0)
                return UNSUPPORTED_SUITE;

            memcpy(ssl->masterSecret, session->masterSecret, SECRET_LEN);
            RNG_GenerateBlock(&ssl->rng, ssl->serverRandom, RAN_LEN);
            if (ssl->tls)
                DeriveTlsKeys(ssl);
            else
                DeriveKeys(ssl);
            ssl->clientState = CLIENT_KEYEXCHANGE_COMPLETE;

            return 0;
        }

        return MatchSuite(ssl, &clSuites);
    }


    static int DoClientHello(SSL* ssl, const byte* input, word32* inOutIdx,
                             word32 totalSz, word32 helloSz)
    {
        byte b;
        byte tmp[2];
        ProtocolVersion pv;
        Suites          clSuites;
        word32 i = *inOutIdx;
        word32 begin = i;

        /* make sure can read up to session */
        if (i + sizeof(pv) + RAN_LEN + ENUM_LEN > totalSz)
            return INCOMPLETE_DATA;

        memcpy(&pv, input + i, sizeof(pv));
        i += sizeof(pv);
        if (ssl->version.minor > 0 && pv.minor == 0) {
            /* turn off tls */
            ssl->tls = 0;
            ssl->version.minor = 0;
            InitSuites(&ssl->suites, ssl->version);
        }
        memcpy(ssl->clientRandom, input + i, RAN_LEN);
        i += RAN_LEN;
        b = input[i++];
        if (b) {
            if (i + ID_LEN > totalSz)
                return INCOMPLETE_DATA;
            memcpy(ssl->sessionID, input + i, ID_LEN);
            i += b;
            ssl->resuming= 1; /* client wants to resume */
        }

        if (i + 2 > totalSz)
            return INCOMPLETE_DATA;
        /* suites */
        tmp[0] = input[i++];
        tmp[1] = input[i++];
        ato16(tmp, &clSuites.suiteSz);

        /* suites and comp len */
        if (i + clSuites.suiteSz + ENUM_LEN > totalSz)
            return INCOMPLETE_DATA;
        memcpy(clSuites.suites, input + i, clSuites.suiteSz);
        i += clSuites.suiteSz;

        b = input[i++];  /* comp len */
        if (i + b > totalSz)
            return INCOMPLETE_DATA;
        i += b;  /* ignore compression for now */

        ssl->clientState = CLIENT_HELLO_COMPLETE;

        *inOutIdx = i;
        if ( (i - begin) < helloSz)
            *inOutIdx = begin + helloSz;  /* skip extensions */
        
        /* ProcessOld uses same resume code */
        while (ssl->resuming) {  /* let's try */
            SSL_SESSION* session = GetSession(ssl);
            if (!session) {
                ssl->resuming = 0;
                break;   /* session lookup failed */
            }
            if (MatchSuite(ssl, &clSuites) < 0)
                return UNSUPPORTED_SUITE;

            memcpy(ssl->masterSecret, session->masterSecret, SECRET_LEN);
            RNG_GenerateBlock(&ssl->rng, ssl->serverRandom, RAN_LEN);
            if (ssl->tls)
                DeriveTlsKeys(ssl);
            else
                DeriveKeys(ssl);
            ssl->clientState = CLIENT_KEYEXCHANGE_COMPLETE;

            return 0;
        }
        return MatchSuite(ssl, &clSuites);
    }


    int SendServerHelloDone(SSL* ssl)
    {
        RecordLayerHeader rl;
        HandShakeHeader   hs;
        byte              alen[BYTE3_LEN];
        byte              output[RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ];
        word32            idx = 0;
        int               sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

        /* handshake header */
        hs.type = server_hello_done;
        c32to24(0, alen);
        memcpy(&hs.length, alen, sizeof(hs.length));

        /* record layer header */
        rl.type    = handshake;
        rl.version = ssl->version;
        c16toa(HANDSHAKE_HEADER_SZ, alen);
        memcpy(&rl.length, alen, sizeof(rl.length));

        /* now write to output */
        memcpy(output, &rl, RECORD_HEADER_SZ);
        idx += RECORD_HEADER_SZ;
        memcpy(output + idx, &hs, HANDSHAKE_HEADER_SZ);
        idx += HANDSHAKE_HEADER_SZ;

        HashOutput(ssl, output, sendSz);
        if (Send(ssl->socket, output, sendSz, 0) != sendSz)
            return SOCKET_ERROR_E;

        ssl->serverState = SERVER_HELLODONE_COMPLETE;
        return 0;
    }


    static int DoClientKeyExchange(SSL* ssl, const byte* input,
                                   word32* inOutIdx)
    {
        int    ret = 0;
        word32 idx = 0;
        RsaKey key;
        byte*  tmp = 0;
        byte   sz[2];    /* for tls length */
        word32 length;


        InitRsaKey(&key);

        if (ssl->key.buffer)
            ret = RsaPrivateKeyDecode(ssl->key.buffer, &idx, &key,
                                      ssl->key.length);
        else
            return NO_PRIVATE_KEY;

        if (ret == 0) {
            length = RsaEncryptSize(&key);
            tmp = (byte*) malloc(length);
            if (!tmp) return MEMORY_ERROR;

            if (ssl->tls) {
                sz[0] = input[(*inOutIdx)++];
                sz[1] = input[(*inOutIdx)++];
            }   
            memcpy(tmp, input + *inOutIdx, length);
            *inOutIdx += length;

            if (RsaPrivateDecrypt(tmp, length, ssl->preMasterSecret,
                                  SECRET_LEN, &key) == SECRET_LEN)
                ret = MakeMasterSecret(ssl);
            else
                ret = RSA_PRIVATE_ERROR;
        }

        FreeRsaKey(&key);
        free(tmp);

        if (ret == 0)
            ssl->clientState = CLIENT_KEYEXCHANGE_COMPLETE;

        return ret;
    }

#endif /* NO_CYASSL_SERVER */
