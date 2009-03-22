/* cyassl_int.c
 *
 * Copyright (C) 2006-2009 Sawtooth Consulting Ltd.
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

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __sun
    #include <sys/filio.h>
#endif

#define TRUE  1
#define FALSE 0


#ifndef NO_CYASSL_CLIENT
    static int DoServerHello(SSL* ssl, const byte* input, word32*);
    static int DoCertificateRequest(SSL* ssl, const byte* input, word32*);
    static int DoServerKeyExchange(SSL* ssl, const byte* input, word32*);
#endif


#ifndef NO_CYASSL_SERVER
    static int DoClientHello(SSL* ssl, const byte* input, word32*, word32,
                             word32);
    static int DoCertificateVerify(SSL* ssl, byte*, word32*, word32);
    static int ProcessOldClientHello(SSL*, const byte*, word32*, word32,word16);
    static int DoClientKeyExchange(SSL* ssl, byte* input, word32*);
#endif

typedef enum {
    doProcessInit = 0,
#ifndef NO_CYASSL_SERVER
    runProcessOldClientHello,
#endif
    getRecordLayerHeader,
    getData,
    runProcessingOneMessage
} processReply;

static void Hmac(SSL* ssl, byte* digest, const byte* buffer, word32 sz,
                 int content, int verify);

static void BuildCertHashes(SSL* ssl, Hashes* hashes);


void BuildTlsFinished(SSL* ssl, Hashes* hashes, const byte* sender);
int  DeriveTlsKeys(SSL* ssl);


#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


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


#ifdef HAVE_LIBZ

    /* alloc user allocs to work with zlib */
    void* myAlloc(void* opaque, unsigned int item, unsigned int size)
    {
        return XMALLOC(item * size, opaque);
    }


    void myFree(void* opaque, void* memory)
    {
        XFREE(memory, opaque);
    }


    /* init zlib comp/decomp streams, 0 on success */
    static int InitStreams(SSL* ssl)
    {
        ssl->c_stream.zalloc = (alloc_func)myAlloc;
        ssl->c_stream.zfree  = (free_func)myFree;
        ssl->c_stream.opaque = (voidpf)ssl->heap;

        if (deflateInit(&ssl->c_stream, 8) != Z_OK) return ZLIB_INIT_ERROR;

        ssl->didStreamInit = 1;

        ssl->d_stream.zalloc = (alloc_func)myAlloc;
        ssl->d_stream.zfree  = (free_func)myFree;
        ssl->d_stream.opaque = (voidpf)ssl->heap;

        if (inflateInit(&ssl->d_stream) != Z_OK) return ZLIB_INIT_ERROR;

        return 0;
    }


    static void FreeStreams(SSL* ssl)
    {
        if (ssl->didStreamInit) {
            deflateEnd(&ssl->c_stream);
            inflateEnd(&ssl->d_stream);
        }
    }


    /* compress in to out, return out size or error */
    static int Compress(SSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = ssl->c_stream.total_out;

        /* put size in front of compression */
        c16toa((word16)inSz, out);
        out   += 2;
        outSz -= 2;

        ssl->c_stream.next_in   = in;
        ssl->c_stream.avail_in  = inSz;
        ssl->c_stream.next_out  = out;
        ssl->c_stream.avail_out = outSz;

        err = deflate(&ssl->c_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_COMPRESS_ERROR;

        return ssl->c_stream.total_out - currTotal + sizeof(word16);
    }
        

    /* decompress in to out, returnn out size or error */
    static int DeCompress(SSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = ssl->d_stream.total_out;
        word16 len;

        /* find size in front of compression */
        ato16(in, &len);
        in   += 2;
        inSz -= 2;

        ssl->d_stream.next_in   = in;
        ssl->d_stream.avail_in  = inSz;
        ssl->d_stream.next_out  = out;
        ssl->d_stream.avail_out = outSz;

        err = inflate(&ssl->d_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_DECOMPRESS_ERROR;

        return ssl->d_stream.total_out - currTotal;
    }
        
#endif /* HAVE_LIBZ */


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
    ctx->haveDH             = 0;
    ctx->heap               = ctx;  /* defualts to self */
#ifndef NO_PSK
    ctx->havePSK            = 0;
    ctx->server_hint[0]     = 0;
    ctx->client_psk_cb      = 0;
    ctx->server_psk_cb      = 0;
#endif /* NO_PSK */

    ctx->CBIORecv = EnbedReceive;
    ctx->CBIOSend = EmbedSend;

    ctx->caList = 0;
    /* remove DH later if server didn't set, add psk later  */
    InitSuites(&ctx->suites, method->version, TRUE, FALSE);  
    ctx->verifyPeer = 0;
    ctx->verifyNone = 0;
    ctx->failNoCert = 0;
    ctx->sessionCacheOff      = 0;  /* initially on */
    ctx->sessionCacheFlushOff = 0;  /* initially on */
    ctx->sendVerify = 0;
}


void FreeSSL_Ctx(SSL_CTX* ctx)
{
    XFREE(ctx->privateKey.buffer, ctx->heap);
    XFREE(ctx->certificate.buffer, ctx->heap);
    XFREE(ctx->method, ctx->heap);

    FreeSigners(ctx->caList, ctx->heap);
    
    XFREE(ctx, ctx->heap);
}


void InitSuites(Suites* suites, ProtocolVersion pv, byte haveDH, byte havePSK)
{
    word32 idx = 0;
    int    tls = pv.major == 3 && pv.minor >= 1;

    (void)tls;  /* shut up compiler */

    suites->setSuites = 0;  /* user hasn't set yet */

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveDH) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveDH) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

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

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA;
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

#ifdef BUILD_TLS_RSA_WITH_HC_128_CBC_SHA
    if (tls) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_CBC_SHA
    if (tls) {
        suites->suites[idx++] = 0; 
        suites->suites[idx++] = TLS_RSA_WITH_RABBIT_CBC_SHA;
    }
#endif

    suites->suiteSz = idx;
}


int InitSSL(SSL* ssl, SSL_CTX* ctx)
{
    int  ret;
    byte havePSK = 0;

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    ssl->version = ctx->method->version;
    ssl->suites  = ctx->suites;

#ifdef HAVE_LIBZ
    ssl->didStreamInit = 0;
#endif
   
    ssl->buffers.certificate.buffer   = 0;
    ssl->buffers.key.buffer           = 0;
    ssl->buffers.inputBuffer.length   = 0;
    ssl->buffers.inputBuffer.idx      = 0;
    ssl->buffers.outputBuffer.length  = 0;
    ssl->buffers.outputBuffer.idx     = 0;
    ssl->buffers.domainName.buffer    = 0;
    ssl->buffers.serverDH_P.buffer    = 0;
    ssl->buffers.serverDH_G.buffer    = 0;
    ssl->buffers.serverDH_Pub.buffer  = 0;
    ssl->buffers.serverDH_Priv.buffer = 0;
    ssl->buffers.clearOutputBuffer.buffer  = 0;
    ssl->buffers.clearOutputBuffer.length  = 0;

    if ( (ret = InitRng(&ssl->rng)) )
        return ret;

    InitMd5(&ssl->hashMd5);
    InitSha(&ssl->hashSha);
    InitRsaKey(&ssl->peerRsaKey, ctx->heap);

    ssl->peerRsaKeyPresent = 0;
    ssl->options.side  = ctx->method->side;
    ssl->error = 0;
    ssl->options.connReset = 0;
    ssl->options.isClosed  = 0;
    ssl->options.usingCompression = 0;
    ssl->options.haveDH    = ctx->haveDH;
    ssl->options.usingPSK_cipher = 0;
    ssl->options.sendAlertState = 0;
#ifndef NO_PSK
    havePSK = ctx->havePSK;
    ssl->options.havePSK   = ctx->havePSK;
    ssl->options.client_psk_cb = ctx->client_psk_cb;
    ssl->options.server_psk_cb = ctx->server_psk_cb;
#endif /* NO_PSK */

    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->options.acceptState  = ACCEPT_BEGIN; 
    ssl->options.processReply = doProcessInit;

    ssl->keys.encryptionOn = 0;     /* initially off */
    ssl->options.sessionCacheOff      = ctx->sessionCacheOff;
    ssl->options.sessionCacheFlushOff = ctx->sessionCacheFlushOff;

    ssl->options.verifyPeer = ctx->verifyPeer;
    ssl->options.verifyNone = ctx->verifyNone;
    ssl->options.failNoCert = ctx->failNoCert;
    ssl->options.sendVerify = ctx->sendVerify;
    
    ssl->options.resuming = 0;
    ssl->hmac = Hmac;         /* default to SSLv3 */
    ssl->heap = ctx->heap;    /* defualts to self */
    ssl->options.tls    = 0;
    ssl->options.tls1_1 = 0;

    /* SSL_CTX still owns certificate, key, and caList buffers */
    ssl->buffers.certificate = ctx->certificate;
    ssl->buffers.key = ctx->privateKey;
    ssl->caList = ctx->caList;

    ssl->peerCert.issuer.sz    = 0;
    ssl->peerCert.subject.sz   = 0;

#ifndef NO_PSK
    ssl->arrays.client_identity[0] = 0;
    if (ctx->server_hint[0])   /* set in CTX */
        strncpy(ssl->arrays.server_hint, ctx->server_hint, MAX_PSK_ID_LEN);
    else
        ssl->arrays.server_hint[0] = 0;
#endif /* NO_PSK */

#ifdef CYASSL_CALLBACKS
    ssl->hsInfoOn = 0;
    ssl->toInfoOn = 0;
#endif

    /* make sure server has DH parms, and add PSK if there */
    if (!ssl->ctx->suites.setSuites) {    /* trust user override */
        if (ssl->options.side == SERVER_END) 
            InitSuites(&ssl->suites, ssl->version,ssl->options.haveDH, havePSK);
        else 
            InitSuites(&ssl->suites, ssl->version, TRUE, havePSK);
    }

    return 0;
}


void FreeSSL(SSL* ssl)
{
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap);
    XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap);
    XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap);
    XFREE(ssl->buffers.domainName.buffer, ssl->heap);
    FreeRsaKey(&ssl->peerRsaKey);

#ifdef HAVE_LIBZ
    FreeStreams(ssl);
#endif

    XFREE(ssl, ssl->heap);
}


ProtocolVersion MakeSSLv3(void)
{
    ProtocolVersion pv;
    pv.major = 3;
    pv.minor = 0;

    return pv;
}




#ifdef _WIN32

    timer_d Timer(void)
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


    word32 LowResTimer(void)
    {
        return (word32)Timer();
    }

#else /* _WIN32 */

    #include <sys/time.h>

    timer_d Timer(void)
    {
        struct timeval tv;
        gettimeofday(&tv, 0);

        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
    }


    word32 LowResTimer(void)
    {
        struct timeval tv;
        gettimeofday(&tv, 0);

        return tv.tv_sec; 
    }


#endif /* _WIN32 */


/* add output to md5 and sha handshake hashes, exclude record header */
static void HashOutput(SSL* ssl, const byte* output, int sz, int ivSz)
{
    const byte* buffer = output + RECORD_HEADER_SZ + ivSz;
    sz -= RECORD_HEADER_SZ;

    Md5Update(&ssl->hashMd5, buffer, sz);
    ShaUpdate(&ssl->hashSha, buffer, sz);
}


/* add input to md5 and sha handshake hashes, include handshake header */
static void HashInput(SSL* ssl, const byte* input, int sz)
{
    const byte* buffer = input - HANDSHAKE_HEADER_SZ;
    sz += HANDSHAKE_HEADER_SZ;

    Md5Update(&ssl->hashMd5, buffer, sz);
    ShaUpdate(&ssl->hashSha, buffer, sz);
}


static word32 Receive(SSL* ssl, byte* buf, word32 sz, int flags)
{
    int recvd;

retry:
    recvd = ssl->ctx->CBIORecv((char *)buf, (int)sz, ssl->IOCBCtx);
    if (recvd < 0)
        switch (recvd) {
            case -1:            /* general/unknown error */
                return -1;

            case -2:            /* want read, would block */
                return WANT_READ;

            case -3:            /* connection reset */
                ssl->options.connReset = 1;
                return -1;

            case -4:            /* interrupt */
                /* see if we got our timeout */
                #ifdef CYASSL_CALLBACKS
                    if (ssl->toInfoOn) {
                        struct itimerval timeout;
                        getitimer(ITIMER_REAL, &timeout);
                        if (timeout.it_value.tv_sec == 0 && 
                                                timeout.it_value.tv_usec == 0) {
                            strncpy(ssl->timeoutInfo.timeoutName,
                                    "recv() timeout", MAX_TIMEOUT_NAME_SZ);
                            return 0;
                        }
                    }
                #endif
                goto retry;

            case -5:            /* peer closed connection */
                ssl->options.isClosed = 1;
                return -1;
        }

    return recvd;
}

int SendBuffered(SSL* ssl)
{
    while (ssl->buffers.outputBuffer.length > 0) {
        int sent = ssl->ctx->CBIOSend((char*)ssl->buffers.outputBuffer.buffer +
                                      ssl->buffers.outputBuffer.idx,
                                      (int)ssl->buffers.outputBuffer.length,
                                      ssl->IOCBCtx);
        if (sent < 0) {
            switch (sent) {

                case -2:        /* would block */
                    return WANT_WRITE;

                case -3:        /* connection reset */
                    ssl->options.connReset = 1;
                    break;

                case -4:        /* interrupt */
                    /* see if we got our timeout */
                    #ifdef CYASSL_CALLBACKS
                        if (ssl->toInfoOn) {
                            struct itimerval timeout;
                            getitimer(ITIMER_REAL, &timeout);
                            if (timeout.it_value.tv_sec == 0 && 
                                                timeout.it_value.tv_usec == 0) {
                                strncpy(ssl->timeoutInfo.timeoutName,
                                        "send() timeout", MAX_TIMEOUT_NAME_SZ);
                                return WANT_WRITE;
                            }
                        }
                    #endif
                    continue;
            }

            return SOCKET_ERROR_E;
        }

        ssl->buffers.outputBuffer.idx += sent;
        ssl->buffers.outputBuffer.length -= sent;
    }
      
    ssl->buffers.outputBuffer.idx = 0;
    return 0;
}

/* check avalaible size into outbut buffer */
static INLINE int CheckAvalaibleSize(SSL *ssl, int size)
{
    if (BUFFER16K_LEN - ssl->buffers.outputBuffer.length < (word32)size) {
        if (SendBuffered(ssl) == SOCKET_ERROR_E)
            return SOCKET_ERROR_E;
        if (BUFFER16K_LEN - ssl->buffers.outputBuffer.length < (word32)size) 
            return WANT_WRITE;
    }
    return 0;
}

/* do all verify and sanity checks on record header */
static int GetRecordHeader(SSL* ssl, const byte* input, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    memcpy(rh, input + *inOutIdx, RECORD_HEADER_SZ);
    *inOutIdx += RECORD_HEADER_SZ;
    ato16(rh->length, size);

    /* catch version mismatch */
    if (rh->version.major != ssl->version.major || 
        rh->version.minor != ssl->version.minor)
        return VERSION_ERROR;              /* only use requested version */

    /* record layer length check */
    if (*size > (MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA))
        return LENGTH_ERROR;

    /* verify record type here as well */
    switch ((enum ContentType)rh->type) {
        case handshake:
        case change_cipher_spec:
        case application_data:
        case alert:
            break;
        default:
            return UNKNOWN_RECORD_TYPE;
    }

    return 0;
}


static int GetHandShakeHeader(SSL* ssl, const byte* input, word32* inOutIdx,
                              byte *type, word32 *size)
{
    const byte *ptr = input + *inOutIdx;
    *inOutIdx += HANDSHAKE_HEADER_SZ;

    *type = ptr[0];
    c24to32(&ptr[1], size);

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

    /* make md5 inner */    
    Md5Update(&ssl->hashMd5, sender, SIZEOF_SENDER);
    Md5Update(&ssl->hashMd5, ssl->arrays.masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD1, PAD_MD5);
    Md5Final(&ssl->hashMd5, md5_result);

    /* make md5 outer */
    Md5Update(&ssl->hashMd5, ssl->arrays.masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD2, PAD_MD5);
    Md5Update(&ssl->hashMd5, md5_result, MD5_DIGEST_SIZE);

    Md5Final(&ssl->hashMd5, hashes->md5);
}


/* calculate SHA hash for finished */
static void BuildSHA(SSL* ssl, Hashes* hashes, const byte* sender)
{
    byte sha_result[SHA_DIGEST_SIZE];

    /* make sha inner */
    ShaUpdate(&ssl->hashSha, sender, SIZEOF_SENDER);
    ShaUpdate(&ssl->hashSha, ssl->arrays.masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD1, PAD_SHA);
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    ShaUpdate(&ssl->hashSha, ssl->arrays.masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD2, PAD_SHA);
    ShaUpdate(&ssl->hashSha, sha_result, SHA_DIGEST_SIZE);

    ShaFinal(&ssl->hashSha, hashes->sha);
}


static void BuildFinished(SSL* ssl, Hashes* hashes, const byte* sender)
{
    /* store current states, building requires get_digest which resets state */
    Md5 md5 = ssl->hashMd5;
    Sha sha = ssl->hashSha;

    if (ssl->options.tls)
        BuildTlsFinished(ssl, hashes, sender);
    else {
        BuildMD5(ssl, hashes, sender);
        BuildSHA(ssl, hashes, sender);
    }
    
    /* restore */
    ssl->hashMd5 = md5;
    ssl->hashSha = sha;
}


static int DoCertificate(SSL* ssl, byte* input, word32* inOutIdx)
{
    word32 listSz, i = *inOutIdx;
    int    ret = 0;
    int    firstTime = 1;  /* peer's is at front */

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Certificate", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("Certificate", &ssl->timeoutInfo);
    #endif
    c24to32(&input[i], &listSz);
    i += CERT_HEADER_SZ;
    
    while (listSz && ret == 0) {
        /* cert size */
        buffer      myCert;
        word32      certSz;
        DecodedCert dCert;
        word32      idx = 0;

        c24to32(&input[i], &certSz);
        i += CERT_HEADER_SZ;
        
        myCert.length = certSz;
        myCert.buffer = input + i;
        i += certSz;

        listSz -= certSz + CERT_HEADER_SZ;

        InitDecodedCert(&dCert, myCert.buffer, ssl->heap);
        ret = ParseCertRelative(&dCert, myCert.length, CERT_TYPE,
                                !ssl->options.verifyNone, ssl->caList);

        if (!firstTime || ret != 0)
            goto DoCertificate_free_cert;
        
        /* first one has peer's key */
        firstTime = 0;

        /* set X509 format */
        ssl->peerCert.issuer.sz    = (int)strlen(dCert.issuer) + 1;
        strncpy(ssl->peerCert.issuer.name, dCert.issuer, ASN_NAME_MAX);
        ssl->peerCert.subject.sz   = (int)strlen(dCert.subject) + 1;
        strncpy(ssl->peerCert.subject.name, dCert.subject, ASN_NAME_MAX);
            
        if (!ssl->options.verifyNone && ssl->buffers.domainName.buffer)
            if (strncmp((char*)ssl->buffers.domainName.buffer,
                        dCert.subjectCN,
                        ssl->buffers.domainName.length - 1)) {
                ret = DOMAIN_NAME_MISMATCH;
                goto DoCertificate_free_cert;
            }

        /* decode peer key */
        if (RsaPublicKeyDecode(dCert.publicKey, &idx,
                               &ssl->peerRsaKey, dCert.pubKeySize) != 0) {
            ret = PEER_KEY_ERROR;
            goto DoCertificate_free_cert;
        }

        ssl->peerRsaKeyPresent = 1;

DoCertificate_free_cert:
        FreeDecodedCert(&dCert);
    }

    if (ret == 0 && ssl->options.side == CLIENT_END)
        ssl->options.serverState = SERVER_CERT_COMPLETE;

    if (ret != 0) {
        if (!ssl->options.verifyNone) {
            int why = bad_certificate;
            if (ret == ASN_AFTER_DATE_E || ret == ASN_BEFORE_DATE_E)
                why = certificate_expired;
            SendAlert(ssl, alert_fatal, why);   /* try to send */
            ssl->options.isClosed = 1;
        }
        ssl->error = ret;
    }

    *inOutIdx = i;
    return ret;
}


static int DoFinished(SSL* ssl, const byte* input, word32* inOutIdx)
{
    byte   verifyMAC[SHA_DIGEST_SIZE];
    int    finishedSz = ssl->options.tls ? TLS_FINISHED_SZ : FINISHED_SZ;
    word32 macSz = finishedSz + HANDSHAKE_HEADER_SZ,
           idx = *inOutIdx,
           padSz = ssl->keys.encryptSz - HANDSHAKE_HEADER_SZ - finishedSz -
                   ssl->specs.hash_size;
    const byte* mac;

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Finished", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("Finished", &ssl->timeoutInfo);
    #endif
    if (memcmp(input + idx, &ssl->verifyHashes, finishedSz))
        return VERIFY_FINISHED_ERROR;

    ssl->hmac(ssl, verifyMAC, input + idx - HANDSHAKE_HEADER_SZ, macSz,
         handshake, 1);
    idx += finishedSz;

    /* read mac and fill */
    mac = input + idx;
    idx += ssl->specs.hash_size;

    if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
        padSz -= ssl->specs.block_size;

    idx += padSz;

    /* verify mac */
    if (memcmp(mac, verifyMAC, ssl->specs.hash_size))
        return VERIFY_MAC_ERROR;

    if (ssl->options.side == CLIENT_END) {
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
        if (!ssl->options.resuming)
            ssl->options.handShakeState = HANDSHAKE_DONE;
    }
    else {
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        if (ssl->options.resuming)
            ssl->options.handShakeState = HANDSHAKE_DONE;
    }

    *inOutIdx = idx;
    return 0;
}


static int DoHandShakeMsg(SSL* ssl, byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    byte type;
    word32 size;
    int ret = 0;

    CYASSL_ENTER("DoHandShakeMsg()");

    if (GetHandShakeHeader(ssl, input, inOutIdx, &type, &size) != 0)
        return PARSE_ERROR;

    if (*inOutIdx + size > totalSz)
        return INCOMPLETE_DATA;
    
    HashInput(ssl, input + *inOutIdx, size);
#ifdef CYASSL_CALLBACKS
    /* add name later, add on record and handshake header  part back on */
    if (ssl->toInfoOn) {
        int add = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        AddPacketInfo(0, &ssl->timeoutInfo, input + *inOutIdx - add,
                      size + add, ssl->heap);
        AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
    }
#endif

    switch (type) {

#ifndef NO_CYASSL_CLIENT
    case server_hello:
        CYASSL_MSG("processing server hello");
        ret = DoServerHello(ssl, input, inOutIdx);
        break;

    case certificate_request:
        CYASSL_MSG("processing certificate request");
        ret = DoCertificateRequest(ssl, input, inOutIdx);
        break;

    case server_key_exchange:
        CYASSL_MSG("processing server key exchange");
        ret = DoServerKeyExchange(ssl, input, inOutIdx);
        break;
#endif

    case certificate:
        CYASSL_MSG("processing certificate");
        ret =  DoCertificate(ssl, input, inOutIdx);
        break;

    case server_hello_done:
        CYASSL_MSG("processing server hello done");
        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn) 
                AddPacketName("ServerHelloDone", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddLateName("ServerHelloDone", &ssl->timeoutInfo);
        #endif
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
        break;

    case finished:
        CYASSL_MSG("processing finished");
        ret = DoFinished(ssl, input, inOutIdx);
        break;

#ifndef NO_CYASSL_SERVER
    case client_hello:
        CYASSL_MSG("processing client hello");
        ret = DoClientHello(ssl, input, inOutIdx, totalSz, size);
        break;

    case client_key_exchange:
        CYASSL_MSG("processing client key exchange");
        ret = DoClientKeyExchange(ssl, input, inOutIdx);
        break;

    case certificate_verify:
        CYASSL_MSG("processing certificate verify");
        ret = DoCertificateVerify(ssl, input, inOutIdx, totalSz);
        break;

#endif

    default:
        ret = UNKNOWN_HANDSHAKE_TYPE;
    }

    CYASSL_LEAVE("DoHandShakeMsg()", ret);
    return ret;
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

        #ifdef BUILD_HC128
            case hc128:
                Hc128_Process(&ssl->encrypt.hc128, out, input, sz);
                break;
        #endif

        #ifdef BUILD_RABBIT
            case rabbit:
                RabbitProcess(&ssl->encrypt.rabbit, out, input, sz);
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

        #ifdef BUILD_HC128
            case hc128:
                Hc128_Process(&ssl->decrypt.hc128, plain, input, sz);
                break;
        #endif

        #ifdef BUILD_RABBIT
            case rabbit:
                RabbitProcess(&ssl->decrypt.rabbit, plain, input, sz);
                break;
        #endif
    }
}


/* decrypt input message in place */
static int DecryptMessage(SSL* ssl, byte* input, word32 sz, word32* idx)
{
    Decrypt(ssl, input, input, sz);
    ssl->keys.encryptSz = sz;
    if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
        *idx += ssl->specs.block_size;  /* go past TLSv1.1 IV */

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
           digestSz = ssl->specs.hash_size;
    int    dataSz;
    int    ivExtra = 0;
    byte*  rawData = input + idx;  /* keep current  for hmac */
#ifdef HAVE_LIBZ
    byte   decomp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

    byte        verify[SHA_DIGEST_SIZE];
    const byte* mac;

    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
        pad = *(input + idx + msgSz - ivExtra - 1);
        padByte = 1;
    }

    dataSz = msgSz - ivExtra - digestSz - pad - padByte;   

    /* read data */
    if (dataSz) {
        int    rawSz   = dataSz;       /* keep raw size for hmac */

        ssl->hmac(ssl, verify, rawData, rawSz, application_data, 1);

#ifdef HAVE_LIBZ
        byte  decomp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
        
        if (ssl->options.usingCompression) {
            dataSz = DeCompress(ssl, rawData, dataSz, decomp, sizeof(decomp));
            if (dataSz < 0) return dataSz;
        }
#endif

        if (ssl->options.usingCompression)
            idx += rawSz;
        else
            idx += dataSz;

        ssl->buffers.clearOutputBuffer.buffer = rawData;
        ssl->buffers.clearOutputBuffer.length = dataSz;
    }

    /* read mac and fill */
    mac = input + idx;
    idx += digestSz;
   
    idx += pad;
    if (padByte)
        idx++;

#ifdef HAVE_LIBZ
    if (ssl->options.usingCompression)
        memmove(rawData, decomp, dataSz);
#endif

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

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("Alert", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            /* add record header back on to info + 2 byte level, data */
            AddPacketInfo("Alert", &ssl->timeoutInfo, input + *inOutIdx -
                          RECORD_HEADER_SZ, 2 + RECORD_HEADER_SZ, ssl->heap);
    #endif
    level = input[(*inOutIdx)++];
    type  = input[(*inOutIdx)++];

    if (ssl->keys.encryptionOn) {
        int         aSz = ALERT_SIZE;
        const byte* mac;
        byte        verify[SHA_DIGEST_SIZE];
        int         padSz = ssl->keys.encryptSz - aSz - ssl->specs.hash_size;
        
        ssl->hmac(ssl, verify, input + *inOutIdx - aSz, aSz, alert, 1);

        /* read mac and fill */
        mac = input + *inOutIdx;
        *inOutIdx += (ssl->specs.hash_size + padSz);

        /* verify */
        if (memcmp(mac, verify, ssl->specs.hash_size))
            return VERIFY_MAC_ERROR;
    }

    return level;
}

static int GetInputData(SSL *ssl, size_t size)
{
    int in;
    int inSz;
    int maxLength;
    int usedLength;

    /* check max input length */
    usedLength = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
    maxLength  = BUFFER16K_LEN - usedLength;
    inSz       = (int)(size - usedLength);      /* from last partial read */

    if (inSz > maxLength || inSz <= 0) {
        assert(0);        
        return BUFFER_ERROR;
    }

    /* Put buffer data at start if not there */
    if (usedLength > 0 && ssl->buffers.inputBuffer.idx != 0)
        memcpy(ssl->buffers.inputBuffer.buffer,
               ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
               usedLength);
    
    /* remove processed data */
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;
  
    /* read data from network */
    do {
        in = Receive(ssl, 
                     ssl->buffers.inputBuffer.buffer +
                     ssl->buffers.inputBuffer.length, 
                     inSz, 0);
        if (in == -1)
            return SOCKET_ERROR_E;
   
        if (in == WANT_READ)
            return WANT_READ;
        
        ssl->buffers.inputBuffer.length += in;
        inSz -= in;

    } while (ssl->buffers.inputBuffer.length < size);

    return 0;
}

/* process input requests, return 0 is done, 1 is call again to complete, and
   negative number is error */
int ProcessReply(SSL* ssl)
{
    int    ret;
    word32 startIdx = 0;
    byte   b0, b1;

    switch ((processReply)ssl->options.processReply) {

        /* in the CYASSL_SERVER case, get the first byte for detecting 
         * old client hello */
        case doProcessInit:
lbl_doProcessInit:

            /* get 5 bytes or return error */
            if ((ret = GetInputData(ssl, RECORD_HEADER_SZ)) < 0)
                return ret;

#ifndef NO_CYASSL_SERVER

            /* see if sending SSLv2 client hello */
            if ( ssl->options.side == SERVER_END &&
                 ssl->options.clientState == NULL_STATE &&
                 ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx]
                         != handshake) {
                ssl->options.processReply = runProcessOldClientHello;

                /* how many bytes need ProcessOldClientHello */
                b0 =
                ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx++];
                b1 =
                ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx++];
                ssl->curSize = ((b0 & 0x7f) << 8) | b1;
            }
            else {
                ssl->options.processReply = getRecordLayerHeader;
                goto lbl_getRecordLayerHeader;
            }

        /* in the CYASSL_SERVER case, run the old client hello */
        case runProcessOldClientHello:     

            /* get sz bytes or return error */
            if ((ret = GetInputData(ssl, ssl->curSize)) < 0)
                return ret;

            ret = ProcessOldClientHello(ssl, ssl->buffers.inputBuffer.buffer,
                                        &ssl->buffers.inputBuffer.idx,
                                        ssl->buffers.inputBuffer.length -
                                        ssl->buffers.inputBuffer.idx,
                                        ssl->curSize);
            if (ret < 0)
                return ret;

            else if (ssl->buffers.inputBuffer.idx ==
                     ssl->buffers.inputBuffer.length) {
                ssl->options.processReply = doProcessInit;
                return 0;
            }

#endif

        /* get the record layer header */
        case getRecordLayerHeader:
lbl_getRecordLayerHeader:

            ret = GetRecordHeader(ssl, ssl->buffers.inputBuffer.buffer,
                                       &ssl->buffers.inputBuffer.idx,
                                       &ssl->curRL, &ssl->curSize);
            if (ret != 0)
                return ret;

            ssl->options.processReply = getData;

        /* retrieve record layer data */
        case getData:

            /* get ssl record layer header bloc size bytes or return error */
            if ((ret = GetInputData(ssl, ssl->curSize)) < 0)
                return ret;
            ssl->options.processReply = runProcessingOneMessage;
            startIdx = ssl->buffers.inputBuffer.idx;  /* in case > 1 msg per */

        /* the record layer is here */
        case runProcessingOneMessage:
lbl_runProcessingOneMessage:
            if (ssl->keys.encryptionOn)
                if (DecryptMessage(ssl, ssl->buffers.inputBuffer.buffer + 
                                        ssl->buffers.inputBuffer.idx,
                                        ssl->curSize,
                                        &ssl->buffers.inputBuffer.idx) < 0)
                    return DECRYPT_ERROR;

            CYASSL_MSG("received record layer msg");

            switch (ssl->curRL.type) {
                case handshake :
                    /* debugging in DoHandShakeMsg */
                    if ((ret = DoHandShakeMsg(ssl, 
                                              ssl->buffers.inputBuffer.buffer,
                                              &ssl->buffers.inputBuffer.idx,
                                              ssl->buffers.inputBuffer.length))
                                                                           != 0)
                        return ret;
                    break;

                case change_cipher_spec:
                    CYASSL_MSG("got CHANGE CIPHER SPEC");
                    #ifdef CYASSL_CALLBACKS
                        if (ssl->hsInfoOn)
                            AddPacketName("ChangeCipher", &ssl->handShakeInfo);
                        /* add record header back on info */
                        if (ssl->toInfoOn) {
                            AddPacketInfo("ChangeCipher", &ssl->timeoutInfo,
                                ssl->buffers.inputBuffer.buffer +
                                ssl->buffers.inputBuffer.idx - RECORD_HEADER_SZ,
                                1 + RECORD_HEADER_SZ, ssl->heap);
                            AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
                        }
                    #endif
                    ssl->buffers.inputBuffer.idx++;
                    ssl->keys.encryptionOn = 1;

                    #ifdef HAVE_LIBZ
                        if (ssl->options.usingCompression)
                            if ( (ret = InitStreams(ssl)) != 0)
                                return ret;
                    #endif
                    if (ssl->options.resuming && ssl->options.side ==
                                                                    CLIENT_END)
                        BuildFinished(ssl, &ssl->verifyHashes, server);
                    else if (!ssl->options.resuming && ssl->options.side ==
                                                                    SERVER_END)
                        BuildFinished(ssl, &ssl->verifyHashes, client);
                    break;

                case application_data:
                    CYASSL_MSG("got app DATA");
                    if ((ret = DoApplicationData(ssl,
                                                ssl->buffers.inputBuffer.buffer,
                                               &ssl->buffers.inputBuffer.idx))
                                                                         != 0) {
                        CYASSL_ERROR(ret);
                        return ret;
                    }
                    break;

                case alert:
                    CYASSL_MSG("got ALERT!");
                    if (DoAlert(ssl, ssl->buffers.inputBuffer.buffer,
                                  &ssl->buffers.inputBuffer.idx) == alert_fatal)
                        return FATAL_ERROR;
                    break;
            
                default:
                    CYASSL_ERROR(UNKNOWN_RECORD_TYPE);
                    return UNKNOWN_RECORD_TYPE;
            }

            ssl->options.processReply = doProcessInit;

            /* input exhausted? */
            if (ssl->buffers.inputBuffer.idx == ssl->buffers.inputBuffer.length)
                return 0;
            /* more messages per record */
            else if ((ssl->buffers.inputBuffer.idx - startIdx) < ssl->curSize) {
                ssl->options.processReply = runProcessingOneMessage;
                goto lbl_runProcessingOneMessage;
            }
            /* more records */
            else
                goto lbl_doProcessInit;
    }

    return 0;
}


int SendChangeCipher(SSL* ssl)
{
    byte              *output;
    RecordLayerHeader *rl;
    int                sendSz = RECORD_HEADER_SZ + ENUM_LEN;
    int                ret;

    /* check for avalaible size */
    if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer + 
             ssl->buffers.outputBuffer.idx;

    rl = (RecordLayerHeader*)output;
    rl->type      = change_cipher_spec;
    rl->version   = ssl->version;
    rl->length[0] = 0;
    rl->length[1] = 1;

    output[RECORD_HEADER_SZ] = 1;             /* turn it on */

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("ChangeCipher", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ChangeCipher", &ssl->timeoutInfo, output, sendSz,
                           ssl->heap);
    #endif
    ssl->buffers.outputBuffer.length += sendSz;
    return SendBuffered(ssl);
}


static INLINE const byte* GetMacSecret(SSL* ssl, int verify)
{
    if ( (ssl->options.side == CLIENT_END && !verify) ||
         (ssl->options.side == SERVER_END &&  verify) )
        return ssl->keys.client_write_MAC_secret;
    else
        return ssl->keys.server_write_MAC_secret;
}


static void Hmac(SSL* ssl, byte* digest, const byte* buffer, word32 sz,
                 int content, int verify)
{
    byte   result[SHA_DIGEST_SIZE];                    /* max possible sizes */
    word32 digestSz = ssl->specs.hash_size;            /* actual sizes */
    word32 padSz    = ssl->specs.pad_size;

    Md5 md5;
    Sha sha;

    /* data */
    byte seq[SEQ_SZ] = { 0x00, 0x00, 0x00, 0x00 };
    byte conLen[ENUM_LEN + LENGTH_SZ];     /* content & length */
    const byte* macSecret = GetMacSecret(ssl, verify);
    
    conLen[0] = content;
    c16toa((word16)sz, &conLen[ENUM_LEN]);
    c32toa(GetSEQIncrement(ssl, verify), &seq[sizeof(word32)]);

    if (ssl->specs.mac_algorithm == md5_mac) {
        InitMd5(&md5);
        /* inner */
        Md5Update(&md5, macSecret, digestSz);
        Md5Update(&md5, PAD1, padSz);
        Md5Update(&md5, seq, SEQ_SZ);
        Md5Update(&md5, conLen, sizeof(conLen));
        /* buffer */
        Md5Update(&md5, buffer, sz);
        Md5Final(&md5, result);
        /* outer */
        Md5Update(&md5, macSecret, digestSz);
        Md5Update(&md5, PAD2, padSz);
        Md5Update(&md5, result, digestSz);
        Md5Final(&md5, digest);        
    }
    else {
        InitSha(&sha);
        /* inner */
        ShaUpdate(&sha, macSecret, digestSz);
        ShaUpdate(&sha, PAD1, padSz);
        ShaUpdate(&sha, seq, SEQ_SZ);
        ShaUpdate(&sha, conLen, sizeof(conLen));
        /* buffer */
        ShaUpdate(&sha, buffer, sz);
        ShaFinal(&sha, result);
        /* outer */
        ShaUpdate(&sha, macSecret, digestSz);
        ShaUpdate(&sha, PAD2, padSz);
        ShaUpdate(&sha, result, digestSz);
        ShaFinal(&sha, digest);        
    }
}


static void BuildMD5_CertVerify(SSL* ssl, byte* digest)
{
    byte md5_result[MD5_DIGEST_SIZE];

    /* make md5 inner */
    Md5Update(&ssl->hashMd5, ssl->arrays.masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD1, PAD_MD5);
    Md5Final(&ssl->hashMd5, md5_result);

    /* make md5 outer */
    Md5Update(&ssl->hashMd5, ssl->arrays.masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD2, PAD_MD5);
    Md5Update(&ssl->hashMd5, md5_result, MD5_DIGEST_SIZE);

    Md5Final(&ssl->hashMd5, digest);
}


static void BuildSHA_CertVerify(SSL* ssl, byte* digest)
{
    byte sha_result[SHA_DIGEST_SIZE];
    
    /* make sha inner */
    ShaUpdate(&ssl->hashSha, ssl->arrays.masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD1, PAD_SHA);
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    ShaUpdate(&ssl->hashSha, ssl->arrays.masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD2, PAD_SHA);
    ShaUpdate(&ssl->hashSha, sha_result, SHA_DIGEST_SIZE);

    ShaFinal(&ssl->hashSha, digest);
}


static void BuildCertHashes(SSL* ssl, Hashes* hashes)
{
    /* store current states, building requires get_digest which resets state */
    Md5 md5 = ssl->hashMd5;
    Sha sha = ssl->hashSha;

    if (ssl->options.tls) {
        Md5Final(&ssl->hashMd5, hashes->md5);
        ShaFinal(&ssl->hashSha, hashes->sha);
    }
    else {
        BuildMD5_CertVerify(ssl, hashes->md5);
        BuildSHA_CertVerify(ssl, hashes->sha);
    }
    
    /* restore */
    ssl->hashMd5 = md5;
    ssl->hashSha = sha;
}


/* Build SSL Message, encrypted */
static int BuildMessage(SSL* ssl, byte* output, const byte* input, int inSz,
                        int type)
{
    word32 digestSz = ssl->specs.hash_size;
    word32 sz = RECORD_HEADER_SZ + inSz + digestSz;                
    word32 pad  = 0, i;
    word32 idx  = RECORD_HEADER_SZ;
    word32 ivSz = 0;      /* TLSv1.1  IV */
    word16 size;
    byte               iv[AES_BLOCK_SIZE];                  /* max size */
    RecordLayerHeader *const rl = (RecordLayerHeader*)output;

    if (ssl->specs.cipher_type == block) {
        word32 blockSz = ssl->specs.block_size;
        if (ssl->options.tls1_1) {
            ivSz = blockSz;
            sz  += ivSz;
            RNG_GenerateBlock(&ssl->rng, iv, ivSz);
        }
        sz += 1;       /* pad byte */
        pad = (sz - RECORD_HEADER_SZ) % blockSz;
        pad = blockSz - pad;
        sz += pad;
    }
    
    /* record layer header */
    rl->type    = type;
    rl->version = ssl->version;
    size        = sz - RECORD_HEADER_SZ;    /* include mac and digest */
    c16toa(size, rl->length);

    /* write to output */
    if (ivSz) {
        memcpy(output + idx, iv, ivSz);
        idx += ivSz;
    }
    memcpy(output + idx, input, inSz);
    idx += inSz;

    if (type == handshake)
        HashOutput(ssl, output, RECORD_HEADER_SZ + inSz, ivSz);
    ssl->hmac(ssl, output+idx, output + RECORD_HEADER_SZ + ivSz, inSz, type, 0);
    idx += digestSz;

    if (ssl->specs.cipher_type == block)
        for (i = 0; i <= pad; i++) output[idx++] = pad; /* pad byte gets */
                                                        /* pad value too */
    Encrypt(ssl, output + RECORD_HEADER_SZ, output + RECORD_HEADER_SZ, size);

    return sz;
}


int SendFinished(SSL* ssl)
{
    int              sendSz,
                     finishedSz = ssl->options.tls ? TLS_FINISHED_SZ :
                                                     FINISHED_SZ;
    byte             input[FINISHED_SZ + HANDSHAKE_HEADER_SZ];   /* max size */
    byte            *output;
    Hashes*          hashes;
    HandShakeHeader* hs;
    int              ret;

    /* check for avalaible size */
    if ((ret = CheckAvalaibleSize(ssl, sizeof(input) + MAX_MSG_EXTRA)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer + 
             ssl->buffers.outputBuffer.idx;

    /* make handshake header */
    hs = (HandShakeHeader*)input;
    hs->type = finished;
    c32to24(finishedSz, hs->length);

    /* make finished hashes */
    hashes = (Hashes*)&input[HANDSHAKE_HEADER_SZ];
    BuildFinished(ssl, hashes, ssl->options.side == CLIENT_END ? client :
                  server);

    if ( (sendSz = BuildMessage(ssl, output, input, HANDSHAKE_HEADER_SZ +
                                finishedSz, handshake)) == -1)
        return BUILD_MSG_ERROR;

    if (!ssl->options.resuming) {
        AddSession(ssl);    /* just try */
        if (ssl->options.side == CLIENT_END)
            BuildFinished(ssl, &ssl->verifyHashes, server);
        else
            ssl->options.handShakeState = HANDSHAKE_DONE;
    }
    else {
        if (ssl->options.side == CLIENT_END)
            ssl->options.handShakeState = HANDSHAKE_DONE;
        else
            BuildFinished(ssl, &ssl->verifyHashes, client);
    }

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Finished", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Finished", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
    #endif

    ssl->buffers.outputBuffer.length += sendSz;

    return SendBuffered(ssl);
}


int SendCertificate(SSL* ssl)
{
    int    sendSz, ret = 0;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    byte*  output = 0;

    RecordLayerHeader* rl;
    HandShakeHeader*   hs;

    if (ssl->options.usingPSK_cipher) return 0;  /* not needed */

    /* list + cert size */
    sendSz = ssl->buffers.certificate.length + 2 * CERT_HEADER_SZ +
        RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    /* check for avalaible size */
    if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.idx;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    rl->type    = handshake;
    rl->version = ssl->version;
    c16toa((word16)(sendSz - RECORD_HEADER_SZ), rl->length);      

    /* make handshake header */
    hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
    hs->type = certificate;
    c32to24(ssl->buffers.certificate.length + 2 * CERT_HEADER_SZ, hs->length);

    /* list total */
    c32to24(ssl->buffers.certificate.length + CERT_HEADER_SZ, output + i);
    i += CERT_HEADER_SZ;

    /* member */
    c32to24(ssl->buffers.certificate.length, output + i);
    i += CERT_HEADER_SZ;
    memcpy(output + i, ssl->buffers.certificate.buffer,
           ssl->buffers.certificate.length);
    i += ssl->buffers.certificate.length;

    HashOutput(ssl, output, sendSz, 0);
    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Certificate", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Certificate", &ssl->timeoutInfo, output, sendSz,
                           ssl->heap);
    #endif

    if (ssl->options.side == SERVER_END)
        ssl->options.serverState = SERVER_CERT_COMPLETE;

    ssl->buffers.outputBuffer.length += sendSz;
    return SendBuffered(ssl);
}


int SendCertificateRequest(SSL* ssl)
{
    byte   *output;
    int    ret;
    int    sendSz;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    
    RecordLayerHeader *rl;
    HandShakeHeader   *hs;

    int  typeTotal = 1;  /* only rsa for now */
    int  reqSz = ENUM_LEN + typeTotal + REQ_HEADER_SZ;  /* add auth later */

    if (ssl->options.usingPSK_cipher) return 0;  /* not needed */

    sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + reqSz;

    /* check for avalaible size */
    if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer + 
             ssl->buffers.outputBuffer.idx;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    rl->type    = handshake;
    rl->version = ssl->version;
    c16toa((word16)(sendSz - RECORD_HEADER_SZ), rl->length);      

    /* make handshake header */
    hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
    hs->type = certificate_request;
    c32to24(reqSz, hs->length);

    /* write to output */
    output[i++] = typeTotal;  /* # of types */
    output[i++] = rsa_sign;

    c16toa(0, &output[i]);  /* auth's */
    i += REQ_HEADER_SZ;

    HashOutput(ssl, output, sendSz, 0);

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("CertificateRequest", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("CertificateRequest", &ssl->timeoutInfo, output,
                          sendSz, ssl->heap);
    #endif
    ssl->buffers.outputBuffer.length += sendSz;
    return SendBuffered(ssl);
}


int SendData(SSL* ssl, const void* buffer, int sz)
{
    int sent = 0,  /* plainText size */
        sendSz,
        ret;

    if (ssl->error == WANT_WRITE)
        ssl->error = 0;

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        CYASSL_ERROR(NOT_READY_ERROR);
        return ssl->error = NOT_READY_ERROR;
    }

    for (;;) {
        int   len = min(sz - sent, MAX_RECORD_SIZE);
        byte* out;
        byte* sendBuffer = (byte*)buffer + sent;  /* may switch on comp */
        int   buffSz = len;                       /* may switch on comp */
#ifdef HAVE_LIBZ
        byte  comp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

        if (sent == sz) break;

        /* check for avalaible size */
        if ((ret = CheckAvalaibleSize(ssl, len + MAX_COMP_EXTRA +
                        MAX_MSG_EXTRA)) != 0)
            return ret;

        /* get ouput buffer */
        out = ssl->buffers.outputBuffer.buffer +
              ssl->buffers.outputBuffer.idx;

#ifdef HAVE_LIBZ
        if (ssl->options.usingCompression) {
            buffSz = Compress(ssl, sendBuffer, buffSz, comp, sizeof(comp));
            if (buffSz < 0) {
                return buffSz;
            }
            sendBuffer = comp;
        }
#endif
        sendSz = BuildMessage(ssl, out, sendBuffer, buffSz,
                              application_data);

        ssl->buffers.outputBuffer.length += sendSz;

        if ( (ret = SendBuffered(ssl)) < 0) {
            CYASSL_ERROR(ret);
            if (ret == SOCKET_ERROR_E && ssl->options.connReset)
                return 0;  /* peer reset */
            return ssl->error = ret;
        }

        sent += len;
    }
 
    return sent;
}

/* process input data */
int ReceiveData(SSL* ssl, byte* output, int sz)
{
    int size;

    CYASSL_ENTER("ReceiveData()");

    if (ssl->error == WANT_READ)
        ssl->error = 0;

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        CYASSL_ERROR(NOT_READY_ERROR);
        return ssl->error = NOT_READY_ERROR;
    }

    while (ssl->buffers.clearOutputBuffer.length == 0)
        if ( (ssl->error = ProcessReply(ssl)) < 0) {
            CYASSL_ERROR(ssl->error);
            if (ssl->error == SOCKET_ERROR_E)
                if (ssl->options.connReset || ssl->options.isClosed)
                    return 0;     /* peer reset or closed */
            return ssl->error;
        }

    if (sz < (int)ssl->buffers.clearOutputBuffer.length)
        size = sz;
    else
        size = ssl->buffers.clearOutputBuffer.length;

    memcpy(output, ssl->buffers.clearOutputBuffer.buffer, size);
    ssl->buffers.clearOutputBuffer.length -= size;
    ssl->buffers.clearOutputBuffer.buffer += size;
    
    CYASSL_LEAVE("ReceiveData()", size);
    return size;
}


/* send alert message */
int SendAlert(SSL* ssl, int severity, int type)
{
    byte input[ALERT_SIZE];
    byte *output;
    int  sendSz;
    int  ret;

    /* if sendalert is called again for nonbloking */
    if (ssl->options.sendAlertState != 0) {
        ret = SendBuffered(ssl);
        if (ret == 0)
            ssl->options.sendAlertState = 0;
        return ret;
    }

    /* check for avalaible size */
    if ((ret = CheckAvalaibleSize(ssl, ALERT_SIZE + MAX_MSG_EXTRA)) != 0)
        return ret;

    /* get ouput buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.idx;

    input[0] = severity;
    input[1] = type;

    if (ssl->keys.encryptionOn)
        sendSz = BuildMessage(ssl, output, input, sizeof(input), alert);
    else {
        RecordLayerHeader *const rl = (RecordLayerHeader*)output;
        rl->type    = alert;
        rl->version = ssl->version;
        c16toa(ALERT_SIZE, rl->length);      

        memcpy(output + RECORD_HEADER_SZ, input, sizeof(input));
        sendSz = RECORD_HEADER_SZ + sizeof(input);
    }

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("Alert", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Alert", &ssl->timeoutInfo, output, sendSz,ssl->heap);
    #endif

    ssl->buffers.outputBuffer.length += sendSz;
    ssl->options.sendAlertState = 1;

    return SendBuffered(ssl);
}



void SetErrorString(int error, char* buffer)
{
    const int max = MAX_ERROR_SZ;  /* shorthand */

#ifdef NO_ERROR_STRINGS

    strncpy(buffer, "no support for error strings built in", max);

#else

    /* pass to CTaoCrypt */
    if (error < MAX_CODE_E && error > MIN_CODE_E) {
        CTaoCryptErrorString(error, buffer);
        return;
    }

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

    case UNKNOWN_RECORD_TYPE :
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

    case WANT_READ :
        strncpy(buffer, "non-blocking socket wants data to be read", max);
        break;

    case NOT_READY_ERROR :
        strncpy(buffer, "handshake layer not ready yet, complete first", max);
        break;

    case PMS_VERSION_ERROR :
        strncpy(buffer, "premaster secret version mismatch error", max);
        break;

    case VERSION_ERROR :
        strncpy(buffer, "record layer version error", max);
        break;

    case WANT_WRITE :
        strncpy(buffer, "non-blocking socket write buffer full", max);
        break;

    case BUFFER_ERROR :
        strncpy(buffer, "malformed buffer input error", max);
        break;

    case VERIFY_CERT_ERROR :
        strncpy(buffer, "verify problem on certificate", max);
        break;

    case VERIFY_SIGN_ERROR :
        strncpy(buffer, "verify problem based on signature", max);
        break;

    case CLIENT_ID_ERROR :
        strncpy(buffer, "psk client identity error", max);
        break;

    case SERVER_HINT_ERROR:
        strncpy(buffer, "psk server hint error", max);
        break;

    case PSK_KEY_ERROR:
        strncpy(buffer, "psk key callback error", max);
        break;

    case ZLIB_INIT_ERROR:
        strncpy(buffer, "zlib init error", max);
        break;

    case ZLIB_COMPRESS_ERROR:
        strncpy(buffer, "zlib compress error", max);
        break;

    case ZLIB_DECOMPRESS_ERROR:
        strncpy(buffer, "zlib decompress error", max);
        break;

    case GETTIME_ERROR:
        strncpy(buffer, "gettimeofday() error", max);
        break;

    case GETITIMER_ERROR:
        strncpy(buffer, "getitimer() error", max);
        break;

    case SIGACT_ERROR:
        strncpy(buffer, "sigaction() error", max);
        break;

    case SETITIMER_ERROR:
        strncpy(buffer, "setitimer() error", max);
        break;

    case LENGTH_ERROR:
        strncpy(buffer, "record layer length error", max);
        break;

    case PEER_KEY_ERROR:
        strncpy(buffer, "cant decode peer key", max);
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

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    "DHE-RSA-AES128-SHA",
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    "DHE-RSA-AES256-SHA",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    "PSK-AES128-CBC-SHA",
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    "PSK-AES256-CBC-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_CBC_SHA
    "HC128-SHA",
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_CBC_SHA
    "RABBIT-SHA",
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

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,    
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    TLS_PSK_WITH_AES_128_CBC_SHA,    
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    TLS_PSK_WITH_AES_256_CBC_SHA,
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_CBC_SHA
    TLS_RSA_WITH_HC_128_CBC_SHA,    
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_CBC_SHA
    TLS_RSA_WITH_RABBIT_CBC_SHA,    
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
        size_t len;
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


#ifdef CYASSL_CALLBACKS

    /* Initialisze HandShakeInfo */
    void InitHandShakeInfo(HandShakeInfo* info)
    {
        int i;

        info->cipherName[0] = 0;
        for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++)
            info->packetNames[i][0] = 0;
        info->numberPackets = 0;
        info->negotiationError = 0;
    }

    /* Set Final HandShakeInfo parameters */
    void FinishHandShakeInfo(HandShakeInfo* info, const SSL* ssl)
    {
        int i;
        int sz = sizeof(cipher_name_idx)/sizeof(int); 

        for (i = 0; i < sz; i++)
            if (ssl->options.cipherSuite == (byte)cipher_name_idx[i]) {
                strncpy(info->cipherName, cipher_names[i], MAX_CIPHERNAME_SZ);
                break;
            }

        /* error max and min are negative numbers */
        if (ssl->error <= MIN_PARAM_ERR && ssl->error >= MAX_PARAM_ERR)
            info->negotiationError = ssl->error;
    }

   
    /* Add name to info packet names, increase packet name count */
    void AddPacketName(const char* name, HandShakeInfo* info)
    {
        if (info->numberPackets < MAX_PACKETS_HANDSHAKE) {
            strncpy(info->packetNames[info->numberPackets++], name,
                    MAX_PACKETNAME_SZ);
        }
    } 


    /* Initialisze TimeoutInfo */
    void InitTimeoutInfo(TimeoutInfo* info)
    {
        int i;

        info->timeoutName[0] = 0;
        info->flags          = 0;

        for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++) {
            info->packets[i].packetName[0]     = 0;
            info->packets[i].timestamp.tv_sec  = 0;
            info->packets[i].timestamp.tv_usec = 0;
            info->packets[i].bufferValue       = 0;
            info->packets[i].valueSz           = 0;
        }
        info->numberPackets        = 0;
        info->timeoutValue.tv_sec  = 0;
        info->timeoutValue.tv_usec = 0;
    }


    /* Free TimeoutInfo */
    void FreeTimeoutInfo(TimeoutInfo* info, void* heap)
    {
        int i;
        for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++)
            if (info->packets[i].bufferValue) {
                XFREE(info->packets[i].bufferValue, heap);
                info->packets[i].bufferValue = 0;
            }

    }


    /* Add PacketInfo to TimeoutInfo */
    void AddPacketInfo(const char* name, TimeoutInfo* info, const byte* data,
                       int sz, void* heap)
    {
        if (info->numberPackets < (MAX_PACKETS_HANDSHAKE - 1)) {
            Timeval currTime;

            /* may add name after */
            if (name)
                strncpy(info->packets[info->numberPackets].packetName, name,
                        MAX_PACKETNAME_SZ);

            /* add data, put in buffer if bigger than static buffer */
            info->packets[info->numberPackets].valueSz = sz;
            if (sz < MAX_VALUE_SZ)
                memcpy(info->packets[info->numberPackets].value, data, sz);
            else {
                info->packets[info->numberPackets].bufferValue = XMALLOC(sz,
                                                                         heap);
                if (!info->packets[info->numberPackets].bufferValue)
                    /* let next alloc catch, just don't fill, not fatal here  */
                    info->packets[info->numberPackets].valueSz = 0;
                else
                    memcpy(info->packets[info->numberPackets].bufferValue,
                           data, sz);
            }
            gettimeofday(&currTime, 0);
            info->packets[info->numberPackets].timestamp.tv_sec  =
                                                             currTime.tv_sec;
            info->packets[info->numberPackets].timestamp.tv_usec =
                                                             currTime.tv_usec;
            info->numberPackets++;
        }
    }


    /* Add packet name to previsouly added packet info */
    void AddLateName(const char* name, TimeoutInfo* info)
    {
        /* make sure we have a valid previous one */
        if (info->numberPackets > 0 && info->numberPackets <
                                                        MAX_PACKETS_HANDSHAKE) {
            strncpy(info->packets[info->numberPackets - 1].packetName, name,
                    MAX_PACKETNAME_SZ);
        }
    }

    /* Add record header to previsouly added packet info */
    void AddLateRecordHeader(const RecordLayerHeader* rl, TimeoutInfo* info)
    {
        /* make sure we have a valid previous one */
        if (info->numberPackets > 0 && info->numberPackets <
                                                        MAX_PACKETS_HANDSHAKE) {
            if (info->packets[info->numberPackets - 1].bufferValue)
                memcpy(info->packets[info->numberPackets - 1].bufferValue, rl,
                       RECORD_HEADER_SZ);
            else
                memcpy(info->packets[info->numberPackets - 1].value, rl,
                       RECORD_HEADER_SZ);
        }
    }

#endif /* CYASSL_CALLBACKS */


/* client only parts */
#ifndef NO_CYASSL_CLIENT

    int SendClientHello(SSL* ssl)
    {
        byte              *output;
        RecordLayerHeader *rl;
        HandShakeHeader   *hs;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                idSz = ssl->options.resuming ? ID_LEN : 0;
        int                ret;

        length = sizeof(ProtocolVersion) + RAN_LEN
               + idSz + ENUM_LEN                      
               + ssl->suites.suiteSz + SUITE_LEN
               + COMP_LEN  + ENUM_LEN;

        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        /* check for avalaible size */
        if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.idx;

        /* handshake header */
        hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
        hs->type = client_hello;
        c32to24(length, hs->length);

        /* record layer header */
        rl = (RecordLayerHeader*)output;
        rl->type    = handshake;
        rl->version = ssl->version;
        c16toa((word16)(length + HANDSHAKE_HEADER_SZ), rl->length);

            /* client hello, first version */
        memcpy(output + idx, &ssl->version, sizeof(ProtocolVersion));
        idx += sizeof(ProtocolVersion);
        ssl->chVersion = ssl->version;  /* store in case changed */

            /* then random */
        RNG_GenerateBlock(&ssl->rng, output + idx, RAN_LEN);
                /* store random */
        memcpy(ssl->arrays.clientRandom, output + idx, RAN_LEN);
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
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;
            
        HashOutput(ssl, output, sendSz, 0);

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;

#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("ClientHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ClientHello", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
#endif

        ssl->buffers.outputBuffer.length += sendSz;

        return SendBuffered(ssl);
    }


    static int DoServerHello(SSL* ssl, const byte* input, word32* inOutIdx)
    {
        byte b;
        byte compression;
        ProtocolVersion pv;
        word32 i = *inOutIdx;

#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("ServerHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("ServerHello", &ssl->timeoutInfo);
#endif
        memcpy(&pv, input + i, sizeof(pv));
        i += sizeof(pv);
        memcpy(ssl->arrays.serverRandom, input + i, RAN_LEN);
        i += RAN_LEN;
        b = input[i++];
        if (b) {
            memcpy(ssl->arrays.sessionID, input + i, b);
            i += b;
        }
        ssl->options.cipherSuite = input[++i];  
        compression = input[++i];
        ++i;   /* 2nd byte */

        if (compression != ZLIB_COMPRESSION && ssl->options.usingCompression)
            ssl->options.usingCompression = 0;  /* turn off if server refused */
        
        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        *inOutIdx = i;

        if (ssl->options.resuming) {
            if (memcmp(ssl->arrays.sessionID, ssl->session.sessionID, ID_LEN)
                                                                        == 0) {
                if (SetCipherSpecs(ssl) == 0) {
                    memcpy(ssl->arrays.masterSecret, ssl->session.masterSecret,
                           SECRET_LEN);
                    if (ssl->options.tls)
                        DeriveTlsKeys(ssl);
                    else
                        DeriveKeys(ssl);
                    ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
                    return 0;
                }
                else
                    return UNSUPPORTED_SUITE;
            }
            else
                ssl->options.resuming = 0; /* server denied resumption try */
        }

        return SetCipherSpecs(ssl);
    }


    /* just read in and ignore for now TODO: */
    static int DoCertificateRequest(SSL* ssl, const byte* input, word32*
                                    inOutIdx)
    {
        word16 len;
       
        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("CertificateRequest", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddLateName("CertificateRequest", &ssl->timeoutInfo);
        #endif
        len = input[(*inOutIdx)++];

        /* types, read in here */
        *inOutIdx += len;
        ato16(&input[*inOutIdx], &len);
        *inOutIdx += LENGTH_SZ;

        /* authorities */
        while (len) {
            word16 dnSz;
       
            ato16(&input[*inOutIdx], &dnSz);
            *inOutIdx += (REQUEST_HEADER + dnSz);
            len -= dnSz + REQUEST_HEADER;
        }

        /* don't send client cert or cert verify if user hasn't provided
           cert or private key */
        if (ssl->buffers.certificate.buffer && ssl->buffers.key.buffer)
            ssl->options.sendVerify = 1;

        return 0;
    }


    static int DoServerKeyExchange(SSL* ssl, const byte* input, word32*
                                   inOutIdx)
    {
    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ServerKeyExchange", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddLateName("ServerKeyExchange", &ssl->timeoutInfo);
    #endif

    #ifndef NO_PSK
        if (ssl->specs.kea == psk_kea) {
            word16 length;
           
            ato16(&input[*inOutIdx], &length);
            *inOutIdx += LENGTH_SZ;
            memcpy(ssl->arrays.server_hint, &input[*inOutIdx],
                   min(length, MAX_PSK_ID_LEN));
            if (length < MAX_PSK_ID_LEN)
                ssl->arrays.server_hint[length] = 0;
            else
                ssl->arrays.server_hint[MAX_PSK_ID_LEN - 1] = 0;
            *inOutIdx += length;

            return 0;
        }
    #endif
    #ifdef OPENSSL_EXTRA
        if (ssl->specs.kea == diffie_hellman_kea)
        {
        word16 length, verifySz, messageTotal = 6;  /* pSz + gSz + pubSz */
        byte   messageVerify[MAX_DH_SZ];
        byte*  signature;
        byte   hash[FINISHED_SZ];
        Md5    md5;
        Sha    sha;

        /* p */
        ato16(&input[*inOutIdx], &length);
        *inOutIdx += LENGTH_SZ;
        messageTotal += length;

        ssl->buffers.serverDH_P.buffer = (byte*) XMALLOC(length, ssl->heap);
        if (ssl->buffers.serverDH_P.buffer)
            ssl->buffers.serverDH_P.length = length;
        else
            return MEMORY_ERROR;
        memcpy(ssl->buffers.serverDH_P.buffer, &input[*inOutIdx], length);
        *inOutIdx += length;

        /* g */
        ato16(&input[*inOutIdx], &length);
        *inOutIdx += LENGTH_SZ;
        messageTotal += length;

        ssl->buffers.serverDH_G.buffer = (byte*) XMALLOC(length, ssl->heap);
        if (ssl->buffers.serverDH_G.buffer)
            ssl->buffers.serverDH_G.length = length;
        else
            return MEMORY_ERROR;
        memcpy(ssl->buffers.serverDH_G.buffer, &input[*inOutIdx], length);
        *inOutIdx += length;

        /* pub */
        ato16(&input[*inOutIdx], &length);
        *inOutIdx += LENGTH_SZ;
        messageTotal += length;

        ssl->buffers.serverDH_Pub.buffer = (byte*) XMALLOC(length, ssl->heap);
        if (ssl->buffers.serverDH_Pub.buffer)
            ssl->buffers.serverDH_Pub.length = length;
        else
            return MEMORY_ERROR;
        memcpy(ssl->buffers.serverDH_Pub.buffer, &input[*inOutIdx], length);
        *inOutIdx += length;

        /* save message for hash verify */
        if (messageTotal > sizeof(messageVerify))
            return BUFFER_ERROR;
        memcpy(messageVerify, &input[*inOutIdx - messageTotal], messageTotal);
        verifySz = messageTotal;

        /* signature */
        ato16(&input[*inOutIdx], &length);
        *inOutIdx += LENGTH_SZ;

        signature = (byte*)&input[*inOutIdx];
        *inOutIdx += length;

        /* verify signature */

        /* md5 */
        InitMd5(&md5);
        Md5Update(&md5, ssl->arrays.clientRandom, RAN_LEN);
        Md5Update(&md5, ssl->arrays.serverRandom, RAN_LEN);
        Md5Update(&md5, messageVerify, verifySz);
        Md5Final(&md5, hash);

        /* sha */
        InitSha(&sha);
        ShaUpdate(&sha, ssl->arrays.clientRandom, RAN_LEN);
        ShaUpdate(&sha, ssl->arrays.serverRandom, RAN_LEN);
        ShaUpdate(&sha, messageVerify, verifySz);
        ShaFinal(&sha, &hash[MD5_DIGEST_SIZE]);

        /* rsa for now */
        {
            int   ret;
            byte* out;

            if (!ssl->peerRsaKeyPresent)
                return NO_PEER_KEY;

            ret = RsaSSL_VerifyInline(signature, length,&out, &ssl->peerRsaKey);

            if (ret != sizeof(hash) || memcmp(out, hash, sizeof(hash)))
                return VERIFY_SIGN_ERROR;
        }

        ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;

        return 0;
        }  /* dh_kea */
    #endif /* OPENSSL_EXTRA */
        return -1;  /* not supported by build */
    }


    int SendClientKeyExchange(SSL* ssl)
    {
        byte   encSecret[ENCRYPT_LEN];
        word32 encSz = 0;
        word32 idx = 0;
        int    ret = 0;

        if (ssl->specs.kea == rsa_kea) {
            RNG_GenerateBlock(&ssl->rng, ssl->arrays.preMasterSecret,
                              SECRET_LEN);
            ssl->arrays.preMasterSecret[0] = ssl->chVersion.major;
            ssl->arrays.preMasterSecret[1] = ssl->chVersion.minor;
            ssl->arrays.preMasterSz = SECRET_LEN;

            if (ssl->peerRsaKeyPresent == 0)
                return NO_PEER_KEY;

            ret = RsaPublicEncrypt(ssl->arrays.preMasterSecret, SECRET_LEN,
                             encSecret, sizeof(encSecret), &ssl->peerRsaKey,
                             &ssl->rng);
            if (ret > 0) {
                encSz = ret;
                ret = 0;   /* set success to 0 */
            }
        #ifdef OPENSSL_EXTRA
        } else if (ssl->specs.kea == diffie_hellman_kea) {
            buffer  serverP   = ssl->buffers.serverDH_P;
            buffer  serverG   = ssl->buffers.serverDH_G;
            buffer  serverPub = ssl->buffers.serverDH_Pub;
            byte    priv[ENCRYPT_LEN];
            word32  privSz;
            DhKey   key;

            InitDhKey(&key);
            ret = DhSetKey(&key, serverP.buffer, serverP.length,
                           serverG.buffer, serverG.length);
            if (ret == 0)
                /* for DH, encSecret is Yc, agree is pre-master */
                ret = DhGenerateKeyPair(&key, &ssl->rng, priv, &privSz,
                                        encSecret, &encSz);
            if (ret == 0)
                ret = DhAgree(&key, ssl->arrays.preMasterSecret,
                              &ssl->arrays.preMasterSz, priv, privSz,
                              serverPub.buffer, serverPub.length);
            FreeDhKey(&key);
        #endif /* OPENSSL_EXTRA */
        #ifndef NO_PSK
        } else if (ssl->specs.kea == psk_kea) {
            byte* pms = ssl->arrays.preMasterSecret;

            ssl->arrays.psk_keySz = ssl->options.client_psk_cb(ssl,
                ssl->arrays.server_hint, ssl->arrays.client_identity,
                MAX_PSK_ID_LEN, ssl->arrays.psk_key, MAX_PSK_KEY_LEN);
            if (ssl->arrays.psk_keySz == 0 || 
                ssl->arrays.psk_keySz > MAX_PSK_KEY_LEN)
                return PSK_KEY_ERROR;
            encSz = (word32)strlen(ssl->arrays.client_identity);
            if (encSz > MAX_PSK_ID_LEN) return CLIENT_ID_ERROR;
            memcpy(encSecret, ssl->arrays.client_identity, encSz);

            /* make psk pre master secret */
            /* length of key + length 0s + length of key + key */
            c16toa((word16)ssl->arrays.psk_keySz, pms);
            pms += 2;
            memset(pms, 0, ssl->arrays.psk_keySz);
            pms += ssl->arrays.psk_keySz;
            c16toa((word16)ssl->arrays.psk_keySz, pms);
            pms += 2;
            memcpy(pms, ssl->arrays.psk_key, ssl->arrays.psk_keySz);
            ssl->arrays.preMasterSz = ssl->arrays.psk_keySz * 2 + 4;
        #endif /* NO_PSK */
        } else
            return -1; /* unsupported kea */

        if (ret == 0) {
            byte              *output;
            int                sendSz;
            RecordLayerHeader *rl;
            HandShakeHeader   *hs;
            word32             tlsSz = 0;
            
            if (ssl->options.tls || ssl->specs.kea == diffie_hellman_kea)
                tlsSz = 2;

            sendSz = encSz + tlsSz + HANDSHAKE_HEADER_SZ +RECORD_HEADER_SZ;

            /* check for avalaible size */
            if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
                return ret;

            /* get ouput buffer */
            output = ssl->buffers.outputBuffer.buffer + 
                     ssl->buffers.outputBuffer.idx;

            idx = HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

            /* handshake header */
            hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
            hs->type = client_key_exchange;
            c32to24(encSz + tlsSz, hs->length);

            /* record layer header */
            rl = (RecordLayerHeader*)output;
            rl->type    = handshake;
            rl->version = ssl->version;
            c16toa((word16)(encSz + tlsSz + HANDSHAKE_HEADER_SZ), rl->length);

            if (tlsSz) {
                c16toa((word16)encSz, &output[idx]);
                idx += 2;
            }
            memcpy(output + idx, encSecret, encSz);
            idx += encSz;

            HashOutput(ssl, output, sendSz, 0);

            #ifdef CYASSL_CALLBACKS
                if (ssl->hsInfoOn)
                    AddPacketName("ClientKeyExchange", &ssl->handShakeInfo);
                if (ssl->toInfoOn)
                    AddPacketInfo("ClientKeyExchange", &ssl->timeoutInfo,
                                  output, sendSz, ssl->heap);
            #endif

            ssl->buffers.outputBuffer.length += sendSz;

            ret = SendBuffered(ssl);;
        }
    
        if (ret == 0 || ret == WANT_WRITE) {
            int tmpRet = MakeMasterSecret(ssl);
            if (tmpRet != 0)
                ret = tmpRet;   /* save WANT_WRITE unless more serious */
            ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
        }

        return ret;
    }

    int SendCertificateVerify(SSL* ssl)
    {
        byte              *output;
        RecordLayerHeader *rl;
        HandShakeHeader   *hs;
        int                sendSz = 0, length, ret;
        word32             idx = 0;
        RsaKey             key;

        /* check for avalaible size */
        if ((ret = CheckAvalaibleSize(ssl, MAX_CERT_VERIFY_SZ)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.idx;

        BuildCertHashes(ssl, &ssl->certHashes);

        /* TODO: when add DSS support check here  */
        InitRsaKey(&key, ssl->heap);
        ret = RsaPrivateKeyDecode(ssl->buffers.key.buffer, &idx, &key,
                                  ssl->buffers.key.length); 
        if (ret == 0) {
            byte* verify = (byte*)&output[RECORD_HEADER_SZ +
                                          HANDSHAKE_HEADER_SZ];
            length = RsaEncryptSize(&key);
            c16toa((word16)length, verify);   /* prepend verify header */

            ret = RsaSSL_Sign(ssl->certHashes.md5, sizeof(Hashes), verify +
                  VERIFY_HEADER, ENCRYPT_LEN, &key, &ssl->rng);

            if (ret > 0) {
                ret = 0;  /* reset */
                hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
                hs->type = certificate_verify;
                c32to24(length + VERIFY_HEADER, hs->length);

                rl = (RecordLayerHeader*)output;
                rl->type = handshake;
                rl->version = ssl->version;
                c16toa((word16)(length + VERIFY_HEADER + HANDSHAKE_HEADER_SZ),
                       rl->length);

                sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + length +
                            VERIFY_HEADER;
                HashOutput(ssl, output, sendSz, 0);
            }
        }

        FreeRsaKey(&key);

        if (ret == 0) {
            #ifdef CYASSL_CALLBACKS
                if (ssl->hsInfoOn)
                    AddPacketName("CertificateVerify", &ssl->handShakeInfo);
                if (ssl->toInfoOn)
                    AddPacketInfo("CertificateVerify", &ssl->timeoutInfo,
                                  output, sendSz, ssl->heap);
            #endif
            ssl->buffers.outputBuffer.length += sendSz;
            return SendBuffered(ssl);
        }
        else
            return ret;
    }



#endif /* NO_CYASSL_CLIENT */


#ifndef NO_CYASSL_SERVER

    int SendServerHello(SSL* ssl)
    {
        byte              *output;
        RecordLayerHeader *rl;
        HandShakeHeader   *hs;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                ret;

        length = sizeof(ProtocolVersion) + RAN_LEN
               + ID_LEN + ENUM_LEN                 
               + SUITE_LEN 
               + ENUM_LEN;

        /* check for avalaible size */
        if ((ret = CheckAvalaibleSize(ssl, MAX_HELLO_SZ)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer + 
                 ssl->buffers.outputBuffer.idx;

        /* handshake header */
        hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
        hs->type = server_hello;
        c32to24(length, hs->length);

        /* record layer header */
        rl = (RecordLayerHeader*)output;
        rl->type    = handshake;
        rl->version = ssl->version;
        c16toa((word16)(length + HANDSHAKE_HEADER_SZ), rl->length);

        /* now write to output */
            /* first version */
        memcpy(output + idx, &ssl->version, sizeof(ProtocolVersion));
        idx += sizeof(ProtocolVersion);

            /* then random */
        if (!ssl->options.resuming)         
            RNG_GenerateBlock(&ssl->rng, ssl->arrays.serverRandom, RAN_LEN);
        memcpy(output + idx, ssl->arrays.serverRandom, RAN_LEN);
        idx += RAN_LEN;

            /* then session id */
        output[idx++] = ID_LEN;
        if (!ssl->options.resuming)
            RNG_GenerateBlock(&ssl->rng, ssl->arrays.sessionID, ID_LEN);
        memcpy(output + idx, ssl->arrays.sessionID, ID_LEN);
        idx += ID_LEN;

            /* then cipher suite */
        output[idx++] = 0x00; 
        output[idx++] = ssl->options.cipherSuite;

            /* last, compression */
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;
            
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        ssl->buffers.outputBuffer.length += sendSz;
        HashOutput(ssl, output, sendSz, 0);

        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("ServerHello", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("ServerHello", &ssl->timeoutInfo, output, sendSz,
                              ssl->heap);
        #endif

        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        return SendBuffered(ssl);
    }

    int SendServerKeyExchange(SSL* ssl)
    {
        byte              *output;
        RecordLayerHeader *rl;
        HandShakeHeader   *hs;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                ret = 0;

        if (ssl->specs.kea != psk_kea) return 0;

        #ifndef NO_PSK
            if (ssl->arrays.server_hint[0] == 0) return 0; /* don't send */

            /* include size part */
            length = (word32)strlen(ssl->arrays.server_hint);
            if (length > MAX_PSK_ID_LEN) return SERVER_HINT_ERROR;
            length += + HINT_LEN_SZ;
            sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

            /* check for avalaible size */
            if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
               return ret;

            /* get ouput buffer */
            output = ssl->buffers.outputBuffer.buffer + 
                     ssl->buffers.outputBuffer.idx;

            /* handshake header */
            hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
            hs->type = server_key_exchange;
            c32to24(length, hs->length);

            /* record layer header */
            rl = (RecordLayerHeader*)output;
            rl->type    = handshake;
            rl->version = ssl->version;
            c16toa((word16)(length + HANDSHAKE_HEADER_SZ), rl->length);

            /* key data */
            c16toa((word16)(length - HINT_LEN_SZ), output + idx);
            idx += HINT_LEN_SZ;
            memcpy(output + idx, ssl->arrays.server_hint, length -HINT_LEN_SZ);

            HashOutput(ssl, output, sendSz, 0);

            #ifdef CYASSL_CALLBACKS
                if (ssl->hsInfoOn)
                    AddPacketName("ServerKeyExchange", &ssl->handShakeInfo);
                if (ssl->toInfoOn)
                    AddPacketInfo("ServerKeyExchange", &ssl->timeoutInfo,
                                  output, sendSz, ssl->heap);
            #endif

            ssl->buffers.outputBuffer.length += sendSz;
            ret = SendBuffered(ssl);
            ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;
        #endif /*NO_PSK */

        return ret;
    }


    static int MatchSuite(SSL* ssl, Suites* peerSuites)
    {
        word16 i, j;

        /* & 0x1 equivalent % 2 */
        if (peerSuites->suiteSz == 0 || peerSuites->suiteSz & 0x1)
            return MATCH_SUITE_ERROR;

        /* start with best, if a match we are good, Ciphers are at odd index
           since all SSL and TLS ciphers have 0x00 first byte               */
        for (i = 1; i < ssl->suites.suiteSz; i += 2)
            for (j = 1; j < peerSuites->suiteSz; j += 2)
                if (ssl->suites.suites[i] == peerSuites->suites[j]) {
                    ssl->options.cipherSuite = ssl->suites.suites[i];
                    return SetCipherSpecs(ssl);
                }

        return MATCH_SUITE_ERROR;
    }


    /* process alert, return level */
    static int ProcessOldClientHello(SSL* ssl, const byte* input,
                                     word32* inOutIdx, word32 inSz, word16 sz)
    {
        word32          idx = *inOutIdx;
        word16          sessionSz;
        word16          randomSz;
        word16          i, j;
        ProtocolVersion pv;
        Suites          clSuites;

#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ClientHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddLateName("ClientHello", &ssl->timeoutInfo);
#endif

        /* manually hash input since different format */
        Md5Update(&ssl->hashMd5, input + idx, sz);
        ShaUpdate(&ssl->hashSha, input + idx, sz);

        /* does this value mean client_hello? */
        idx++;

        /* version */
        pv.major = input[idx++];
        pv.minor = input[idx++];
        ssl->chVersion = pv;  /* store */

        if (ssl->version.minor > 0 && pv.minor == 0) {
            /* turn off tls */
            ssl->options.tls    = 0;
            ssl->options.tls1_1 = 0;
            ssl->version.minor  = 0;
            InitSuites(&ssl->suites, ssl->version, ssl->options.haveDH, FALSE);
        }

        /* suite size */
        ato16(&input[idx], &clSuites.suiteSz);
        idx += 2;

        /* session size */
        ato16(&input[idx], &sessionSz);
        idx += 2;
    
        /* random size */
        ato16(&input[idx], &randomSz);
        idx += 2;

        /* suites */
        for (i = 0, j = 0; i < clSuites.suiteSz; i += 3) {    
            byte first = input[idx++];
            if (!first) { /* implicit: skip sslv2 type */
                memcpy(&clSuites.suites[j], &input[idx], 2);
                j += 2;
            }
            idx += 2;
        }
        clSuites.suiteSz = j;

        /* session id */
        if (sessionSz) {
            memcpy(ssl->arrays.sessionID, input + idx, sessionSz);
            idx += sessionSz;
            ssl->options.resuming = 1;
        }

        /* random */
        if (randomSz < RAN_LEN)
            memset(ssl->arrays.clientRandom, 0, RAN_LEN - randomSz);
        memcpy(&ssl->arrays.clientRandom[RAN_LEN - randomSz], input + idx,
               randomSz);
        idx += randomSz;

        if (ssl->options.usingCompression)
            ssl->options.usingCompression = 0;  /* turn off */

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;
        *inOutIdx = idx;

        /* DoClientHello uses same resume code */
        while (ssl->options.resuming) {  /* let's try */
            SSL_SESSION* session = GetSession(ssl, ssl->arrays.masterSecret);
            if (!session) {
                ssl->options.resuming = 0;
                break;   /* session lookup failed */
            }
            if (MatchSuite(ssl, &clSuites) < 0)
                return UNSUPPORTED_SUITE;

            RNG_GenerateBlock(&ssl->rng, ssl->arrays.serverRandom, RAN_LEN);
            if (ssl->options.tls)
                DeriveTlsKeys(ssl);
            else
                DeriveKeys(ssl);
            ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;

            return 0;
        }

        return MatchSuite(ssl, &clSuites);
    }


    static int DoClientHello(SSL* ssl, const byte* input, word32* inOutIdx,
                             word32 totalSz, word32 helloSz)
    {
        byte b;
        ProtocolVersion pv;
        Suites          clSuites;
        word32 i = *inOutIdx;
        word32 begin = i;

#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("ClientHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("ClientHello", &ssl->timeoutInfo);
#endif
        /* make sure can read up to session */
        if (i + sizeof(pv) + RAN_LEN + ENUM_LEN > totalSz)
            return INCOMPLETE_DATA;

        memcpy(&pv, input + i, sizeof(pv));
        ssl->chVersion = pv;   /* store */
        i += sizeof(pv);
        if (ssl->version.minor > 0 && pv.minor == 0) {
            /* turn off tls */
            ssl->options.tls    = 0;
            ssl->options.tls1_1 = 0;
            ssl->version.minor  = 0;
            InitSuites(&ssl->suites, ssl->version, ssl->options.haveDH, FALSE);
        }
        memcpy(ssl->arrays.clientRandom, input + i, RAN_LEN);
        i += RAN_LEN;
        b = input[i++];
        if (b) {
            if (i + ID_LEN > totalSz)
                return INCOMPLETE_DATA;
            memcpy(ssl->arrays.sessionID, input + i, ID_LEN);
            i += b;
            ssl->options.resuming= 1; /* client wants to resume */
        }

        if (i + LENGTH_SZ > totalSz)
            return INCOMPLETE_DATA;
        /* suites */
        ato16(&input[i], &clSuites.suiteSz);
        i += 2;

        /* suites and comp len */
        if (i + clSuites.suiteSz + ENUM_LEN > totalSz)
            return INCOMPLETE_DATA;
        memcpy(clSuites.suites, input + i, clSuites.suiteSz);
        i += clSuites.suiteSz;

        b = input[i++];  /* comp len */
        if (i + b > totalSz)
            return INCOMPLETE_DATA;

        if (ssl->options.usingCompression) {
            int match = 0;
            while (b--) {
                byte comp = input[i++];
                if (comp == ZLIB_COMPRESSION)
                    match = 1;
            }
            if (!match)
                ssl->options.usingCompression = 0;  /* turn off */
        }
        else
            i += b;  /* ignore, since we're not on */

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;

        *inOutIdx = i;
        if ( (i - begin) < helloSz)
            *inOutIdx = begin + helloSz;  /* skip extensions */
        
        /* ProcessOld uses same resume code */
        while (ssl->options.resuming) {  /* let's try */
            SSL_SESSION* session = GetSession(ssl, ssl->arrays.masterSecret);
            if (!session) {
                ssl->options.resuming = 0;
                break;   /* session lookup failed */
            }
            if (MatchSuite(ssl, &clSuites) < 0)
                return UNSUPPORTED_SUITE;

            RNG_GenerateBlock(&ssl->rng, ssl->arrays.serverRandom, RAN_LEN);
            if (ssl->options.tls)
                DeriveTlsKeys(ssl);
            else
                DeriveKeys(ssl);
            ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;

            return 0;
        }
        return MatchSuite(ssl, &clSuites);
    }


    static int DoCertificateVerify(SSL* ssl, byte* input, word32* inOutsz,
                                   word32 totalSz)
    {
        word16      sz = 0;
        word32      i = *inOutsz;
        int         ret = VERIFY_CERT_ERROR;   /* start in error state */
        byte*       sig;
        byte*       out;
        int         outLen;

        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("CertificateVerify", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddLateName("CertificateVerify", &ssl->timeoutInfo);
        #endif
        if ( (i + VERIFY_HEADER) > totalSz)
            return INCOMPLETE_DATA;

        ato16(&input[i], &sz);
        i += VERIFY_HEADER;

        if ( (i + sz) > totalSz)
            return INCOMPLETE_DATA;

        if (sz > ENCRYPT_LEN)
            return BUFFER_ERROR;

        sig = &input[i];
        *inOutsz = i + sz;
        /* TODO: when add DSS support check here  */
        if (ssl->peerRsaKeyPresent != 0) {
            outLen = RsaSSL_VerifyInline(sig, sz, &out, &ssl->peerRsaKey);
            if (memcmp(out, ssl->certHashes.md5, sizeof(ssl->certHashes)) == 0)
                ret = 0;
        }
        return ret;
    }


    int SendServerHelloDone(SSL* ssl)
    {
        byte              *output;
        RecordLayerHeader *rl;
        HandShakeHeader   *hs;
        int                sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                ret;

        /* check for avalaible size */
        if ((ret = CheckAvalaibleSize(ssl, sendSz)) != 0)
            return ret;

        /* get ouput buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.idx;

        /* handshake header */
        hs = (HandShakeHeader*)&output[RECORD_HEADER_SZ];
        hs->type = server_hello_done;
        c32to24(0, hs->length);

        /* record layer header */
        rl = (RecordLayerHeader*)output;
        rl->type    = handshake;
        rl->version = ssl->version;
        c16toa(HANDSHAKE_HEADER_SZ, rl->length);

        HashOutput(ssl, output, sendSz, 0);
#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ServerHelloDone", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ServerHelloDone", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
#endif
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;

        ssl->buffers.outputBuffer.length += sendSz;

        return SendBuffered(ssl);
    }


    static int DoClientKeyExchange(SSL* ssl, byte* input,
                                   word32* inOutIdx)
    {
        int    ret = 0;
        word32 length = 0;
        byte*  out;

        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("ClientKeyExchange", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddLateName("ClientKeyExchange", &ssl->timeoutInfo);
        #endif
        if (ssl->specs.kea == rsa_kea) {
            word32 idx = 0;
            RsaKey key;
            byte*  tmp = 0;

            InitRsaKey(&key, ssl->heap);

            if (ssl->buffers.key.buffer)
                ret = RsaPrivateKeyDecode(ssl->buffers.key.buffer, &idx, &key,
                                          ssl->buffers.key.length);
            else
                return NO_PRIVATE_KEY;

            if (ret == 0) {
                length = RsaEncryptSize(&key);
                ssl->arrays.preMasterSz = SECRET_LEN;

                if (ssl->options.tls)
                    (*inOutIdx) += 2;
                tmp = input + *inOutIdx;
                *inOutIdx += length;

                if (RsaPrivateDecryptInline(tmp, length, &out, &key) ==
                                                             SECRET_LEN) {
                    memcpy(ssl->arrays.preMasterSecret, out, SECRET_LEN);
                    if (ssl->arrays.preMasterSecret[0] != ssl->chVersion.major
                     ||
                        ssl->arrays.preMasterSecret[1] != ssl->chVersion.minor)

                        ret = PMS_VERSION_ERROR;
                    else
                        ret = MakeMasterSecret(ssl);
                }
                else
                    ret = RSA_PRIVATE_ERROR;
            }

            FreeRsaKey(&key);
#ifndef NO_PSK
        } else if (ssl->specs.kea == psk_kea) {
            byte* pms = ssl->arrays.preMasterSecret;
            word16 ci_sz;

            ato16(&input[*inOutIdx], &ci_sz);
            *inOutIdx += LENGTH_SZ;
            if (ci_sz > MAX_PSK_ID_LEN) return CLIENT_ID_ERROR;

            memcpy(ssl->arrays.client_identity, &input[*inOutIdx], ci_sz);
            *inOutIdx += ci_sz;
            ssl->arrays.client_identity[ci_sz] = 0;

            ssl->arrays.psk_keySz = ssl->options.server_psk_cb(ssl,
                ssl->arrays.client_identity, ssl->arrays.psk_key,
                MAX_PSK_KEY_LEN);
            if (ssl->arrays.psk_keySz == 0 || 
                ssl->arrays.psk_keySz > MAX_PSK_KEY_LEN) return PSK_KEY_ERROR;
            
            /* make psk pre master secret */
            /* length of key + length 0s + length of key + key */
            c16toa((word16)ssl->arrays.psk_keySz, pms);
            pms += 2;
            memset(pms, 0, ssl->arrays.psk_keySz);
            pms += ssl->arrays.psk_keySz;
            c16toa((word16)ssl->arrays.psk_keySz, pms);
            pms += 2;
            memcpy(pms, ssl->arrays.psk_key, ssl->arrays.psk_keySz);
            ssl->arrays.preMasterSz = ssl->arrays.psk_keySz * 2 + 4;

            ret = MakeMasterSecret(ssl);
#endif /* NO_PSK */
        }

        if (ret == 0) {
            ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
            if (ssl->options.verifyPeer)
                BuildCertHashes(ssl, &ssl->certHashes);
        }

        return ret;
    }

#endif /* NO_CYASSL_SERVER */



#ifdef DEBUG_CYASSL

    static int logging = 0;


    int CyaSSL_Debugging_ON(void)
    {
        logging = 1;
        return 0;
    }


    void CyaSSL_Debugging_OFF(void)
    {
        logging = 0;
    }


    void CYASSL_MSG(const char* msg)
    {
        if (logging)
            fprintf(stderr, "%s\n", msg);
    }


    void CYASSL_ENTER(const char* msg)
    {
        if (logging) {
            char buffer[80];
            sprintf(buffer, "CyaSSL Entering %s", msg);
            CYASSL_MSG(buffer);
        }
    }


    void CYASSL_LEAVE(const char* msg, int ret)
    {
        if (logging) {
            char buffer[80];
            sprintf(buffer, "CyaSSL Leaving %s, return %d", msg, ret);
            CYASSL_MSG(buffer);
        }
    }


    void CYASSL_ERROR(int error)
    {
        if (logging) {
            char buffer[80];
            sprintf(buffer, "CyaSSL error occured, error = %d", error);
            CYASSL_MSG(buffer);
        }
    }


#else   /* DEBUG_CYASSL */

    int CyaSSL_Debugging_ON(void)
    {
        return -1;    /* not compiled in */
    }


    void CyaSSL_Debugging_OFF(void)
    {
        /* already off */
    }

#endif  /* DEBUG_CYASSL */
