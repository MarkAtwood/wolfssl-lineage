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

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

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
    #include <fcntl.h>
#endif /* _WIN32 */

#ifdef __sun
    #include <sys/filio.h>
#endif

#define TRUE  1
#define FALSE 0


#ifdef _WIN32
    const int SOCKET_EINVAL = WSAEINVAL;
    const int SOCKET_EWOULDBLOCK = WSAEWOULDBLOCK;
    const int SOCKET_EAGAIN = WSAEWOULDBLOCK;
    const int SOCKET_ECONNRESET = WSAECONNRESET;
    const int SOCKET_EINTR = WSAEINTR;
#else
    const int SOCKET_EINVAL = EINVAL;
    const int SOCKET_EWOULDBLOCK = EWOULDBLOCK;
    const int SOCKET_EAGAIN = EAGAIN;
    const int SOCKET_ECONNRESET = ECONNRESET;
    const int SOCKET_EINTR = EINTR;

    SOCKET_T INVALID_SOCKET = -1;
#endif /* _WIN32 */


#ifndef NO_CYASSL_CLIENT
    static int DoServerHello(SSL* ssl, const byte* input, word32*);
    static int DoCertificateRequest(SSL* ssl, const byte* input, word32*);
    static int DoServerKeyExchange(SSL* ssl, const byte* input, word32*);
#endif


#ifndef NO_CYASSL_SERVER
    static int DoClientHello(SSL* ssl, const byte* input, word32*, word32,
                             word32);
    static int DoCertificateVerify(SSL* ssl, const byte*, word32*, word32);
    static int ProcessOldClientHello(SSL*, const byte*, word32*, word32);
    static int DoClientKeyExchange(SSL* ssl, const byte* input, word32*);
#endif


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
        return XMALLOC(item * size);
    }


    void myFree(void* opaque, void* memory)
    {
        XFREE(memory);
    }


    /* init zlib comp/decomp streams, 0 on success */
    static int InitStreams(SSL* ssl)
    {
        ssl->c_stream.zalloc = (alloc_func)myAlloc;
        ssl->c_stream.zfree  = (free_func)myFree;
        ssl->c_stream.opaque = (voidpf)0;

        if (deflateInit(&ssl->c_stream, 8) != Z_OK) return ZLIB_INIT_ERROR;

        ssl->didStreamInit = 1;

        ssl->d_stream.zalloc = (alloc_func)myAlloc;
        ssl->d_stream.zfree  = (free_func)myFree;
        ssl->d_stream.opaque = (voidpf)0;

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
        byte   tmp[LENGTH_SZ];

        /* find size in front of compression */
        tmp[0] = *in++;
        tmp[1] = *in++;
        ato16(tmp, &len);
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
#ifndef NO_PSK
    ctx->havePSK            = 0;
    ctx->server_hint[0]     = 0;
    ctx->client_psk_cb      = 0;
    ctx->server_psk_cb      = 0;
#endif /* NO_PSK */

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
    XFREE(ctx->privateKey.buffer);
    XFREE(ctx->certificate.buffer);
    XFREE(ctx->method);

    FreeSigners(ctx->caList);
    
    XFREE(ctx);
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

    suites->suiteSz = idx;
}


int InitSSL(SSL* ssl, SSL_CTX* ctx)
{
    byte havePSK = 0;

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    ssl->version = ctx->method->version;
    ssl->suites  = ctx->suites;
    ssl->socket  = INVALID_SOCKET;

#ifdef HAVE_LIBZ
    ssl->didStreamInit = 0;
#endif
   
    ssl->buffers.certificate.buffer   = 0;
    ssl->buffers.key.buffer           = 0;
    ssl->buffers.peerCert.buffer      = 0;
    ssl->buffers.peerKey.buffer       = 0;
    ssl->buffers.bufferedData.buffer  = 0;
    ssl->buffers.bufferedInput.buffer = 0;
    ssl->buffers.domainName.buffer    = 0;
    ssl->buffers.serverDH_P.buffer    = 0;
    ssl->buffers.serverDH_G.buffer    = 0;
    ssl->buffers.serverDH_Pub.buffer  = 0;
    ssl->buffers.serverDH_Priv.buffer = 0;
    ssl->writeBuffer.send.buffer      = 0;

    InitRng(&ssl->rng);
    InitMd5(&ssl->hashMd5);
    InitSha(&ssl->hashSha);

    ssl->options.side  = ctx->method->side;
    ssl->error = 0;
    ssl->options.isNonBlocking = 0;  /* clear win32 non-blocking flag */
    ssl->options.connReset = 0;
    ssl->options.isClosed  = 0;
    ssl->options.usingCompression = 0;
    ssl->options.haveDH    = ctx->haveDH;
    ssl->options.usingPSK_cipher = 0;
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

    ssl->keys.encryptionOn = 0;     /* initially off */
    ssl->options.sessionCacheOff      = ctx->sessionCacheOff;
    ssl->options.sessionCacheFlushOff = ctx->sessionCacheFlushOff;

    ssl->options.verifyPeer = ctx->verifyPeer;
    ssl->options.verifyNone = ctx->verifyNone;
    ssl->options.failNoCert = ctx->failNoCert;
    ssl->options.sendVerify = ctx->sendVerify;
    
    ssl->options.resuming = 0;
    ssl->hmac = Hmac;    /* default to SSLv3 */
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
    XFREE(ssl->buffers.serverDH_Priv.buffer);
    XFREE(ssl->buffers.serverDH_Pub.buffer);
    XFREE(ssl->buffers.serverDH_G.buffer);
    XFREE(ssl->buffers.serverDH_P.buffer);
    XFREE(ssl->buffers.domainName.buffer);
    XFREE(ssl->buffers.bufferedInput.buffer);
    XFREE(ssl->buffers.bufferedData.buffer);
    XFREE(ssl->buffers.peerKey.buffer);
    XFREE(ssl->buffers.peerCert.buffer);
    XFREE(ssl->writeBuffer.send.buffer);

#ifdef HAVE_LIBZ
    FreeStreams(ssl);
#endif

    XFREE(ssl);
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


static INLINE void Close(SSL* ssl)
{
    ssl->options.isClosed = 1;

#ifdef _WIN32
    closesocket(ssl->socket);
#else
    close(ssl->socket);
#endif
}


static INLINE int LastError(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}


static INLINE void SetError(int errorCode)
{
#ifdef _WIN32
    WSASetLastError(errorCode);
#else
    errno = errorCode;
#endif
}


static INLINE int IsNonBlocking(SSL* ssl)
{
#ifdef _WIN32
    /* user may switch even though not supposed to, no get sock options for
       win non-blocking so can only tell if this attempt returned EAGAIN, may
       miss incomplete data case where don't call revc() again, so caller 
       should loop                                      
     */
    return ssl->options.isNonBlocking;
#else
    if (ssl->options.isNonBlocking)
        return 1;
    else
        return O_NONBLOCK & fcntl(ssl->socket, F_GETFL, 0);
#endif
}


static word32 Receive(SSL* ssl, byte* buf, word32 sz, int flags)
{
    int recvd;

    assert(ssl->socket != INVALID_SOCKET);
    ssl->options.isNonBlocking = 0; /* clear win32 flag */
retry:
    recvd = recv(ssl->socket, (char *)buf, sz, flags);

    /* idea to seperate error from would block by arnetheduck@gmail.com */
    if (recvd == -1) {
        if (LastError() == SOCKET_EWOULDBLOCK || 
            LastError() == SOCKET_EAGAIN) {
    
            ssl->options.isNonBlocking = 1; /* nonblocking on, 
                                               win32 only way to tell */
            return 0;
        }
        else if (LastError() == SOCKET_ECONNRESET)
            ssl->options.connReset = 1;
        else if (LastError() == SOCKET_EINTR) {
            /* see if we got our timeout */
            #ifdef CYASSL_CALLBACKS
                if (ssl->toInfoOn) {
                    struct itimerval timeout;
                    getitimer(ITIMER_REAL, &timeout);
                    if (timeout.it_value.tv_sec == 0 && 
                                            timeout.it_value.tv_usec == 0) {
                        strncpy(ssl->timeoutInfo.timeoutName,
                                "recv() timeout", MAX_TIMEOUT_NAME_SZ);
                        /* same processing as non blocking (WANT_READ) */
                        ssl->options.isNonBlocking = 1;
                        return 0;
                    }
                }
            #endif
            goto retry;
        }
    }
    else if (recvd == 0) {
        ssl->options.isClosed = 1;
        return (word32) -1;
    }

    return recvd;
}


/* wait if blocking for input, return false(0) for error */
static int Wait(SSL* ssl)
{
    byte b;
    return Receive(ssl, &b, 1, MSG_PEEK) != (word32) -1;
}


/* find out how much data is waiting */
static word32 GetReady(SSL* ssl)
{
    unsigned long ready = 0;

#ifdef _WIN32
    ioctlsocket(ssl->socket, FIONREAD, &ready);
#else
    ioctl(ssl->socket, FIONREAD, &ready);
#endif

    return ready;
}


/* send all data or return error, if WANT_WRITE call again w/ same args */
int Send(SSL* ssl, const byte* buf, int sz, int flags)
{
    const byte* end = buf + sz;

    if (ssl->writeBuffer.send.buffer)
        buf = ssl->writeBuffer.offset;  /* adjust to last offset */

    assert(ssl->socket != INVALID_SOCKET);

    while (buf != end) {
        int sent = send(ssl->socket, (const char*)buf, (int)(end - buf), flags);

        if (sent == -1) {
            if (LastError() == SOCKET_EWOULDBLOCK || 
                LastError() == SOCKET_EAGAIN) {
        
                ssl->writeBuffer.offset = buf;  /* save offset for next call */
                return WANT_WRITE;
            }
            else if (LastError() == SOCKET_ECONNRESET)
                ssl->options.connReset = 1;
            else if (LastError() == SOCKET_EINTR) {
                /* see if we got our timeout */
                #ifdef CYASSL_CALLBACKS
                    if (ssl->toInfoOn) {
                        struct itimerval timeout;
                        getitimer(ITIMER_REAL, &timeout);
                        if (timeout.it_value.tv_sec == 0 && 
                                               timeout.it_value.tv_usec == 0) {
                            strncpy(ssl->timeoutInfo.timeoutName,
                                    "send() timeout", MAX_TIMEOUT_NAME_SZ); 
                            ssl->writeBuffer.offset = buf;
                            return WANT_WRITE;
                        }
                    }
                #endif
                continue;
            }

            return SOCKET_ERROR_E;
        }
        buf += sent;
    }

    return sz;
}


/* send all write buffer (0) or return error */
int SendBuffered(SSL* ssl)
{
    int ret;

    assert(ssl->writeBuffer.send.buffer);

    if ( (ret = Send(ssl, ssl->writeBuffer.send.buffer,
                     ssl->writeBuffer.send.length, 0)) > 0) {
        XFREE(ssl->writeBuffer.send.buffer);
        ssl->writeBuffer.send.buffer = 0;
        return 0;
    }
    return ret;
}


/* send all data (0) or error, if write buffer full buffer output
   if copy we were passed a static buffer so copy it, we now own either way */
int SendWrapper(SSL* ssl, const byte* output, int sz, int copy)
{
    int ret;
    int offset;

    assert(ssl->writeBuffer.send.buffer == 0);

    if ( (ret = Send(ssl, output, sz, 0)) == WANT_WRITE) {
        if (copy) {
            ssl->writeBuffer.send.buffer = (byte*)XMALLOC(sz);
            if (!ssl->writeBuffer.send.buffer) return MEMORY_ERROR;
            memcpy(ssl->writeBuffer.send.buffer, output, sz);

            /* adjust for partial send, since made new buffer */
            offset = (int)(ssl->writeBuffer.offset - output);   
            ssl->writeBuffer.offset = ssl->writeBuffer.send.buffer + offset;
        }
        else 
            ssl->writeBuffer.send.buffer = (byte*)output;  /* take ownership */

        ssl->writeBuffer.send.length = sz;
        return ret;
    }
    else if (ret < 0)
        return ret;

    return 0;
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
    memcpy(&md5_inner[SIZEOF_SENDER], ssl->arrays.masterSecret, SECRET_LEN);
    memcpy(&md5_inner[SIZEOF_SENDER + SECRET_LEN], PAD1, PAD_MD5);
    
    Md5Update(&ssl->hashMd5, md5_inner, sizeof(md5_inner));
    Md5Final(&ssl->hashMd5, md5_result);

    /* make md5 outer */
    memcpy(md5_outer, ssl->arrays.masterSecret, SECRET_LEN);
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
    memcpy(&sha_inner[SIZEOF_SENDER], ssl->arrays.masterSecret, SECRET_LEN);
    memcpy(&sha_inner[SIZEOF_SENDER + SECRET_LEN], PAD1, PAD_SHA);
    
    ShaUpdate(&ssl->hashSha, sha_inner, sizeof(sha_inner));
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    memcpy(sha_outer, ssl->arrays.masterSecret, SECRET_LEN);
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


static int DoCertificate(SSL* ssl, const byte* input, word32* inOutIdx)
{
    word32 listSz, i = *inOutIdx;
    byte   tmp[3];
    int    ret = 0;
    int    firstTime = 1;  /* peer's is at front */

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Certificate", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("Certificate", &ssl->timeoutInfo);
    #endif
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
        myCert.buffer = (byte*) XMALLOC(certSz);
        if (!myCert.buffer) {
            ret = MEMORY_ERROR;
            break;
        }
        memcpy(myCert.buffer, input + i, certSz); i += certSz;
        
        ssl->buffers.peerCert = myCert; /* takes ownership */

        listSz -= certSz + CERT_HEADER_SZ;

        InitDecodedCert(&dCert, ssl->buffers.peerCert.buffer);
        ret = ParseCert(&dCert, ssl->buffers.peerCert.length, CERT_TYPE,
                        !ssl->options.verifyNone, ssl->caList);

        if (firstTime && ret == 0) {  /* first one has peer's key */
            firstTime = 0;

            /* set X509 format */
            ssl->peerCert.issuer.sz    = (int)strlen(dCert.issuer) + 1;
            strncpy(ssl->peerCert.issuer.name, dCert.issuer, ASN_NAME_MAX);
            ssl->peerCert.subject.sz   = (int)strlen(dCert.subject) + 1;
            strncpy(ssl->peerCert.subject.name, dCert.subject, ASN_NAME_MAX);

            if ( (ssl->buffers.peerKey.buffer =
                                           (byte*)XMALLOC(dCert.pubKeySize))) {
                memcpy(ssl->buffers.peerKey.buffer, dCert.publicKey,
                       dCert.pubKeySize);
                ssl->buffers.peerKey.length = dCert.pubKeySize;

                if (!ssl->options.verifyNone && ssl->buffers.domainName.buffer)
                    if (strncmp((char*)ssl->buffers.domainName.buffer,
                                dCert.subjectCN,
                                ssl->buffers.domainName.length - 1))
                        ret = DOMAIN_NAME_MISMATCH;
            }
            else
                ret = MEMORY_ERROR;
        }

        FreeDecodedCert(&dCert);
        if (listSz) {   /* more to come, release */
            XFREE(myCert.buffer);
            ssl->buffers.peerCert.buffer = 0;
        }
    }

    if (ret == 0 && ssl->options.side == CLIENT_END)
        ssl->options.serverState = SERVER_CERT_COMPLETE;

    if (ret != 0) {
        if (!ssl->options.verifyNone) {
            int why = bad_certificate;
            if (ret == ASN_AFTER_DATE_E || ret == ASN_BEFORE_DATE_E)
                why = certificate_expired;
            SendAlert(ssl, alert_fatal, why);   /* try to send */
            Close(ssl);
        }
        ssl->error = ret;
    }

    *inOutIdx = i;
    return ret;
}


static int DoFinished(SSL* ssl, const byte* input, word32* inOutIdx)
{
    byte   verifyMAC[SHA_DIGEST_SIZE],
           mac[SHA_DIGEST_SIZE],
           fill;
    int    finishedSz = ssl->options.tls ? TLS_FINISHED_SZ : FINISHED_SZ;
    word32 macSz = finishedSz + HANDSHAKE_HEADER_SZ,
           idx = *inOutIdx,
           padSz = ssl->keys.encryptSz - HANDSHAKE_HEADER_SZ - finishedSz -
                   ssl->specs.hash_size,
           i;

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
    memcpy(mac, input + idx, ssl->specs.hash_size);
    idx += ssl->specs.hash_size;

    if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
        padSz -= ssl->specs.block_size;

    for (i = 0; i < padSz; i++) 
        fill = input[idx++];

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


static int DoHandShakeMsg(SSL* ssl, const byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    HandShakeHeader hs;
    int ret = 0;

    CYASSL_ENTER("DoHandShakeMsg()");

    if (GetHandShakeHeader(ssl, input, inOutIdx, &hs) != 0)
        return PARSE_ERROR;

    if (*inOutIdx + hs.size > totalSz)
        return INCOMPLETE_DATA;
    
    HashInput(ssl, input + *inOutIdx, hs.size);
#ifdef CYASSL_CALLBACKS
    /* add name later, add on record and handshake header  part back on */
    if (ssl->toInfoOn) {
        int add = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        AddPacketInfo(0, &ssl->timeoutInfo, input + *inOutIdx - add,
                      hs.size + add);
    }
#endif

    switch (hs.type) {

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
        ret = DoClientHello(ssl, input, inOutIdx, totalSz, hs.size);
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
           digestSz = ssl->specs.hash_size,
           i;
    int    dataSz;
    int    ivExtra = 0;

    byte verify[SHA_DIGEST_SIZE];
    byte mac[SHA_DIGEST_SIZE];
    byte fill;

    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
        pad = *(input + idx + msgSz - ivExtra - 1);
        padByte = 1;
    }

    dataSz = msgSz - ivExtra - digestSz - pad - padByte;   

    /* read data */
    if (dataSz) {
        byte*  rawData = input + idx;  /* keep current  for hmac */
        int    rawSz   = dataSz;       /* keep raw size for hmac */
        word32 oldSz = ssl->buffers.bufferedData.buffer ?
                       ssl->buffers.bufferedData.length : 0;
        byte* newData = rawData;       /* could switch on decompression */
        byte* data;                    /* old data plus new data */
        byte  decomp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];

#ifdef HAVE_LIBZ
        if (ssl->options.usingCompression) {
            dataSz = DeCompress(ssl, rawData, dataSz, decomp, sizeof(decomp));
            if (dataSz < 0) return dataSz;
            newData = decomp;
        }
#else
        (void)decomp;
#endif

        data = (byte*) XMALLOC(dataSz + oldSz);
        if (!data) return MEMORY_ERROR;

        if (oldSz)
            memcpy(data, ssl->buffers.bufferedData.buffer, oldSz);

        memcpy(data + oldSz, newData, dataSz);
        if (ssl->options.usingCompression)
            idx += rawSz;
        else
            idx += dataSz;

        if (oldSz)
            XFREE(ssl->buffers.bufferedData.buffer);
        ssl->buffers.bufferedData.buffer = data;
        ssl->buffers.bufferedData.length = dataSz + oldSz;

        ssl->hmac(ssl, verify, rawData, rawSz, application_data, 1);
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

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("Alert", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            /* add record header back on to info + 2 byte level, data */
            AddPacketInfo("Alert", &ssl->timeoutInfo,
                  input + *inOutIdx - RECORD_HEADER_SZ, 2 + RECORD_HEADER_SZ);
    #endif
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


/* process input requests, return 0 is done, 1 is call again to complete, and
   negative number is error */
int DoProcessReply(SSL* ssl)
{
    byte*  input = 0;
    int    ret;
    word32 inSz,
           idx = 0, 
           offset = 0,
           bufferedSz;

    #define ERROR_OUT(x) { XFREE(input); return x; }

    if (!Wait(ssl))
        return SOCKET_ERROR_E;

    if (!(inSz = GetReady(ssl)))
        return 1;

    bufferedSz = ssl->buffers.bufferedInput.buffer ?
                 ssl->buffers.bufferedInput.length : 0;
    input = (byte*) XMALLOC(inSz + bufferedSz);
    if (!input) return MEMORY_ERROR;
    if ( (inSz = Receive(ssl, input + bufferedSz, inSz, 0)) == -1)
        ERROR_OUT(SOCKET_ERROR_E);

    if (bufferedSz) {
        /* prepend old data */
        memcpy(input, ssl->buffers.bufferedInput.buffer,
               ssl->buffers.bufferedInput.length);

        XFREE(ssl->buffers.bufferedInput.buffer);
        ssl->buffers.bufferedInput.buffer = 0;
        ssl->buffers.bufferedInput.length = 0;

        inSz += bufferedSz;
    }

#ifndef NO_CYASSL_SERVER
    if ( ssl->options.side == SERVER_END && ssl->options.clientState ==
                                                                    NULL_STATE)
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
        
        if (!needHdr && (rh.version.major != ssl->version.major || 
                         rh.version.minor != ssl->version.minor))
            ERROR_OUT(VERSION_ERROR);  /* only use requested version */

        /* make sure enough data left */
        if ( needHdr || (inSz - idx) < rh.size) {
            /* buffer for next call */
            word32 extra = needHdr ? 0 : RECORD_HEADER_SZ;
            word32 sz = inSz - idx + extra;

            byte*  data = (byte*)XMALLOC(sz);
            if (!data) ERROR_OUT(MEMORY_ERROR);
            memcpy(data, input + idx - extra, sz);

            assert(ssl->buffers.bufferedInput.buffer == 0);
            ssl->buffers.bufferedInput.buffer = data;
            ssl->buffers.bufferedInput.length = sz;
            
            /* let caller decide */
            ERROR_OUT(1);
        }

        /* each message in record, can be more than 1 */
        while ( idx < rh.size + RECORD_HEADER_SZ + offset) {
            if (ssl->keys.encryptionOn)
                if (DecryptMessage(ssl, input + idx, rh.size, &idx) < 0)
                    ERROR_OUT(DECRYPT_ERROR);

            CYASSL_MSG("received record layer msg");
            switch (rh.type) {
                case handshake :
                    /* debugging in DoHandShakeMsg */
                    if ( (ret = DoHandShakeMsg(ssl, input, &idx, inSz)) != 0)
                        ERROR_OUT(ret);
                    break;

                case change_cipher_spec:
                    CYASSL_MSG("got CHANGE CIPHER SPEC");
                    #ifdef CYASSL_CALLBACKS
                        if (ssl->hsInfoOn)
                            AddPacketName("ChangeCipher", &ssl->handShakeInfo);
                        /* add record header back on info */
                        if (ssl->toInfoOn)
                            AddPacketInfo("ChangeCipher", &ssl->timeoutInfo,
                                    input + idx - RECORD_HEADER_SZ,
                                    1 + RECORD_HEADER_SZ);
                    #endif
                    idx++;
                    ssl->keys.encryptionOn = 1;

                    #ifdef HAVE_LIBZ
                        if (ssl->options.usingCompression)
                            if ( (ret = InitStreams(ssl)) != 0)
                                ERROR_OUT(ret);
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
                    if ( (ret = DoApplicationData(ssl, input, &idx)) != 0) {
                        CYASSL_ERROR(ret);
                        ERROR_OUT(ret);
                    }
                    break;

                case alert:
                    CYASSL_MSG("got ALERT!");
                    if (DoAlert(ssl, input, &idx) == alert_fatal)
                        ERROR_OUT(FATAL_ERROR);
                    break;
            
                default:
                    CYASSL_ERROR(UNKNOWN_RECORD_TYPE);
                    ERROR_OUT(UNKNOWN_RECORD_TYPE);
            }
        }
        offset += rh.size + RECORD_HEADER_SZ;
    }

    XFREE(input);
    return 0;
}


int ProcessReply(SSL* ssl)
{
    int ret;

    CYASSL_ENTER("ProcessReply()");

    while ( (ret = DoProcessReply(ssl)) == 1) { /* need to call again */
        if (IsNonBlocking(ssl)) {
            CYASSL_MSG("Received partial data in non-blocking mode, must call "
                       "again to complete");
            /* for incomplete data, if app checking directly */
            SetError(SOCKET_EAGAIN);
            return ssl->error = WANT_READ;  /* non blocking */
        }
        else
            CYASSL_MSG("Received parital data while blocking, calling again");
    }

    CYASSL_LEAVE("ProcessReply()", ret);
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

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("ChangeCipher", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ChangeCipher", &ssl->timeoutInfo, output, sendSz);
    #endif
    return SendWrapper(ssl, output, sendSz, COPY);
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


static void BuildMD5_CertVerify(SSL* ssl, byte* digest)
{
    byte md5_result[MD5_DIGEST_SIZE];
    byte md5_inner[SECRET_LEN + PAD_MD5];
    byte md5_outer[SECRET_LEN + PAD_MD5 + MD5_DIGEST_SIZE];

    /* make md5 inner */
    memcpy(md5_inner, ssl->arrays.masterSecret, SECRET_LEN);
    memcpy(&md5_inner[SECRET_LEN], PAD1, PAD_MD5);

    Md5Update(&ssl->hashMd5, md5_inner, sizeof(md5_inner));
    Md5Final(&ssl->hashMd5, md5_result);

    /* make md5 outer */
    memcpy(md5_outer, ssl->arrays.masterSecret, SECRET_LEN);
    memcpy(&md5_outer[SECRET_LEN], PAD2, PAD_MD5);
    memcpy(&md5_outer[SECRET_LEN + PAD_MD5], md5_result, MD5_DIGEST_SIZE);

    Md5Update(&ssl->hashMd5, md5_outer, sizeof(md5_outer));
    Md5Final(&ssl->hashMd5, digest);
}


static void BuildSHA_CertVerify(SSL* ssl, byte* digest)
{
    byte sha_result[SHA_DIGEST_SIZE];
    byte sha_inner[SECRET_LEN + PAD_SHA];
    byte sha_outer[SECRET_LEN + PAD_SHA + SHA_DIGEST_SIZE];

    /* make sha inner */
    memcpy(sha_inner, ssl->arrays.masterSecret, SECRET_LEN);
    memcpy(&sha_inner[SECRET_LEN], PAD1, PAD_SHA);

    ShaUpdate(&ssl->hashSha, sha_inner, sizeof(sha_inner));
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    memcpy(sha_outer, ssl->arrays.masterSecret, SECRET_LEN);
    memcpy(&sha_outer[SECRET_LEN], PAD2, PAD_SHA);
    memcpy(&sha_outer[SECRET_LEN + PAD_SHA], sha_result, SHA_DIGEST_SIZE);

    ShaUpdate(&ssl->hashSha, sha_outer, sizeof(sha_outer));
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
    word32 pad  = 0;
    word32 idx  = 0, i;
    word32 ivSz = 0;      /* TLSv1.1  IV */
    byte              digest[SHA_DIGEST_SIZE];  /* max size */
    byte              alen[BYTE3_LEN];
    byte              iv[AES_BLOCK_SIZE];                  /* max size */
    RecordLayerHeader rl;

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
    rl.type    = type;
    rl.version = ssl->version;
    rl.size    = sz - RECORD_HEADER_SZ;          /* includes mac and digest */
    c16toa((word16)rl.size, alen);      
    memcpy(&rl.length, alen, sizeof(rl.length));

    /* write to output */
    memcpy(output, &rl, RECORD_HEADER_SZ);
    idx += RECORD_HEADER_SZ;
    if (ivSz) {
        memcpy(output + idx, iv, ivSz);
        idx += ivSz;
    }
    memcpy(output + idx, input, inSz);
    idx += inSz;

    if (type == handshake)
        HashOutput(ssl, output, RECORD_HEADER_SZ + inSz, ivSz);
    ssl->hmac(ssl, digest, output + RECORD_HEADER_SZ + ivSz, inSz, type, 0);
           
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
                    finishedSz = ssl->options.tls ? TLS_FINISHED_SZ :
                                                    FINISHED_SZ;
    byte            input[FINISHED_SZ + HANDSHAKE_HEADER_SZ];   /* max size */
    byte            output[sizeof(input) + MAX_MSG_EXTRA];
    byte            alen[BYTE3_LEN];
    Hashes          hashes;
    HandShakeHeader hs;

    BuildFinished(ssl, &hashes, ssl->options.side == CLIENT_END ? client :
                                                                  server);

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
            AddPacketInfo("Finished", &ssl->timeoutInfo, output, sendSz);
    #endif
    return SendWrapper(ssl, output, sendSz, COPY);
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

    if (ssl->options.usingPSK_cipher) return 0;  /* not needed */

    /* list + cert size */
    sendSz = ssl->buffers.certificate.length + 2 * CERT_HEADER_SZ +
        RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    output = (byte*) XMALLOC(sendSz);
    if (!output) return MEMORY_ERROR;

    /* record layer header */
    rl.type    = handshake;
    rl.version = ssl->version;
    rl.size    = sendSz - RECORD_HEADER_SZ;  
    c16toa((word16)rl.size, alen);      
    memcpy(&rl.length, alen, sizeof(rl.length));

    /* make handshake header */
    hs.type = certificate;
    c32to24(ssl->buffers.certificate.length + 2 * CERT_HEADER_SZ, alen);
    memcpy(&hs.length, alen, sizeof(hs.length));

    /* write to output */
    memcpy(output, &rl, RECORD_HEADER_SZ);
    i += RECORD_HEADER_SZ;

    memcpy(output + i, &hs, HANDSHAKE_HEADER_SZ);
    i += HANDSHAKE_HEADER_SZ;

    /* list total */
    c32to24(ssl->buffers.certificate.length + CERT_HEADER_SZ, tmp);
    memcpy(output + i, tmp, CERT_HEADER_SZ);
    i += CERT_HEADER_SZ;

    /* member */
    c32to24(ssl->buffers.certificate.length, tmp);
    memcpy(output + i, tmp, CERT_HEADER_SZ);
    i += CERT_HEADER_SZ;
    memcpy(output + i, ssl->buffers.certificate.buffer,
           ssl->buffers.certificate.length);
    i += ssl->buffers.certificate.length;

    HashOutput(ssl, output, sendSz, 0);
    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Certificate", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Certificate", &ssl->timeoutInfo, output, sendSz);
    #endif

    if (ssl->options.side == SERVER_END)
        ssl->options.serverState = SERVER_CERT_COMPLETE;

    if ( (ret = SendWrapper(ssl, output, sendSz, NO_COPY)) == 0)
        XFREE(output);  /* otherwise write_buffer owns */

    return ret;
}


int SendCertificateRequest(SSL* ssl)
{
    byte   output[MAX_REQUEST_SZ];
    int    sendSz;
    word32 i = 0;
    
    RecordLayerHeader rl;
    HandShakeHeader   hs;

    int  typeTotal = 1;  /* only rsa for now */
    int  reqSz = ENUM_LEN + typeTotal + REQ_HEADER_SZ;  /* add auth later */

    if (ssl->options.usingPSK_cipher) return 0;  /* not needed */

    sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + reqSz;

    /* record layer header */
    rl.type    = handshake;
    rl.version = ssl->version;
    rl.size    = sendSz - RECORD_HEADER_SZ;  
    c16toa((word16)rl.size, rl.length);      

    /* make handshake header */
    hs.type = certificate_request;
    c32to24(reqSz, hs.length);

    /* write to output */
    memcpy(output, &rl, RECORD_HEADER_SZ);
    i += RECORD_HEADER_SZ;

    memcpy(output + i, &hs, HANDSHAKE_HEADER_SZ);
    i += HANDSHAKE_HEADER_SZ;

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
                          sendSz);
    #endif
    return SendWrapper(ssl, output, sendSz, COPY);
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

    /* last time write buffer was full, try again */
    if (ssl->writeBuffer.send.buffer) {
        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            CYASSL_ERROR(ssl->error);
            if (ssl->error == SOCKET_ERROR_E && ssl->options.connReset)
                return 0;  /* peer reset */
            return ssl->error;
        }
        else {
            /* sent is now previous sent + just sent */
            sent = ssl->writeBuffer.sent + ssl->writeBuffer.plainSz;
            CYASSL_MSG("sent write buffered data");
        }
    }

    for (;;) {
        int   len = min(sz - sent, MAX_RECORD_SIZE);
        byte* out;
        byte* sendBuffer = (byte*)buffer + sent;  /* may switch on comp */
        int   buffSz = len;                       /* may switch on comp */
        byte  comp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];

        if (sent == sz) break;
        out = (byte*) XMALLOC(len + MAX_COMP_EXTRA + MAX_MSG_EXTRA);

        if (!out) return MEMORY_ERROR;

#ifdef HAVE_LIBZ
        if (ssl->options.usingCompression) {
            buffSz = Compress(ssl, sendBuffer, buffSz, comp, sizeof(comp));
            if (buffSz < 0) {
                XFREE(out);
                return buffSz;
            }
            sendBuffer = comp;
        }
#else
        (void)comp;
#endif
        sendSz = BuildMessage(ssl, out, sendBuffer, buffSz,
                              application_data);
        if ( (ret = SendWrapper(ssl, out, sendSz, NO_COPY)) < 0) {
            CYASSL_ERROR(ret);
            if (ret == WANT_WRITE) {
                /* store for next call */
                ssl->writeBuffer.plainSz     = len;
                ssl->writeBuffer.sent        = sent;
            }
            else
                XFREE(out);
            if (ret == SOCKET_ERROR_E && ssl->options.connReset)
                return 0;  /* peer reset */
            return ssl->error = ret;
        }

        XFREE(out);
        sent += len;
    }
 
    return sent;
}


static int FillData(SSL* ssl, byte* output, int sz)
{
    int   dataSz = min(sz, ssl->buffers.bufferedData.buffer ?
                      (int)ssl->buffers.bufferedData.length : 0);
    int   leftSz = 0;
    byte* left   = 0;

    if (dataSz == 0) return 0;

    memcpy(output, ssl->buffers.bufferedData.buffer, dataSz);

    /* did we leave any */
    if (dataSz < (int)ssl->buffers.bufferedData.length) {
        leftSz = ssl->buffers.bufferedData.length - dataSz;
        left   = (byte*) XMALLOC(leftSz);

        if (!left) return MEMORY_ERROR;

        memcpy(left, ssl->buffers.bufferedData.buffer + dataSz, leftSz);
    }

    XFREE(ssl->buffers.bufferedData.buffer);
    ssl->buffers.bufferedData.buffer = left;
    ssl->buffers.bufferedData.length = leftSz;

    return dataSz;
}


/* process input data */
int ReceiveData(SSL* ssl, byte* output, int sz)
{
    int ret;

    CYASSL_ENTER("ReceiveData()");

    if (ssl->error == WANT_READ)
        ssl->error = 0;

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        CYASSL_ERROR(NOT_READY_ERROR);
        return ssl->error = NOT_READY_ERROR;
    }

    if (!ssl->buffers.bufferedData.buffer)
        if ( (ssl->error = ProcessReply(ssl)) < 0) {
            CYASSL_ERROR(ssl->error);
            if (ssl->error == SOCKET_ERROR_E)
                if (ssl->options.connReset || ssl->options.isClosed)
                    return 0;     /* peer reset or closed */
            return ssl->error;
        }

    ret = FillData(ssl, output, sz);
    
    CYASSL_LEAVE("ReceiveData()", ret);
    return ret;
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

    #ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("Alert", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Alert", &ssl->timeoutInfo, output, sendSz);
    #endif
    return SendWrapper(ssl, output, sendSz, COPY);
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
    void FreeTimeoutInfo(TimeoutInfo* info)
    {
        int i;
        for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++)
            if (info->packets[i].bufferValue) {
                XFREE(info->packets[i].bufferValue);
                info->packets[i].bufferValue = 0;
            }

    }


    /* Add PacketInfo to TimeoutInfo */
    void AddPacketInfo(const char* name, TimeoutInfo* info, const byte* data,
                       int sz)
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
                info->packets[info->numberPackets].bufferValue = XMALLOC(sz);
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

#endif /* CYASSL_CALLBACKS */


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
        int               idSz = ssl->options.resuming ? ID_LEN : 0;

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
            
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        HashOutput(ssl, output, sendSz, 0);

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;

#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("ClientHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ClientHello", &ssl->timeoutInfo, output, sendSz);
#endif
        return SendWrapper(ssl, output, sendSz, COPY);
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
        word16 len, i;
        byte   tmp[REQUEST_HEADER];
        byte   b;

        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("CertificateRequest", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddLateName("CertificateRequest", &ssl->timeoutInfo);
        #endif
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

        /* don't send client cert or cert verify if user hasn't provided
           cert of private key */
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
            byte   tmp[2];

            tmp[0] = input[(*inOutIdx)++];
            tmp[1] = input[(*inOutIdx)++];
            ato16(tmp, &length);
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
        byte   tmp[2];
        byte   messageVerify[MAX_DH_SZ];
        byte   signature[ENCRYPT_LEN];
        byte   hash[FINISHED_SZ];
        Md5    md5;
        Sha    sha;

        /* p */
        tmp[0] = input[(*inOutIdx)++];
        tmp[1] = input[(*inOutIdx)++];
        ato16(tmp, &length);
        messageTotal += length;

        ssl->buffers.serverDH_P.buffer = (byte*) XMALLOC(length);
        if (ssl->buffers.serverDH_P.buffer)
            ssl->buffers.serverDH_P.length = length;
        else
            return MEMORY_ERROR;
        memcpy(ssl->buffers.serverDH_P.buffer, &input[*inOutIdx], length);
        *inOutIdx += length;

        /* g */
        tmp[0] = input[(*inOutIdx)++];
        tmp[1] = input[(*inOutIdx)++];
        ato16(tmp, &length);
        messageTotal += length;

        ssl->buffers.serverDH_G.buffer = (byte*) XMALLOC(length);
        if (ssl->buffers.serverDH_G.buffer)
            ssl->buffers.serverDH_G.length = length;
        else
            return MEMORY_ERROR;
        memcpy(ssl->buffers.serverDH_G.buffer, &input[*inOutIdx], length);
        *inOutIdx += length;

        /* pub */
        tmp[0] = input[(*inOutIdx)++];
        tmp[1] = input[(*inOutIdx)++];
        ato16(tmp, &length);
        messageTotal += length;

        ssl->buffers.serverDH_Pub.buffer = (byte*) XMALLOC(length);
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
        tmp[0] = input[(*inOutIdx)++];
        tmp[1] = input[(*inOutIdx)++];
        ato16(tmp, &length);

        memcpy(signature, &input[*inOutIdx], length);
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
            RsaKey key;
            int    ret;
            word32 idx = 0;
            byte   tmp[ENCRYPT_LEN];

            InitRsaKey(&key);
            if (ssl->buffers.peerKey.buffer)
                ret = RsaPublicKeyDecode(ssl->buffers.peerKey.buffer, &idx,
                                         &key, ssl->buffers.peerKey.length);
            else
                return NO_PEER_KEY;

            if (ret == 0) {
                ret = RsaSSL_Verify(signature, length, tmp, sizeof(tmp), &key);

                if (ret != sizeof(hash) || memcmp(tmp, hash, sizeof(hash)))
                    return VERIFY_SIGN_ERROR;
            }
            else
                return ret;
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
            RsaKey key;
            RNG_GenerateBlock(&ssl->rng, ssl->arrays.preMasterSecret,
                              SECRET_LEN);
            ssl->arrays.preMasterSecret[0] = ssl->chVersion.major;
            ssl->arrays.preMasterSecret[1] = ssl->chVersion.minor;
            ssl->arrays.preMasterSz = SECRET_LEN;
            InitRsaKey(&key);

            if (ssl->buffers.peerKey.buffer)
                ret = RsaPublicKeyDecode(ssl->buffers.peerKey.buffer, &idx,&key,
                                         ssl->buffers.peerKey.length);
            else
                return NO_PEER_KEY;

            if (ret == 0)  {
                ret = RsaPublicEncrypt(ssl->arrays.preMasterSecret, SECRET_LEN,
                                 encSecret, sizeof(encSecret), &key, &ssl->rng);
                if (ret > 0) {
                    encSz = ret;
                    ret = 0;   /* set success to 0 */
                }
            }
            FreeRsaKey(&key);
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
            byte              output[ENCRYPT_LEN + MAX_MSG_EXTRA];
            byte              alen[BYTE3_LEN];
            int               sendSz;
            RecordLayerHeader rl;
            HandShakeHeader   hs;
            word32            tlsSz = 0;
            
            if (ssl->options.tls || ssl->specs.kea == diffie_hellman_kea)
                tlsSz = 2;

            idx = 0;

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
            HashOutput(ssl, output, sendSz, 0);

            #ifdef CYASSL_CALLBACKS
                if (ssl->hsInfoOn)
                    AddPacketName("ClientKeyExchange", &ssl->handShakeInfo);
                if (ssl->toInfoOn)
                    AddPacketInfo("ClientKeyExchange", &ssl->timeoutInfo,
                                  output, sendSz);
            #endif
            ret = SendWrapper(ssl, output, sendSz, COPY);
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
        RecordLayerHeader rl;
        HandShakeHeader   hs;
        int               sendSz = 0, length, ret;
        word32            idx = 0;
        byte              output[MAX_CERT_VERIFY_SZ];
        RsaKey            key;

        BuildCertHashes(ssl, &ssl->certHashes);

        /* TODO: when add DSS support check here  */
        InitRsaKey(&key);
        ret = RsaPrivateKeyDecode(ssl->buffers.key.buffer, &idx, &key,
                                  ssl->buffers.key.length); 
        if (ret == 0) {
            byte verify[ENCRYPT_LEN + VERIFY_HEADER];

            length = RsaEncryptSize(&key);
            c16toa((word16)length, verify);   /* prepend verify header */

            ret = RsaSSL_Sign(ssl->certHashes.md5, sizeof(Hashes), verify +
                  VERIFY_HEADER, ENCRYPT_LEN, &key, &ssl->rng);

            if (ret > 0) {
                ret = 0;  /* reset */
                hs.type = certificate_verify;
                c32to24(length + VERIFY_HEADER, hs.length);

                rl.type = handshake;
                rl.version = ssl->version;
                c16toa((word16)(length + VERIFY_HEADER + HANDSHAKE_HEADER_SZ),
                       rl.length);
                idx = 0;
                memcpy(output, &rl, RECORD_HEADER_SZ);
                idx += RECORD_HEADER_SZ;
                memcpy(output + idx, &hs, HANDSHAKE_HEADER_SZ);
                idx += HANDSHAKE_HEADER_SZ;
                memcpy(output + idx, verify, length + VERIFY_HEADER);
                idx += length + VERIFY_HEADER;

                sendSz = idx;
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
                                  output, sendSz);
            #endif
            return SendWrapper(ssl, output, sendSz, COPY);
        }
        else
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
        HashOutput(ssl, output, sendSz, 0);

        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("ServerHello", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("ServerHello", &ssl->timeoutInfo, output, sendSz);
        #endif

        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        return SendWrapper(ssl, output, sendSz, COPY);
    }

    int SendServerKeyExchange(SSL* ssl)
    {
        RecordLayerHeader rl;
        HandShakeHeader   hs;
        word32            length, idx = 0;
        int               sendSz;
        int               ret = 0;
        byte              alen[BYTE3_LEN];        /* for byte output lengths */
        byte              output[MAX_HELLO_SZ + MAX_PSK_ID_LEN];

        if (ssl->specs.kea != psk_kea) return 0;

        #ifndef NO_PSK
            if (ssl->arrays.server_hint[0] == 0) return 0; /* don't send */

            /* include size part */
            length = (word32)strlen(ssl->arrays.server_hint);
            if (length > MAX_PSK_ID_LEN) return SERVER_HINT_ERROR;
            length += + HINT_LEN_SZ;

            /* handshake header */
            hs.type = server_key_exchange;
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

            c16toa((word16)(length - HINT_LEN_SZ), output + idx);
            idx += HINT_LEN_SZ;
            memcpy(output + idx, ssl->arrays.server_hint, length -HINT_LEN_SZ);

            sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
            HashOutput(ssl, output, sendSz, 0);

            #ifdef CYASSL_CALLBACKS
                if (ssl->hsInfoOn)
                    AddPacketName("ServerKeyExchange", &ssl->handShakeInfo);
                if (ssl->toInfoOn)
                    AddPacketInfo("ServerKeyExchange", &ssl->timeoutInfo,
                                  output, sendSz);
            #endif

            ret = SendWrapper(ssl, output, sendSz, COPY);
            ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;
        #endif /*NO_PSK */

        return ret;
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
                    ssl->options.cipherSuite = ssl->suites.suites[i];
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
#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ClientHello", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddLateName("ClientHello", &ssl->timeoutInfo);
#endif
        if (sz > inSz - 2)
            return INCOMPLETE_DATA;

        /* manually hash input since different format */
        Md5Update(&ssl->hashMd5, input + idx, sz);
        ShaUpdate(&ssl->hashSha, input + idx, sz);

        b1 = input[idx++];  /* does this value mean client_hello? */

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
            SSL_SESSION* session = GetSession(ssl);
            if (!session) {
                ssl->options.resuming = 0;
                break;   /* session lookup failed */
            }
            if (MatchSuite(ssl, &clSuites) < 0)
                return UNSUPPORTED_SUITE;

            memcpy(ssl->arrays.masterSecret, session->masterSecret,SECRET_LEN);
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
        byte tmp[2];
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
            SSL_SESSION* session = GetSession(ssl);
            if (!session) {
                ssl->options.resuming = 0;
                break;   /* session lookup failed */
            }
            if (MatchSuite(ssl, &clSuites) < 0)
                return UNSUPPORTED_SUITE;

            memcpy(ssl->arrays.masterSecret, session->masterSecret,SECRET_LEN);
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


    static int DoCertificateVerify(SSL* ssl, const byte* input, word32* inOutsz,
                                   word32 totalSz)
    {
        word16 sz = 0;
        word32 i = *inOutsz, idx = 0;
        int    ret;
        RsaKey key;
        byte   tmp[VERIFY_HEADER];
        byte   sig[ENCRYPT_LEN];

        #ifdef CYASSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("CertificateVerify", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddLateName("CertificateVerify", &ssl->timeoutInfo);
        #endif
        if ( (i + VERIFY_HEADER) > totalSz)
            return INCOMPLETE_DATA;

        tmp[0] = input[i++];
        tmp[1] = input[i++];

        ato16(tmp, &sz);

        if ( (i + sz) > totalSz)
            return INCOMPLETE_DATA;

        if (sz > sizeof(sig))
            return BUFFER_ERROR;

        memcpy(sig, &input[i], sz);
        *inOutsz = i + sz;

        /* TODO: when add DSS support check here  */
        InitRsaKey(&key);
        ret = RsaPublicKeyDecode(ssl->buffers.peerKey.buffer, &idx, &key,
                                 ssl->buffers.peerKey.length); 
        if (ret == 0) {
            byte plain[ENCRYPT_LEN];

            ret = VERIFY_CERT_ERROR;  /* start in error state */
            RsaSSL_Verify(sig, sz, plain, sizeof(plain), &key);
            if (memcmp(plain,ssl->certHashes.md5,sizeof(ssl->certHashes)) == 0)
                ret = 0;
        }
        return ret;
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

        HashOutput(ssl, output, sendSz, 0);
#ifdef CYASSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("ServerHelloDone", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("ServerHelloDone", &ssl->timeoutInfo, output, sendSz);
#endif
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
        return SendWrapper(ssl, output, sendSz, COPY);
    }


    static int DoClientKeyExchange(SSL* ssl, const byte* input,
                                   word32* inOutIdx)
    {
        int    ret = 0;
        byte   sz[2];    /* for tls length */
        word32 length = 0;

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

            InitRsaKey(&key);

            if (ssl->buffers.key.buffer)
                ret = RsaPrivateKeyDecode(ssl->buffers.key.buffer, &idx, &key,
                                          ssl->buffers.key.length);
            else
                return NO_PRIVATE_KEY;

            if (ret == 0) {
                length = RsaEncryptSize(&key);
                ssl->arrays.preMasterSz = SECRET_LEN;
                tmp = (byte*) XMALLOC(length);
                if (!tmp) return MEMORY_ERROR;

                if (ssl->options.tls) {
                    sz[0] = input[(*inOutIdx)++];
                    sz[1] = input[(*inOutIdx)++];
                }   
                memcpy(tmp, input + *inOutIdx, length);
                *inOutIdx += length;

                if (RsaPrivateDecrypt(tmp, length, ssl->arrays.preMasterSecret,
                                      SECRET_LEN, &key) == SECRET_LEN) {
                    if (ssl->arrays.preMasterSecret[0] != ssl->chVersion.major ||
                        ssl->arrays.preMasterSecret[1] != ssl->chVersion.minor)

                        ret = PMS_VERSION_ERROR;
                    else
                        ret = MakeMasterSecret(ssl);
                }
                else
                    ret = RSA_PRIVATE_ERROR;
            }

            FreeRsaKey(&key);
            XFREE(tmp);
#ifndef NO_PSK
        } else if (ssl->specs.kea == psk_kea) {
            byte* pms = ssl->arrays.preMasterSecret;
            word16 ci_sz;

            sz[0] = input[(*inOutIdx)++];
            sz[1] = input[(*inOutIdx)++];
            ato16(sz, &ci_sz);
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
