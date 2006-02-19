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



#include "openssl/ssl.h"
#include "cyassl_int.h"
#include "asn.h"
#include "coding.h"

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
    #include <string.h>
#else
    #include <winsock2.h>   
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



static void Hmac(SSL* ssl, byte* digest, const byte* buffer, word32 sz,
                 int content, int verify);


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

    InitSigner(&ctx->caList);
    InitSuites(&ctx->suites);
}


void FreeSSL_Ctx(SSL_CTX* ctx)
{
    free(ctx->privateKey.buffer);
    free(ctx->certificate.buffer);
    free(ctx->method);

    FreeSigner(&ctx->caList);
    
    free(ctx);
}


void InitSigner(Signer* signer)
{
    signer->name = 0;
    signer->publicKey.buffer = 0;
}


void FreeSigner(Signer* signer)
{
    free(signer->name);
    free(signer->publicKey.buffer);
}


void InitSuites(Suites* suites)
{
    word32 idx = 0;

    suites->setSuites = 0;  /* user hasn't set yet */

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


void InitSSL(SSL* ssl, SSL_CTX* ctx)
{
    ssl->version = ctx->method->version;
    ssl->suites  = ctx->suites;
    ssl->socket  = INVALID_SOCKET;

    ssl->peerCert.buffer     = 0;
    ssl->peerKey.buffer      = 0;
    ssl->bufferedData.buffer = 0;

    InitRng(&ssl->rng);
    InitMd5(&ssl->hashMd5);
    InitSha(&ssl->hashSha);

    ssl->side  = ctx->method->side;
    ssl->error = 0;

    ssl->serverState = NULL_STATE;
    ssl->clientState = NULL_STATE;

    ssl->keys.encryptionOn = 0;     /* initially off */
}


void FreeSSL(SSL* ssl)
{
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


int SendClientHello(SSL* ssl)
{
    RecordLayerHeader rl;
    HandShakeHeader   hs;
    word32            length, idx = 0;
    int               sendSz;
    byte              alen[BYTE3_LEN];           /* for byte output lengths */
    byte              output[MAX_HELLO_SZ];

    length = sizeof(ProtocolVersion) + RAN_LEN
           + 0 + ENUM_LEN                       /* no resume for now */
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
    output[idx++] = 0;            /* no resume for now TODO: */

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

    if (send(ssl->socket, output, sendSz, 0) != sendSz)
        return -1; /* SOCKET_SEND_E; */

    ssl->clientState = CLIENT_HELLO_COMPLETE;

    return 0;
}


static INLINE int LastError()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}


word32 Receive(SOCKET_T socket, byte* buf, word32 sz, int flags)
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
        return -1;

    return recvd;
}


/* wait if blocking for input, return false(0) for error */
int Wait(SOCKET_T socket)
{
    byte b;
    return Receive(socket, &b, 1, MSG_PEEK) != (word32)-1;
}


/* find out how much data is waiting */
word32 GetReady(SOCKET_T socket)
{
    unsigned long ready = 0;

#ifdef _WIN32
    ioctlsocket(socket, FIONREAD, &ready);
#else
    ioctl(socket, FIONREAD, &ready);
#endif

    return ready;
}


int GetRecordHeader(SSL* ssl, const byte* input, word32* inOutIdx,
                    RecordLayerHeader* rh)
{
    memcpy(rh, input + *inOutIdx, RECORD_HEADER_SZ);
    *inOutIdx += RECORD_HEADER_SZ;
    ato16(rh->length, &rh->size);

    return 0;
}


int GetHandShakeHeader(SSL* ssl, const byte* input, word32* inOutIdx,
                       HandShakeHeader* hs)
{
    memcpy(hs, input + *inOutIdx, HANDSHAKE_HEADER_SZ);
    *inOutIdx += HANDSHAKE_HEADER_SZ;
    c24to32(hs->length, &hs->size);

    return 0;
}


int DoServerHello(SSL* ssl, const byte* input, word32* inOutIdx)
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
    return SetCipherSpecs(ssl);
}


int DoCertificate(SSL* ssl, const byte* input, word32* inOutIdx)
{
    word32 listSz, i = *inOutIdx;
    byte   tmp[3];
    int    ret = 0;

    tmp[0] = input[i++];
    tmp[1] = input[i++];
    tmp[2] = input[i++];
    c24to32(tmp, &listSz);
    
    while (listSz) {
        /* cert size */
        buffer myCert;
        word32 certSz;

        tmp[0] = input[i++];
        tmp[1] = input[i++];
        tmp[2] = input[i++];
        c24to32(tmp, &certSz);
        
        /* TODO: chain */
        myCert.length = certSz;
        myCert.buffer = (byte*) malloc(certSz);
        if (!myCert.buffer) {
            ret = -1; /* out of memory */
            break;
        }
        memcpy(myCert.buffer, input + i, certSz); i += certSz;
        
        ssl->peerCert = myCert; /* takes ownership */

        listSz -= certSz + CERT_HEADER_SZ;
    }

    /* validate */
    if (ret == 0) {
        DecodedCert dCert;

        InitDecodedCert(&dCert, ssl->peerCert.buffer);
        ret = ParseCert(&dCert, ssl->peerCert.length);
    
        if (ret == 0) {
            if ( (ssl->peerKey.buffer = (byte*)malloc(dCert.pubKeySize))) {
                memcpy(ssl->peerKey.buffer, dCert.publicKey, dCert.pubKeySize);
                ssl->peerKey.length = dCert.pubKeySize;
            }
            else
                ret = -1;  /* no memory */
        }

        FreeDecodedCert(&dCert);
    }

    if (ret == 0 && ssl->side == CLIENT_END)
        ssl->serverState = SERVER_CERT_COMPLETE;

    *inOutIdx = i;
    return ret;
}


int DoFinished(SSL* ssl, const byte* input, word32* inOutIdx)
{
    byte   verifyMAC[SHA_DIGEST_SIZE],
           mac[SHA_DIGEST_SIZE],
           fill;
    word32 macSz = FINISHED_SZ + HANDSHAKE_HEADER_SZ,
           idx = *inOutIdx,
           padSz = ssl->keys.encryptSz - HANDSHAKE_HEADER_SZ - FINISHED_SZ -
                   ssl->specs.hash_size,
           i;

    if (memcmp(input + idx, &ssl->verifyHashes, FINISHED_SZ))
        return -1;  /* verify handshake fin error */

    Hmac(ssl, verifyMAC, input + idx - HANDSHAKE_HEADER_SZ, macSz,
         handshake, 1);
    idx += FINISHED_SZ;

    /* read mac and fill */
    memcpy(mac, input + idx, ssl->specs.hash_size);
    idx += ssl->specs.hash_size;

    for (i = 0; i < padSz; i++) 
        fill = input[idx++];

    /* verify mac */
    if (memcmp(mac, verifyMAC, ssl->specs.hash_size))
        return -1;  /* verify mac error */

    if (ssl->side == CLIENT_END) {
        ssl->serverState = SERVER_FINISHED_COMPLETE;
        ssl->handShakeState = HANDSHAKE_DONE;
    }
    else
        ssl->clientState = CLIENT_FINISHED_COMPLETE;

    *inOutIdx = idx;
    return 0;
}


/* just read in and ignore for now TODO: */
int DoCertificateRequest(SSL* ssl, const byte* input, word32* inOutIdx)
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


int DoServerKeyExchange(SSL* ssl, const byte* input, word32* inOutIdx)
{


    return -1;  /* not supported yet TODO: */
}


int DoHandShakeMsg(SSL* ssl, const byte* input, word32* inOutIdx)
{
    HandShakeHeader hs;

    if (GetHandShakeHeader(ssl, input, inOutIdx, &hs) != 0)
        return -1;  /* parse error */
    
    HashInput(ssl, input + *inOutIdx, hs.size);

    switch (hs.type) {
    case server_hello:
        return DoServerHello(ssl, input, inOutIdx);
        break;

    case certificate:
        return DoCertificate(ssl, input, inOutIdx);
        break;

    case certificate_request:
        return DoCertificateRequest(ssl, input, inOutIdx);
        break;

    case server_key_exchange:
        return DoServerKeyExchange(ssl, input, inOutIdx);
        break;

    case server_hello_done:
        ssl->serverState = SERVER_HELLODONE_COMPLETE;
        break;

    case finished:
        return DoFinished(ssl, input, inOutIdx);
        break;

    default:
        return -1; /* unknown type */
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
    }
}


/* decrypt input message in place */
static int DecryptMessage(SSL* ssl, byte* input, word32 sz)
{
    byte* plain = (byte*)malloc(sz);
    if (!plain) return -1; /* no memory */

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
        if (!data) return -1;  /* no memory */

        if (oldSz)
            memcpy(data, ssl->bufferedData.buffer, oldSz);

        memcpy(data + oldSz, input + idx, dataSz);
        idx += dataSz;

        if (oldSz)
            free(ssl->bufferedData.buffer);
        ssl->bufferedData.buffer = data;
        ssl->bufferedData.length = dataSz;

        Hmac(ssl, verify, data, dataSz, application_data, 1);
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
            return -1; /* verify error */
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

    return level;
}


int ProcessReply(SSL* ssl)
{
    byte*  input = 0;
    word32 inSz, idx = 0, offset = 0;
    #define ERROR_OUT { free(input); return -1; }

    if (!Wait(ssl->socket))
        return -1;  /* socket error */

    if (!(inSz = GetReady(ssl->socket)))
        return -1;  /* nothing there */

    input = (byte*) malloc(inSz);
    if (!input) return -1;  /* no memory */
    if (Receive(ssl->socket, input, inSz, 0) != inSz)
        ERROR_OUT;

    while (idx < inSz) {
        /* each record */
        RecordLayerHeader rh;

        /* make sure enough data left */
        if ( (inSz - idx) < RECORD_HEADER_SZ)
            ERROR_OUT;  /* incomplete data */

        if (GetRecordHeader(ssl, input, &idx, &rh) != 0)
            ERROR_OUT;  /* parse error */

        /* make sure enough data left */
        if ( (inSz - idx) < rh.size)
            ERROR_OUT;  /* refill, buffer call again TODO: */

        /* each message in record, can be more than 1 */
        while ( idx < rh.size + RECORD_HEADER_SZ + offset) {
            if (ssl->keys.encryptionOn)
                if (DecryptMessage(ssl, input + idx, rh.size) < 0)
                    return -1;  /* decrypt error */
            switch (rh.type) {
                case handshake :
                    if (DoHandShakeMsg(ssl, input, &idx) != 0)
                        ERROR_OUT;  /* parse error */
                    break;

                case change_cipher_spec:
                    idx++;
                    ssl->keys.encryptionOn = 1;
                    break;

                case application_data:
                    if (DoApplicationData(ssl, input, &idx) != 0)
                        ERROR_OUT;  /* parse error */
                    break;

                case alert:
                    if (DoAlert(ssl, input, &idx) == alert_fatal)
                        ERROR_OUT;
                    break;
            
                default:
                    ERROR_OUT;  /* unknown type */

            }
            

        }
        offset += rh.size + RECORD_HEADER_SZ;
    }

    free(input);
    return 0;
}


int SendClientKeyExchange(SSL* ssl)
{
    byte   encSecret[2 * SECRET_LEN];
    word32 encSz;
    RsaKey key;
    word32 idx = 0;
    int    ret = 0;

    /* RSA for now */
    RNG_GenerateBlock(&ssl->rng, ssl->preMasterSecret, SECRET_LEN);
    ssl->preMasterSecret[0] = ssl->version.major;
    ssl->preMasterSecret[1] = ssl->version.minor;

    if (ssl->peerKey.buffer) {
        InitRsaKey(&key);
        ret = RsaPublicKeyDecode(ssl->peerKey.buffer, &idx, &key,
                                 ssl->peerKey.length);
    }
    else
        return -1;  /* no peer key */

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

            encSz = ret;
            ret   = 0;
            idx   = 0;

            /* handshake header */
            hs.type = client_key_exchange;
            c32to24(encSz, alen);
            memcpy(&hs.length, alen, sizeof(hs.length));

            /* record layer header */
            rl.type    = handshake;
            rl.version = ssl->version;
            c16toa((word16)(encSz + HANDSHAKE_HEADER_SZ), alen);
            memcpy(&rl.length, alen, sizeof(rl.length));

            /* now write to output */
            memcpy(output, &rl, RECORD_HEADER_SZ);
            idx += RECORD_HEADER_SZ;
            memcpy(output + idx, &hs, HANDSHAKE_HEADER_SZ);
            idx += HANDSHAKE_HEADER_SZ;
            memcpy(output + idx, encSecret, encSz);
            idx += encSz;

            sendSz = encSz + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
            HashOutput(ssl, output, sendSz);

            if (send(ssl->socket, output, sendSz, 0) != sendSz)
                ret = -1; /* SOCKET_SEND_E; */
        }
    }

    if (ret == 0) {
        ssl->clientState = CLIENT_KEYEXCHANGE_COMPLETE;
        ret = MakeMasterSecret(ssl);
    }
    FreeRsaKey(&key);

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

    if (send(ssl->socket, output, sendSz, 0) != sendSz)
        return -1; /* SOCKET_SEND_E; */

    return 0;
}


static const byte client[SIZEOF_SENDER] = { 0x43, 0x4C, 0x4E, 0x54 };
static const byte server[SIZEOF_SENDER] = { 0x53, 0x52, 0x56, 0x52 };

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

    BuildMD5(ssl, hashes, sender);
    BuildSHA(ssl, hashes, sender);
    
    /* restore */
    ssl->hashMd5 = md5;
    ssl->hashSha = sha;
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
    Hmac(ssl, digest, output + RECORD_HEADER_SZ, inSz, type, 0);
           
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
    int             sendSz;
    byte            input[FINISHED_SZ + HANDSHAKE_HEADER_SZ];
    byte            output[sizeof(input) + MAX_MSG_EXTRA];
    byte            alen[BYTE3_LEN];
    Hashes          hashes;
    HandShakeHeader hs;

    BuildFinished(ssl, &hashes, ssl->side == CLIENT_END ? client : server);

    /* make handshake header */
    hs.type = finished;
    c32to24(FINISHED_SZ, alen);
    memcpy(&hs.length, alen, sizeof(hs.length));

    /* write to input for message */
    memcpy(input, &hs, HANDSHAKE_HEADER_SZ);
    memcpy(input + HANDSHAKE_HEADER_SZ, &hashes, FINISHED_SZ);

    if ( (sendSz = BuildMessage(ssl, output, input, HANDSHAKE_HEADER_SZ +
                                FINISHED_SZ, handshake)) == -1)
        return -1; /* cipher error */

    if (send(ssl->socket, output, sendSz, 0) != sendSz)
        return -1; /* SOCKET_SEND_E; */

    if (ssl->side == CLIENT_END)
        BuildFinished(ssl, &ssl->verifyHashes, server);

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
        byte* out = (byte*) malloc(len + 32);

        if (!out) return -1;  /* memory error */

        sendSz = BuildMessage(ssl, out, (byte*)buffer + sent, len,
                              application_data);
        if (send(ssl->socket, out, sendSz, 0) != sendSz) {
            free(out);
            return -1; /* SOCKET_SEND_E; */
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

        if (!left) return -1; /* memory error */

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
        return 0;  /* not ready */

    if (!ssl->bufferedData.buffer)
        if (ProcessReply(ssl) != 0)
            return 0;  /* error */

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

    if (send(ssl->socket, output, sendSz, 0) != sendSz)
        return -1;  /* socket error */

    return 0;
}


/* owns der, TODO: make list */
static int AddCA(SSL_CTX* ctx, buffer der)
{
    word32      ret;
    DecodedCert cert;
    Signer      signer;

    InitSigner(&signer);
    InitDecodedCert(&cert, der.buffer);
    ret = ParseCert(&cert, der.length);

    if (ret == 0 && cert.publicKey) {
        signer.publicKey.buffer = (byte*) malloc(cert.pubKeySize);
        if (!signer.publicKey.buffer)
            ret = -1;   /* no memory */
        else {
            memcpy(signer.publicKey.buffer, cert.publicKey, cert.pubKeySize);
            signer.publicKey.length = cert.pubKeySize;
            memcpy(signer.hash, cert.subjectHash, SHA_DIGEST_SIZE);
        }
    }
    if (ret == 0 && cert.subject) {
        signer.name = (char*) malloc(strlen(cert.subject) + 1);
        if (!signer.name)
            ret = -1;  /* no memory */
        else
            strncpy(signer.name, cert.subject, strlen(cert.subject) + 1);
    }
    ctx->caList = signer;   /* takes ownership */
    FreeDecodedCert(&cert);
    free(der.buffer);

    return ret;
}


static int PemToDer(const char* fileName, int type, buffer* der)
{
    long   begin    = -1;
    long   end      =  0;
    int    foundEnd =  0;
    word32 sz       =  0;

    char  line[80];
    char  header[80];
    char  footer[80];

    FILE* file;
    byte* tmp = 0;

    if (type == CERT_TYPE) {
        strncpy(header, "-----BEGIN CERTIFICATE-----", sizeof(header));
        strncpy(footer, "-----END CERTIFICATE-----", sizeof(footer));
    } else {
        strncpy(header, "-----BEGIN RSA PRIVATE KEY-----", sizeof(header));
        strncpy(footer, "-----END RSA PRIVATE KEY-----", sizeof(header));
    }

    file = fopen(fileName, "rb");
    if (!file)
        return -1;

    while(fgets(line, sizeof(line), file))
        if (strncmp(header, line, strlen(header)) == 0) {
            begin = ftell(file);
            break;
        }

    while(fgets(line, sizeof(line), file))
        if (strncmp(footer, line, strlen(footer)) == 0) {
            foundEnd = 1;
            break;
        }
        else
            end = ftell(file);

    if (begin == -1 || !foundEnd) {
        fclose(file);
        return -1;
    }

    sz = end - begin;
    tmp = (byte*) malloc(sz);
    if (!tmp) {
        fclose(file);
        return -1; 
    }

    fseek(file, begin, SEEK_SET);
    if (fread(tmp, sz, 1, file) != 1 || 
            (der->buffer = (byte*) malloc(sz)) == 0) {
        free(tmp);
        fclose(file);
        return -1;
    }
   
    der->length = sz; 
    Base64Decode(tmp, sz, der->buffer, &der->length);

    free(tmp);
    fclose(file);

    return 0;
}


int read_file(SSL_CTX* ctx, const char* file, int format, int type)
{
    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM)
        return SSL_BAD_FILETYPE;

    if (type == CA_TYPE) {
        buffer der;
        der.buffer = 0;
        if (PemToDer(file, CERT_TYPE, &der) < 0) {
            free(der.buffer);
            return SSL_BAD_FILE;
        }
        AddCA(ctx, der); /* takes der over */
    }

    return SSL_SUCCESS;
}



