/* cyassl_int.h
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



#ifndef CYASSL_INT_H
#define CYASSL_INT_H


#include "types.h"
#include "random.h"
#include "md5.h"
#include "des3.h"
#include "aes.h"
#include "asn.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <pthread.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif


#ifdef _WIN32
    typedef unsigned int SOCKET_T;
#else
    typedef int SOCKET_T;
#endif


typedef byte word24[3];

/* Define or comment out the cipher suites you'd like to be compiled in
   make sure to use at least one BUILD_SSL_xxx or BUILD_TLS_xxx is defined

   When adding cipher suites, add name to cipher_names, idx to cipher_name_idx
*/
#ifndef NO_RC4
    #define BUILD_SSL_RSA_WITH_RC4_128_SHA
    #define BUILD_SSL_RSA_WITH_RC4_128_MD5
#endif

#ifndef NO_DES3
    #define BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
#endif

#if !defined(NO_AES) && !defined(NO_TLS)
    #define BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    #define BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
#endif



#if defined(BUILD_SSL_RSA_WITH_RC4_128_SHA) || \
    defined(BUILD_SSL_RSA_WITH_RC4_128_MD5)
    #define BUILD_ARC4
#endif

#if defined(BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA)
    #define BUILD_DES3
#endif

#if defined(BUILD_TLS_RSA_WITH_AES_128_CBC_SHA) || \
    defined(BUILD_TLS_RSA_WITH_AES_256_CBC_SHA)
    #define BUILD_AES
#endif


#ifdef NO_DES3
    #define DES_BLOCK_SIZE 8
#endif

#ifdef NO_AES
    #define AES_BLOCK_SIZE 16
#endif


/* actual cipher values, 2nd byte */
enum {
    TLS_RSA_WITH_AES_256_CBC_SHA  = 0x35,
    TLS_RSA_WITH_AES_128_CBC_SHA  = 0x2F,
    SSL_RSA_WITH_RC4_128_SHA      = 0x05,
    SSL_RSA_WITH_RC4_128_MD5      = 0x04,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A
};


enum Misc {
    SERVER_END = 0,
    CLIENT_END,

    NO_COMPRESSION  =  0,
    SECRET_LEN      = 48,       /* pre RSA and all master */
    ENCRYPT_LEN     = 256,      /* allow 2048 bit static buffer */
    SIZEOF_SENDER   =  4,       /* clnt or srvr           */
    FINISHED_SZ     = MD5_DIGEST_SIZE + SHA_DIGEST_SIZE,
    MAX_RECORD_SIZE = 16384,    /* 2^14, max size by standard */
    MAX_MSG_EXTRA   = 68,       /* max added to msg, mac + pad */

    PAD_MD5        = 48,       /* pad length for finished */
    PAD_SHA        = 40,       /* pad length for finished */
    LENGTH_SZ      =  2,       /* length field for HMAC, data only */
    VERSION_SZ     =  2,       /* length of proctocol version */
    SEQ_SZ         =  8,       /* 64 bit sequence number  */
    BYTE3_LEN      =  3,       /* up to 24 bit byte lengths */
    ALERT_SIZE     =  2,       /* level + description     */
    REQUEST_HEADER =  2,       /* always use 2 bytes      */

    MAX_SUITE_SZ = 64,         /* only 32 suites for now! */
    RAN_LEN      = 32,         /* random length           */
    SEED_LEN     = RAN_LEN * 2, /* tls prf seed length    */
    ID_LEN       = 32,         /* session id length       */
    SUITE_LEN    =  2,         /* cipher suite sz length  */
    ENUM_LEN     =  1,         /* always a byte           */
    COMP_LEN     =  1,         /* compression length      */
    
    HANDSHAKE_HEADER_SZ = 4,   /* type + length(3)        */
    RECORD_HEADER_SZ    = 5,   /* type + version + len(2) */
    CERT_HEADER_SZ      = 3,   /* always 3 bytes          */

    FINISHED_LABEL_SZ   = 15,  /* TLS finished label size */
    TLS_FINISHED_SZ     = 12,  /* TLS has a shorter size  */
    MASTER_LABEL_SZ     = 13,  /* TLS master secret label sz */
    KEY_LABEL_SZ        = 13,  /* TLS key block expansion sz */
    MAX_PRF_HALF        = 48,  /* Maximum half secret len */
    MAX_PRF_LABSEED     = 80,  /* Maximum label + seed len */
    MAX_PRF_DIG         = 148, /* Maximum digest len      */

    RC4_KEY_SIZE        = 16,  /* always 128bit           */
    DES3_KEY_SIZE       = 24,  /* 3 des ede               */
    DES_IV_SIZE         = DES_BLOCK_SIZE,
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */
    AES_IV_SIZE         = 16,  /* always block size       */
    AES_128_KEY_SIZE    = 16,  /* for 128 bit             */

    MAX_HELLO_SZ       = 128,  /* max client or server hello */
    CLIENT_HELLO_FIRST =  35,  /* Protocol + RAN_LEN + sizeof(id_len) */
    MAX_ERROR_SZ       =  80,  /* user supplied buffer size is bigger 120 */
    MAX_SUITE_NAME     =  48,  /* maximum length of cipher suite string */
    DEFAULT_TIMEOUT    = 500   /* default resumption timeout in seconds */
};


/* states */
enum states {
    NULL_STATE = 0,

    SERVER_HELLO_COMPLETE,
    SERVER_CERT_COMPLETE,
    SERVER_KEYEXCHANGE_COMPLETE,
    SERVER_HELLODONE_COMPLETE,
    SERVER_FINISHED_COMPLETE,

    CLIENT_HELLO_COMPLETE,
    CLIENT_KEYEXCHANGE_COMPLETE,
    CLIENT_FINISHED_COMPLETE,

    HANDSHAKE_DONE
};


#ifndef SSL_TYPES_DEFINED
    typedef struct SSL_METHOD  SSL_METHOD;
    typedef struct SSL_CTX     SSL_CTX;
    typedef struct SSL_SESSION SSL_SESSION;
    typedef struct SSL         SSL;
#endif /* SSL_TYPES_DEFINED */


/* SSL Version */
typedef struct ProtocolVersion {
    byte major;
    byte minor;
} ProtocolVersion;


ProtocolVersion MakeSSLv3();


/* OpenSSL method type */
struct SSL_METHOD {
    ProtocolVersion version;
    int             side;           /* connection side, server or client */
    int             verifyPeer;     /* request or send certificate       */
    int             verifyNone;     /* whether to verify certificate     */
    int             failNoCert;    
};


/* defautls to client */
void InitSSL_Method(SSL_METHOD*, ProtocolVersion);


/* CyaSSL buffer type */
typedef struct buffer {
    word32 length;
    byte*  buffer;
} buffer;


/* Cipher Suites holder */
typedef struct Suites {
    int    setSuites;               /* user set suites from default */
    byte   suites[MAX_SUITE_SZ];  
    word16 suiteSz;                 /* suite length in bytes        */
} Suites;


void InitSuites(Suites*, ProtocolVersion);
int  SetCipherList(SSL_CTX* ctx, const char* list);


/* OpenSSL context type */
struct SSL_CTX {
    SSL_METHOD* method;
    buffer      certificate;
    buffer      privateKey;
    Signer*     caList;         /* SSL_CTX owns this, SSL will reference */
    Suites      suites;
    byte        verifyPeer;
    byte        verifyNone;
    byte        failNoCert;
    byte        sessionCacheOff;
};


void InitSSL_Ctx(SSL_CTX*, SSL_METHOD*);
void FreeSSL_Ctx(SSL_CTX*);


/* All cipher suite related info */
typedef struct CipherSpecs {
    byte bulk_cipher_algorithm;
    byte cipher_type;               /* block or stream */
    byte mac_algorithm;
    byte kea;                       /* key exchange algo */
    byte hash_size;
    byte pad_size;
    word16 key_size;
    word16 iv_size;
    word16 block_size;
} CipherSpecs;



/* Supported Ciphers from page 43  */
enum BulkCipherAlgorithm { 
    cipher_null,
    rc4,
    rc2,
    des,
    triple_des,             /* leading 3 (3des) not valid identifier */
    des40,
    idea,
    aes
};


/* Supported Message Authentication Codes from page 43 */
enum MACAlgorithm { 
    no_mac,
    md5_mac,
    sha_mac,
    rmd_mac
};


/* Supported Key Exchange Protocols */
enum KeyExchangeAlgorithm { 
    no_kea = 0,
    rsa_kea, 
    diffie_hellman_kea, 
    fortezza_kea 
};


enum CipherType { stream, block };


/* keys and secrets */
typedef struct Keys {
    byte client_write_MAC_secret[SHA_DIGEST_SIZE];   /* max sizes */
    byte server_write_MAC_secret[SHA_DIGEST_SIZE]; 
    byte client_write_key[AES_256_KEY_SIZE];         /* max sizes */
    byte server_write_key[AES_256_KEY_SIZE]; 
    byte client_write_IV[AES_IV_SIZE];               /* max sizes */
    byte server_write_IV[AES_IV_SIZE];

    word32 peer_sequence_number;
    word32 sequence_number;

    word32 encryptSz;             /* last size of encrypted data   */
    byte   encryptionOn;          /* true after change cipher spec */
} Keys;


/* cipher for now */
typedef union {
#ifdef BUILD_ARC4
    Arc4 arc4;
#endif
#ifdef BUILD_DES3
    Des3 des3;
#endif
#ifdef BUILD_AES
    Aes  aes;
#endif
} Ciphers;


/* hashes type */
typedef struct Hashes {
    byte md5[MD5_DIGEST_SIZE];
    byte sha[SHA_DIGEST_SIZE];
} Hashes;



/* openSSL session type */
struct SSL_SESSION {
    byte         sessionID[ID_LEN];
    byte         masterSecret[SECRET_LEN];
    word32       bornOn;                        /* create time in seconds   */
    word32       timeout;                       /* timeout in seconds       */
    SSL_SESSION* next;
};


SSL_SESSION* GetSession(SSL*);
int          SetSession(SSL*, SSL_SESSION*);

typedef void (*hmacfp) (SSL*, byte*, const byte*, word32, int, int);


/* client connect state for nonblocking restart */
enum ConnectState {
    CONNECT_BEGIN = 0,
    CLIENT_HELLO_SENT,
    FIRST_REPLY_DONE,
    FINISHED_DONE,
    SECOND_REPLY_DONE
};


/* server accpet state for nonblocking restart */
enum AcceptState {
    ACCEPT_BEGIN = 0,
    ACCEPT_FIRST_REPLY_DONE,
    SERVER_HELLO_DONE,
    ACCEPT_SECOND_REPLY_DONE,
    ACCEPT_FINISHED_DONE,
    ACCEPT_THIRD_REPLY_DONE
};


typedef struct Buffers {
    buffer          certificate;            /* SSL_CTX owns */
    buffer          key;                    /* SSL_CTX owns */
    buffer          peerCert;
    buffer          peerKey;
    buffer          bufferedData;           /* decrypted data */
    buffer          bufferedInput;          /* raw partial input */
    buffer          domainName;             /* for client check */
} Buffers;



typedef struct Options {
    byte            sessionCacheOff;
    byte            cipherSuite;
    byte            serverState;
    byte            clientState;
    byte            handShakeState;
    byte            side;               /* client or server end */
    byte            verifyPeer;
    byte            verifyNone;
    byte            failNoCert;
    byte            resuming;
    byte            tls;                /* using TLS ? */
    byte            tls1_1;             /* using TLSv1.1 ? */
    byte            isNonBlocking;      /* option set on this socket */
    byte            connectState;       /* nonblocking resume */
    byte            acceptState;        /* nonblocking resume */
} Options;


typedef struct Arrays {
    byte            clientRandom[RAN_LEN];
    byte            serverRandom[RAN_LEN];
    byte            sessionID[ID_LEN];
    byte            preMasterSecret[SECRET_LEN];
    byte            masterSecret[SECRET_LEN];
} Arrays;


/* OpenSSL ssl type */
struct SSL {
    int             error;
    ProtocolVersion version;            /* negotiated version */
    ProtocolVersion chVersion;          /* client hello version */
    Suites          suites;
    Ciphers         encrypt;
    Ciphers         decrypt;
    CipherSpecs     specs;
    Keys            keys;
    SOCKET_T        socket;
    RNG             rng;
    Md5             hashMd5;            /* md5 hash of handshake msgs */
    Sha             hashSha;            /* sha hash of handshake msgs */
    Hashes          verifyHashes;
    Signer*         caList;             /* SSL_CTX owns */
    Buffers         buffers;
    Options         options;
    Arrays          arrays;
    SSL_SESSION     session;
    hmacfp          hmac;
};


int  InitSSL(SSL*, SSL_CTX*);
void FreeSSL(SSL*);



/* record layer header for PlainText, Compressed, and CipherText */
typedef struct RecordLayerHeader {
    byte            type;
    ProtocolVersion version;
    byte            length[2];
    /* internal add-ons after here */
    word16          size;            /* host order length, not sent or recvd */
} RecordLayerHeader;


/* Record Layer Header identifier from page 12 */
enum ContentType {
    no_type            = 0,
    change_cipher_spec = 20, 
    alert              = 21, 
    handshake          = 22, 
    application_data   = 23 
};


/* handshake header, same for each message type, pgs 20/21 */
typedef struct HandShakeHeader {
    byte            type;
    word24          length;
    /* internal add-ons after here */
    word32          size;         /* host order length, not sent or recvd */
} HandShakeHeader;


enum HandShakeType {
    no_shake            = -1,
    hello_request       = 0, 
    client_hello        = 1, 
    server_hello        = 2,
    certificate         = 11, 
    server_key_exchange = 12,
    certificate_request = 13, 
    server_hello_done   = 14,
    certificate_verify  = 15, 
    client_key_exchange = 16,
    finished            = 20
};


/* Valid Alert types from page 16/17 */
enum AlertDescription {
    close_notify            = 0,
    unexpected_message      = 10,
    bad_record_mac          = 20,
    decompression_failure   = 30,
    handshake_failure       = 40,
    no_certificate          = 41,
    bad_certificate         = 42,
    unsupported_certificate = 43,
    certificate_revoked     = 44,
    certificate_expired     = 45,
    certificate_unknown     = 46,
    illegal_parameter       = 47
};


enum AlertLevel { 
    alert_warning = 1, 
    alert_fatal = 2
};


static const byte client[SIZEOF_SENDER] = { 0x43, 0x4C, 0x4E, 0x54 };
static const byte server[SIZEOF_SENDER] = { 0x53, 0x52, 0x56, 0x52 };

static const byte tls_client[FINISHED_LABEL_SZ + 1] = "client finished";
static const byte tls_server[FINISHED_LABEL_SZ + 1] = "server finished";


/* internal functions */
int SendChangeCipher(SSL*);
int SendData(SSL*, const void*, int);
int SendCertificate(SSL*);
int ReceiveData(SSL*, byte*, int);
int SendFinished(SSL*);
int SendAlert(SSL*, int, int);
int ProcessReply(SSL*);

int SetCipherSpecs(SSL*);
int MakeMasterSecret(SSL*);

void AddSession(SSL*);
int  DeriveKeys(SSL* ssl);
int  StoreKeys(SSL* ssl, const byte* keyData);


#ifndef NO_CYASSL_CLIENT
    int SendClientHello(SSL*);
    int SendClientKeyExchange(SSL*);
#endif /* NO_CYASSL_CLIENT */

#ifndef NO_CYASSL_SERVER
    int SendServerHello(SSL*);
    int SendServerHelloDone(SSL*);
#endif /* NO_CYASSL_SERVER */


#ifndef NO_TLS
    

#endif /* NO_TLS */



typedef double timer_d;

timer_d Timer();
word32  LowResTimer();


#ifdef SINGLE_THREADED
    typedef int CyaSSL_Mutex;

    #define InitMutex(m)
    #define FreeMutex(m)
    #define LockMutex(m)
    #define UnLockMutex(m)

#else /* SINGLE_THREADED */

    #ifdef _WIN32
        typedef CRITICAL_SECTION CyaSSL_Mutex;

        #define InitMutex(m)     InitializeCriticalSection(m)
        #define FreeMutex(m)     DeleteCriticalSection(m)
        #define LockMutex(m)     EnterCriticalSection(m)
        #define UnLockMutex(m)   LeaveCriticalSection(m)

    #elif defined(_POSIX_THREADS)
        typedef pthread_mutex_t CyaSSL_Mutex;

        #define InitMutex(m)     pthread_mutex_init(m, 0)
        #define FreeMutex(m)     pthread_mutex_destroy(m)
        #define LockMutex(m)     pthread_mutex_lock(m) 
        #define UnLockMutex(m)   pthread_mutex_unlock(m)

    #else
        #error Need a mutex type in multithreaded mode
    #endif /* _WIN32 */

#endif /* SINGLE_THREADED */


#ifdef DEBUG_CYASSL

    void CYASSL_ENTER(const char* msg);
    void CYASSL_LEAVE(const char* msg, int ret);

    void CYASSL_ERROR(int);
    void CYASSL_MSG(const char* msg);

#else /* DEBUG_CYASSL   */

    #define CYASSL_ENTER(m)
    #define CYASSL_LEAVE(m, r)

    #define CYASSL_ERROR(e) 
    #define CYASSL_MSG(m)

#endif /* DEBUG_CYASSL  */


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* CyaSSL_INT_H */

