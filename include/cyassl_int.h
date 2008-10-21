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

#ifdef CYASSL_CALLBACKS
    #include "openssl/cyassl_callbacks.h"
    #include <signal.h>
#endif

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #ifndef SINGLE_THREADED
        #include <pthread.h>
    #endif
#endif

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
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
    #if !defined (NO_PSK)
        #define BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
        #define BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    #endif
#endif

#if !defined(NO_DH) && !defined(NO_AES) && !defined(NO_TLS) && defined(OPENSSL_EXTRA)
    #define BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    #define BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
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
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x39,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x33,
    TLS_RSA_WITH_AES_256_CBC_SHA      = 0x35,
    TLS_RSA_WITH_AES_128_CBC_SHA      = 0x2F,
    TLS_PSK_WITH_AES_256_CBC_SHA      = 0x8d,
    TLS_PSK_WITH_AES_128_CBC_SHA      = 0x8c,
    SSL_RSA_WITH_RC4_128_SHA          = 0x05,
    SSL_RSA_WITH_RC4_128_MD5          = 0x04,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0A
};


enum Misc {
    SERVER_END = 0,
    CLIENT_END,

    NO_COMPRESSION  =  0,
    ZLIB_COMPRESSION = 221,     /* CyaSSL zlib compression */
    SECRET_LEN      = 48,       /* pre RSA and all master */
    ENCRYPT_LEN     = 256,      /* allow 2048 bit static buffer */
    SIZEOF_SENDER   =  4,       /* clnt or srvr           */
    FINISHED_SZ     = MD5_DIGEST_SIZE + SHA_DIGEST_SIZE,
    MAX_RECORD_SIZE = 16384,    /* 2^14, max size by standard */
    MAX_MSG_EXTRA   = 68,       /* max added to msg, mac + pad */
    MAX_COMP_EXTRA  = 1024,     /* max compression extra */
    MAX_DH_SZ       = 612,      /* 2240 p, pub, g + 2 byte size for each */

    PAD_MD5        = 48,       /* pad length for finished */
    PAD_SHA        = 40,       /* pad length for finished */
    LENGTH_SZ      =  2,       /* length field for HMAC, data only */
    VERSION_SZ     =  2,       /* length of proctocol version */
    SEQ_SZ         =  8,       /* 64 bit sequence number  */
    BYTE3_LEN      =  3,       /* up to 24 bit byte lengths */
    ALERT_SIZE     =  2,       /* level + description     */
    REQUEST_HEADER =  2,       /* always use 2 bytes      */
    VERIFY_HEADER  =  2,       /* always use 2 bytes      */

    MAX_SUITE_SZ = 128,         /* only 64 suites for now! */
    RAN_LEN      = 32,         /* random length           */
    SEED_LEN     = RAN_LEN * 2, /* tls prf seed length    */
    ID_LEN       = 32,         /* session id length       */
    SUITE_LEN    =  2,         /* cipher suite sz length  */
    ENUM_LEN     =  1,         /* always a byte           */
    COMP_LEN     =  1,         /* compression length      */
    
    HANDSHAKE_HEADER_SZ = 4,   /* type + length(3)        */
    RECORD_HEADER_SZ    = 5,   /* type + version + len(2) */
    CERT_HEADER_SZ      = 3,   /* always 3 bytes          */
    REQ_HEADER_SZ       = 2,   /* cert request header sz  */
    HINT_LEN_SZ         = 2,   /* length of hint size field */

    FINISHED_LABEL_SZ   = 15,  /* TLS finished label size */
    TLS_FINISHED_SZ     = 12,  /* TLS has a shorter size  */
    MASTER_LABEL_SZ     = 13,  /* TLS master secret label sz */
    KEY_LABEL_SZ        = 13,  /* TLS key block expansion sz */
    MAX_PRF_HALF        = 128, /* Maximum half secret len */
    MAX_PRF_LABSEED     = 80,  /* Maximum label + seed len */
    MAX_PRF_DIG         = 148, /* Maximum digest len      */
    MAX_REQUEST_SZ      = 256, /* Maximum cert req len (no auth yet */
    SESSION_FLUSH_COUNT = 256, /* Flush session cache unless user turns off */ 

    RC4_KEY_SIZE        = 16,  /* always 128bit           */
    DES3_KEY_SIZE       = 24,  /* 3 des ede               */
    DES_IV_SIZE         = DES_BLOCK_SIZE,
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */
    AES_IV_SIZE         = 16,  /* always block size       */
    AES_128_KEY_SIZE    = 16,  /* for 128 bit             */

    MAX_HELLO_SZ       = 128,  /* max client or server hello */
    MAX_CERT_VERIFY_SZ = 1024, /* max   */
    CLIENT_HELLO_FIRST =  35,  /* Protocol + RAN_LEN + sizeof(id_len) */
    MAX_SUITE_NAME     =  48,  /* maximum length of cipher suite string */
    DEFAULT_TIMEOUT    = 500,  /* default resumption timeout in seconds */

    MAX_PSK_ID_LEN     = 128,  /* max psk identity/hint supported */
    MAX_PSK_KEY_LEN    =  64,  /* max psk key supported */

    NO_COPY            =   0,  /* should we copy static buffer for write */
    COPY               =   1   /* should we copy static buffer for write */
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
    typedef struct X509        X509;

    #undef X509_NAME
    typedef struct X509_NAME   X509_NAME;
#endif /* SSL_TYPES_DEFINED */


/* SSL Version */
typedef struct ProtocolVersion {
    byte major;
    byte minor;
} ProtocolVersion;


ProtocolVersion MakeSSLv3(void);
ProtocolVersion MakeTLSv1(void);
ProtocolVersion MakeTLSv1_1(void);


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

/* CyaSSL input buffer

   RFC 2246:

   length
       The length (in bytes) of the following TLSPlaintext.fragment.
       The length should not exceed 2^14.
*/
#define BUFFER16K_LEN RECORD_HEADER_SZ + MAX_RECORD_SIZE + \
                      MAX_COMP_EXTRA + MAX_MSG_EXTRA
typedef struct {
    word32 length;
    word32 idx;
    byte   buffer[BUFFER16K_LEN];
} buffer16K;

/* Cipher Suites holder */
typedef struct Suites {
    int    setSuites;               /* user set suites from default */
    byte   suites[MAX_SUITE_SZ];  
    word16 suiteSz;                 /* suite length in bytes        */
} Suites;


void InitSuites(Suites*, ProtocolVersion, byte, byte);
int  SetCipherList(SSL_CTX* ctx, const char* list);

#ifndef PSK_TYPES_DEFINED
    typedef unsigned int (*psk_client_callback)(SSL*, const char*, char*,
                          unsigned int, unsigned char*, unsigned int);
    typedef unsigned int (*psk_server_callback)(SSL*, const char*,
                          unsigned char*, unsigned int);
#endif /* PSK_TYPES_DEFINED */

/* OpenSSL context type */
struct SSL_CTX {
    SSL_METHOD* method;
    buffer      certificate;
    buffer      privateKey;
    Signer*     caList;           /* SSL_CTX owns this, SSL will reference */
    Suites      suites;
    void*       heap;             /* for user memory overrides */
    byte        verifyPeer;
    byte        verifyNone;
    byte        failNoCert;
    byte        sessionCacheOff;
    byte        sessionCacheFlushOff;
    byte        sendVerify;       /* for client side */
    byte        haveDH;           /* server DH parms set by user */
#ifndef NO_PSK
    byte        havePSK;          /* psk key set by user */
    psk_client_callback client_psk_cb;  /* client callback */
    psk_server_callback server_psk_cb;  /* server callback */
    char        server_hint[MAX_PSK_ID_LEN];
#endif /* NO_PSK */
};


void InitSSL_Ctx(SSL_CTX*, SSL_METHOD*);
void FreeSSL_Ctx(SSL_CTX*);


/* All cipher suite related info */
typedef struct CipherSpecs {
    byte bulk_cipher_algorithm;
    byte cipher_type;               /* block or stream */
    byte mac_algorithm;
    byte kea;                       /* key exchange algo */
    byte sig_algo;
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
    fortezza_kea,
    psk_kea 
};


/* Supported Authentication Schemes */
enum SignatureAlgorithm {
    anonymous_sa_algo = 0,
    rsa_sa_algo,
    dsa_sa_algo
};


/* Valid client certificate request types from page 27 */
enum ClientCertificateType {    
    rsa_sign            = 1, 
    dss_sign            = 2,
    rsa_fixed_dh        = 3,
    dss_fixed_dh        = 4,
    rsa_ephemeral_dh    = 5,
    dss_ephemeral_dh    = 6,
    fortezza_kea_cert   = 20
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
    FIRST_REPLY_FIRST,
    FIRST_REPLY_SECOND,
    FIRST_REPLY_THIRD,
    FIRST_REPLY_FOURTH,
    FINISHED_DONE,
    SECOND_REPLY_DONE
};


/* server accpet state for nonblocking restart */
enum AcceptState {
    ACCEPT_BEGIN = 0,
    ACCEPT_FIRST_REPLY_DONE,
    SERVER_HELLO_SENT,
    CERT_SENT,
    KEY_EXCHANGE_SENT,
    CERT_REQ_SENT,
    SERVER_HELLO_DONE,
    ACCEPT_SECOND_REPLY_DONE,
    CHANGE_CIPHER_SENT,
    ACCEPT_FINISHED_DONE,
    ACCEPT_THIRD_REPLY_DONE
};


typedef struct Buffers {
    buffer          certificate;            /* SSL_CTX owns */
    buffer          key;                    /* SSL_CTX owns */
    buffer          domainName;             /* for client check */
    buffer          serverDH_P;
    buffer          serverDH_G;
    buffer          serverDH_Pub;
    buffer          serverDH_Priv;
    buffer16K       inputBuffer;
    buffer16K       outputBuffer;
    buffer          clearOutputBuffer;
} Buffers;


typedef struct Options {
    byte            sessionCacheOff;
    byte            sessionCacheFlushOff;
    byte            cipherSuite;
    byte            serverState;
    byte            clientState;
    byte            handShakeState;
    byte            side;               /* client or server end */
    byte            verifyPeer;
    byte            verifyNone;
    byte            failNoCert;
    byte            sendVerify;
    byte            resuming;
    byte            tls;                /* using TLS ? */
    byte            tls1_1;             /* using TLSv1.1 ? */
    byte            connReset;          /* has the peer reset */
    byte            isClosed;           /* if we consider conn closed */
    byte            connectState;       /* nonblocking resume */
    byte            acceptState;        /* nonblocking resume */
    byte            usingCompression;   /* are we using compression */
    byte            haveDH;             /* server DH parms set by user */
    byte            usingPSK_cipher;    /* whether we're using psk as cipher */
    byte            sendAlertState;     /* nonblocking resume */ 
    byte            processReply;       /* nonblocking resume */
#ifndef NO_PSK
    byte            havePSK;            /* psk key set by user */
    psk_client_callback client_psk_cb;
    psk_server_callback server_psk_cb;
#endif /* NO_PSK */
} Options;


typedef struct Arrays {
    byte            clientRandom[RAN_LEN];
    byte            serverRandom[RAN_LEN];
    byte            sessionID[ID_LEN];
    byte            preMasterSecret[ENCRYPT_LEN];
    byte            masterSecret[SECRET_LEN];
#ifndef NO_PSK
    char            client_identity[MAX_PSK_ID_LEN];
    char            server_hint[MAX_PSK_ID_LEN];
    byte            psk_key[MAX_PSK_KEY_LEN];
    word32          psk_keySz;          /* acutal size */
#endif
    word32          preMasterSz;        /* differs for DH, actual size */
} Arrays;


#undef X509_NAME

struct X509_NAME {
    char  name[ASN_NAME_MAX];
    int   sz;
};


struct X509 {
    X509_NAME issuer;
    X509_NAME subject;
};


/* record layer header for PlainText, Compressed, and CipherText */
typedef struct RecordLayerHeader {
    byte            type;
    ProtocolVersion version;
    byte            length[2];
} RecordLayerHeader;

/* OpenSSL ssl type */
struct SSL {
    SSL_CTX*        ctx;
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
    Hashes          certHashes;         /* for cert verify */
    Signer*         caList;             /* SSL_CTX owns */
    Buffers         buffers;
    Options         options;
    Arrays          arrays;
    SSL_SESSION     session;
    X509            peerCert;           /* X509 peer cert */
    RsaKey          peerRsaKey;
    byte            peerRsaKeyPresent;
    hmacfp          hmac;
    void*           heap;               /* for user overrides */
    RecordLayerHeader curRL;
    word16            curSize;
#ifdef HAVE_LIBZ
    z_stream        c_stream;           /* compression   stream */
    z_stream        d_stream;           /* decompression stream */
    byte            didStreamInit;      /* for stream init and end */
#endif
#ifdef CYASSL_CALLBACKS
    HandShakeInfo   handShakeInfo;      /* info saved during handshake */
    TimeoutInfo     timeoutInfo;        /* info saved during handshake */
    byte            hsInfoOn;           /* track handshake info        */
    byte            toInfoOn;           /* track timeout   info        */
#endif
};


int  InitSSL(SSL*, SSL_CTX*);
void FreeSSL(SSL*);


#ifdef CYASSL_CALLBACKS
    void InitHandShakeInfo(HandShakeInfo*);
    void FinishHandShakeInfo(HandShakeInfo*, const SSL*);
    void AddPacketName(const char*, HandShakeInfo*);

    void InitTimeoutInfo(TimeoutInfo*);
    void FreeTimeoutInfo(TimeoutInfo*, void*);
    void AddPacketInfo(const char*, TimeoutInfo*, const byte*, int, void*);
    void AddLateName(const char*, TimeoutInfo*);
#endif


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
int SendCertificateRequest(SSL*);
int SendServerKeyExchange(SSL*);
int SendBuffered(SSL*);
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
    int SendCertificateVerify(SSL*);
#endif /* NO_CYASSL_CLIENT */

#ifndef NO_CYASSL_SERVER
    int SendServerHello(SSL*);
    int SendServerHelloDone(SSL*);
#endif /* NO_CYASSL_SERVER */


#ifndef NO_TLS
    

#endif /* NO_TLS */



typedef double timer_d;

timer_d Timer(void);
word32  LowResTimer(void);


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

