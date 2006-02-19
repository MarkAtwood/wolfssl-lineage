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



#ifndef CyaSSL_INT_H
#define CyaSSL_INT_H

#include "types.h"
#include "random.h"
#include "sha.h"
#include "md5.h"
#include "des3.h"


#ifdef _WIN32
    typedef int SOCKET_T;
#else
    typedef unsigned int SOCKET_T;
#endif



typedef byte word24[3];

/* Define or comment out the cipher suites you'd like to be compiled in
   make sure to use at least one BUILD_SSL_xxx is defined
*/
#ifndef NO_RC4
    #define BUILD_SSL_RSA_WITH_RC4_128_SHA
    #define BUILD_SSL_RSA_WITH_RC4_128_MD5
#endif

#ifndef NO_DES3
    #define BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
#endif



#if defined(BUILD_SSL_RSA_WITH_RC4_128_SHA) || \
    defined(BUILD_SSL_RSA_WITH_RC4_128_MD5)
    #define BUILD_ARC4
#endif

#if defined(BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA)
    #define BUILD_DES3
#endif


#ifdef NO_DES3
    #define DES_BLOCK_SIZE 8
#endif


/* actual cipher values, 2nd byte */
enum {
    SSL_RSA_WITH_RC4_128_SHA      = 0x05,
    SSL_RSA_WITH_RC4_128_MD5      = 0x04,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA = 0x0a
};


enum Misc {
    SERVER_END = 0,
    CLIENT_END,

    NO_COMPRESSION  =  0,
    SECRET_LEN      = 48,       /* pre RSA and all master */
    SIZEOF_SENDER   =  4,       /* clnt or srvr           */
    FINISHED_SZ     = MD5_DIGEST_SIZE + SHA_DIGEST_SIZE,
    MAX_RECORD_SIZE = 16384,    /* 2^14, max size by standard */
    MAX_MSG_EXTRA   = 68,       /* max added to msg, mac + pad */

    PAD_MD5        = 48,       /* pad length for finished */
    PAD_SHA        = 40,       /* pad length for finished */
    LENGTH_SZ      =  2,       /* length field for HMAC, data only */
    SEQ_SZ         =  8,       /* 64 bit sequence number  */
    BYTE3_LEN      =  3,       /* up to 24 bit byte lengths */
    ALERT_SIZE     =  2,       /* level + description     */
    REQUEST_HEADER =  2,       /* always use 2 bytes      */

    MAX_SUITE_SZ = 64,         /* only 32 suites for now! */
    RAN_LEN      = 32,         /* random length           */
    ID_LEN       = 32,         /* session id length       */
    SUITE_LEN    =  2,         /* cipher suite sz length  */
    ENUM_LEN     =  1,         /* always a byte           */
    COMP_LEN     =  1,         /* compression length      */
    
    HANDSHAKE_HEADER_SZ = 4,   /* type + length(3)        */
    RECORD_HEADER_SZ    = 5,   /* type + version + len(2) */
    CERT_HEADER_SZ      = 3,   /* always 3 bytes          */

    RC4_KEY_SIZE        = 16,  /* always 128bit           */
    DES3_KEY_SIZE       = 24,  /* 3 des ede               */
    DES_IV_SIZE         = DES_BLOCK_SIZE,
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */
    AES_IV_SIZE         = 16,  /* always block size       */

    MAX_HELLO_SZ       = 128,  /* max client or server hello */
    CLIENT_HELLO_FIRST =  35   /* Protocol + RAN_LEN + sizeof(id_len) */
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


/* CyaSSK buffer type */
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


void InitSuites(Suites*);


/* CA Signers */
typedef struct Signer {
    buffer publicKey;
    char*  name;                    /* common name */
    byte   hash[SHA_DIGEST_SIZE];   /* sha hash of names in certificate */
} Signer;


void InitSigner(Signer*);
void FreeSigner(Signer*);

typedef Signer SignerList;  /* just one for now */

/* OpenSSL context type */
struct SSL_CTX {
    SSL_METHOD* method;
    buffer      certificate;
    buffer      privateKey;
    SignerList  caList;
    Suites      suites;
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
} Ciphers;


/* hashes type */
typedef struct Hashes {
    byte md5[MD5_DIGEST_SIZE];
    byte sha[SHA_DIGEST_SIZE];
} Hashes;


/* OpenSSL ssl type */
struct SSL {
    int             error;
    ProtocolVersion version;
    Suites          suites;
    Ciphers         encrypt;
    Ciphers         decrypt;
    CipherSpecs     specs;
    Keys            keys;
    SOCKET_T        socket;
    RNG             rng;
    Md5             hashMd5;                /* md5 hash of handshake msgs */
    Sha             hashSha;                /* sha hash of handshake msgs */
    Hashes          verifyHashes;
    byte            clientRandom[RAN_LEN];
    byte            serverRandom[RAN_LEN];
    byte            sessionID[ID_LEN];
    byte            cipherSuite;
    buffer          peerCert;
    buffer          peerKey;
    buffer          bufferedData;
    byte            serverState;
    byte            clientState;
    byte            handShakeState;
    byte            side;                   /* client or server end */
    byte            preMasterSecret[SECRET_LEN];
    byte            masterSecret[SECRET_LEN];
};


void InitSSL(SSL*, SSL_CTX*);
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


/* Certificate file Type */
enum CertType {
    CERT_TYPE       = 0, 
    PRIVATEKEY_TYPE,
    CA_TYPE
};


 
/* internal functions */
int SendClientHello(SSL*);
int SendClientKeyExchange(SSL*);
int SendChangeCipher(SSL*);
int SendData(SSL*, const void*, int);
int ReceiveData(SSL*, byte*, int);
int SendFinished(SSL*);
int SendAlert(SSL*, int, int);
int ProcessReply(SSL*);

int SetCipherSpecs(SSL*);
int MakeMasterSecret(SSL*);

int read_file(SSL_CTX*, const char*, int format, int type);

#endif /* CyaSSL_INT_H */

