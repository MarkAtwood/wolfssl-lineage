/* yassl_types.hpp                                
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

/*  yaSSL types  header defines all constants, enums, and typedefs
 *  from the SSL.v3 specification "draft-freier-ssl-version3-02.txt"
 */


#ifndef yaSSL_TYPES_HPP
#define yaSSL_TYPES_HPP

namespace yaSSL {


typedef unsigned char  uint8;
typedef unsigned short uint16;
typedef unsigned int   uint32;
typedef uint8          uint24[3];
typedef uint32         uint64[2];

typedef uint8  opaque;
typedef opaque byte;

typedef unsigned int uint;

 
// all length constants in bytes
const int ID_LEN            =  32;  // session id length
const int SUITE_LEN         =   2;  // cipher suite length
const int SECRET_LEN        =  48;  // pre RSA and all master secret length
const int MASTER_ROUNDS     =   3;  // master secret derivation rounds
const int RAN_LEN           =  32;  // client and server random length
const int MAC_BLOCK_SZ      =  64;  // MAC block size, & padding
const int MD5_LEN           =  16;  // MD5 digest length
const int SHA_LEN           =  20;  // SHA digest length
const int PREFIX            =   3;  // up to 3 prefix letters for secret rounds
const int KEY_PREFIX        =   7;  // up to 7 prefix letters for key rounds
const int FORTEZZA_MAX      = 128;  // Maximum Fortezza Key length
const int MAX_SUITE_SZ      =  64;  // 32 max suites * sizeof(suite)
const int MAX_SUITE_NAME    =  48;  // max length of suite name
const int SIZEOF_ENUM       =   1;  // SSL considers an enum 1 byte, not 4
const int SIZEOF_SENDER     =   4;  // Sender constant, for finished generation
const int PAD_MD5           =  48;  // pad length 1 and 2 for md5 finished
const int PAD_SHA           =  40;  // should be 44, specd wrong by netscape
const int CERT_HEADER       =   3;  // always use 3 bytes for certificate
const int RECORD_HEADER     =   5;  // type + version + length(2)
const int HANDSHAKE_HEADER  =   4;  // type + length(3)
const int FINISHED_SZ       = MD5_LEN + SHA_LEN; // sizeof finished data
const int TLS_FINISHED_SZ   =  12;  // TLS verify data size
const int SEQ_SZ            =   8;  // 64 bit sequence number
const int LENGTH_SZ         =   2;  // length field for HMAC, data only
const int VERSION_SZ        = SIZEOF_ENUM * 2;  // SSL/TLS length of version
const int RSA_MOD           =  64;  // 512 bit RSA modulus length
const int RSA_EXP           =   3;  // 512 bit RSA exponent length
const int RSA_KEA_SIG       =  64;  // 512 bit RSA key exchange signature len
const int DSA_KEA_SIG       =  48;  // DSA key exchange signature len
const int DES_KEY_SZ        =   8;  // DES Key length
const int DES_EDE_KEY_SZ    =  24;  // DES EDE Key length
const int DES_IV_SZ         =   8;  // Init Vector length for DES
const int DES_BLOCK         =   8;  // DES is always fixed block size 8
const int RC4_KEY_SZ        =  16;  // RC4 Key length
const int MASTER_LABEL_SZ   =  13;  // TLS master secret label size
const int KEY_LABEL_SZ      =  13;  // TLS key block expansion size
const int FINISHED_LABEL_SZ =  15;  // TLS finished lable length
const int SEED_LEN          = RAN_LEN * 2; // TLS seed, client + server random
const int DEFAULT_TIMEOUT   = 500;  // Default Session timeout in seconds


typedef uint8 Cipher;             // first byte is always 0x00 for SSLv3 & TLS

typedef opaque Random[RAN_LEN];

typedef opaque* DistinguishedName;

typedef bool IsExportable;


enum CompressionMethod { no_compression = 0 };

enum CipherType { stream, block };

enum CipherChoice { change_cipher_spec_choice = 1 };

enum PublicValueEncoding { implicit_encoding, explicit_encoding };

enum ConnectionEnd { server_end, client_end };

enum AlertLevel { warning = 1, fatal = 2, };



// Record Layer Header identifier from page 12
enum ContentType {
    no_type            = 0,
    change_cipher_spec = 20, 
    alert              = 21, 
    handshake          = 22, 
    application_data   = 23 
};


// HandShake Layer Header identifier from page 20
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


// Valid Alert types from page 16/17
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


// Supported Key Exchange Protocols
enum KeyExchangeAlgorithm { 
    no_kea = 0,
    rsa_kea, 
    diffie_hellman_kea, 
    fortezza_kea 
};


// Supported Authentication Schemes
enum SignatureAlgorithm { 
    anonymous_sa_algo = 0, 
    rsa_sa_algo, 
    dsa_sa_alog 
};


// Valid client certificate request types from page 27
enum ClientCertificateType {    
    rsa_sign            = 1, 
    dss_sign            = 2,
    rsa_fixed_dh        = 3,
    dss_fixed_dh        = 4,
    rsa_ephemeral_dh    = 5,
    dss_ephemeral_dh    = 6,
    fortezza_kea_cert   = 20
};


// Supported Ciphers from page 43
enum BulkCipherAlgorithm { 
    cipher_null,
    rc4,
    rc2,
    des,
    triple_des,             // leading 3 (3des) not valid identifier
    des40,
    idea
};


// Supported Message Authentication Codes from page 43
enum MACAlgorithm { 
    no_mac,
    md5,
    sha 
};


// Certificate file Type
enum CertType { Cert = 0, PrivateKey };


// all Cipher Suites from pages 41/42
const Cipher SSL_NULL_WITH_NULL_NULL                =  0; // { 0x00, 0x00 }
const Cipher SSL_RSA_WITH_NULL_MD5                  =  1; // { 0x00, 0x01 }
const Cipher SSL_RSA_WITH_NULL_SHA                  =  2; // { 0x00, 0x02 }
const Cipher SSL_RSA_EXPORT_WITH_RC4_40_MD5         =  3; // { 0x00, 0x03 }
const Cipher SSL_RSA_WITH_RC4_128_MD5               =  4; // { 0x00, 0x04 }
const Cipher SSL_RSA_WITH_RC4_128_SHA               =  5; // { 0x00, 0x05 }
const Cipher SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5     =  6; // { 0x00, 0x06 }
const Cipher SSL_RSA_WITH_IDEA_CBC_SHA              =  7; // { 0x00, 0x07 }
const Cipher SSL_RSA_EXPORT_WITH_DES40_CBC_SHA      =  8; // { 0x00, 0x08 }
const Cipher SSL_RSA_WITH_DES_CBC_SHA               =  9; // { 0x00, 0x09 }
const Cipher SSL_RSA_WITH_3DES_EDE_CBC_SHA          = 10; // { 0x00, 0x0A }
const Cipher SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   = 11; // { 0x00, 0x0B }
const Cipher SSL_DH_DSS_WITH_DES_CBC_SHA            = 12; // { 0x00, 0x0C }
const Cipher SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA       = 13; // { 0x00, 0x0D }
const Cipher SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   = 14; // { 0x00, 0x0E }
const Cipher SSL_DH_RSA_WITH_DES_CBC_SHA            = 15; // { 0x00, 0x0F }
const Cipher SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA       = 16; // { 0x00, 0x10 }
const Cipher SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = 17; // { 0x00, 0x11 }
const Cipher SSL_DHE_DSS_WITH_DES_CBC_SHA           = 18; // { 0x00, 0x12 }
const Cipher SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA      = 19; // { 0x00, 0x13 }
const Cipher SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = 20; // { 0x00, 0x14 }
const Cipher SSL_DHE_RSA_WITH_DES_CBC_SHA           = 21; // { 0x00, 0x15 }
const Cipher SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA      = 22; // { 0x00, 0x16 }
const Cipher SSL_DH_anon_EXPORT_WITH_RC4_40_MD5     = 23; // { 0x00, 0x17 }
const Cipher SSL_DH_anon_WITH_RC4_128_MD5           = 24; // { 0x00, 0x18 }
const Cipher SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA  = 25; // { 0x00, 0x19 }
const Cipher SSL_DH_anon_WITH_DES_CBC_SHA           = 26; // { 0x00, 0x1A }
const Cipher SSL_DH_anon_WITH_3DES_EDE_CBC_SHA      = 27; // { 0x00, 0x1B }
const Cipher SSL_FORTEZZA_KEA_WITH_NULL_SHA         = 28; // { 0x00, 0x1C }
const Cipher SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = 29; // { 0x00, 0x1D }
const Cipher SSL_FORTEZZA_KEA_WITH_RC4_128_SHA      = 30; // { 0x00, 0x1E }


// fill with MD5 pad size since biggest required
const opaque PAD1[PAD_MD5] =  { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
                              };
const opaque PAD2[PAD_MD5] =  { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };

const opaque client[SIZEOF_SENDER] = { 0x43, 0x4C, 0x4E, 0x54 };
const opaque server[SIZEOF_SENDER] = { 0x53, 0x52, 0x56, 0x52 };

const opaque tls_client[FINISHED_LABEL_SZ + 1] = "client finished";
const opaque tls_server[FINISHED_LABEL_SZ + 1] = "server finished";

const opaque master_label[MASTER_LABEL_SZ + 1] = "master secret";
const opaque key_label   [KEY_LABEL_SZ + 1]    = "key expansion";


} // naemspace

#endif // yaSSL_TYPES_HPP
