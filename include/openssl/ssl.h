/* ssl.h                                
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

/*  ssl.h defines openssl compatibility layer 
 *
 */

#ifndef ysSSLopenssl_h__
#define yaSSLopenssl_h__

#include <stdio.h>   /* ERR_print fp */

#ifdef __cplusplus
extern "C" {
#endif


typedef struct SSL_METHOD  SSL_METHOD;   /* forward the SSL types C style */
typedef struct SSL_CTX     SSL_CTX;
typedef struct SSL_SESSION SSL_SESSION;

#ifdef __cplusplus
    class  SSL;	
#else
    typedef struct SSL SSL;          
#endif


/* Big Number stuff, different file? */
typedef struct BIGNUM BIGNUM;

BIGNUM *BN_bin2bn(const unsigned char*, int, BIGNUM*);


/* Diffie-Hellman stuff, different file? */
/* mySQL deferences to set group parameters */
typedef struct DH {
    BIGNUM* p;
    BIGNUM* g;
} DH;

DH*  DH_new(void);
void DH_free(DH*);


/* X509 stuff, different file? */
typedef struct X509 X509;

void X509_free(X509*);

/* because mySQL dereferences to use error and current_cert, even after calling
 * get functions for local references */
typedef struct X509_STORE_CTX {
    int   error;
    X509* current_cert;
} X509_STORE_CTX;


typedef struct X509_NAME X509_NAME;


X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX*);
int   X509_STORE_CTX_get_error(X509_STORE_CTX*);
int   X509_STORE_CTX_get_error_depth(X509_STORE_CTX*);

char*       X509_NAME_oneline(X509_NAME*, char*, int);
X509_NAME*  X509_get_issuer_name(X509*);
X509_NAME*  X509_get_subject_name(X509*);
const char* X509_verify_cert_error_string(long);

enum { /* X509 Constants */
    X509_V_OK                                 = 0,
    X509_V_ERR_CERT_CHAIN_TOO_LONG            = 1,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT      = 2,
    X509_V_ERR_CERT_NOT_YET_VALID             = 3,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 4,
    X509_V_ERR_CERT_HAS_EXPIRED               = 5,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD  = 6,
};


/* Error stuff, could move to yassl_error */
unsigned long ERR_get_error_line_data(const char**, int*, const char**, int *);
void          ERR_print_errors_fp(FILE*);
char*         ERR_error_string(unsigned long,char*);


enum {  /* ERR Constants */
    ERR_TXT_STRING = 1,
};



SSL_CTX* SSL_CTX_new(SSL_METHOD*);
SSL* SSL_new(SSL_CTX*);
int  SSL_set_fd (SSL*, int);
int  SSL_connect(SSL*);
int  SSL_write(SSL*, const void*, int);
int  SSL_read(SSL*, void*, int);
int  SSL_accept(SSL*);
void SSL_CTX_free(SSL_CTX*);
void SSL_free(SSL*);
int  SSL_clear(SSL*);
int  SSL_shutdown(SSL*);

void SSL_set_connect_state(SSL*);
void SSL_set_accept_state(SSL*);
int  SSL_do_handshake(SSL*);

const char* SSL_get_cipher(SSL*);
const char* SSL_get_cipher_name(SSL*);	           /* uses SSL_get_cipher */
char*       SSL_get_shared_ciphers(SSL*, char*, int);
const char* SSL_get_cipher_list(SSL*, int);
const char* SSL_get_version(SSL*);

int  SSL_get_error(SSL*, int);
void SSL_load_error_strings(void);

SSL_SESSION* SSL_get_session(SSL* ssl);
long         SSL_SESSION_set_timeout(SSL_SESSION*, long);
X509*        SSL_get_peer_certificate(SSL*);
long         SSL_get_verify_result(SSL*);


typedef int (*VerifyCallback)(int, X509_STORE_CTX*);
void SSL_CTX_set_verify(SSL_CTX*, int, VerifyCallback verify_callback);
int  SSL_CTX_load_verify_locations(SSL_CTX*, const char*, const char*);
int  SSL_CTX_set_default_verify_paths(SSL_CTX*);
int  SSL_CTX_check_private_key(SSL_CTX*);
int  SSL_CTX_set_session_id_context(SSL_CTX*, const unsigned char*,
                                    unsigned int);

long SSL_CTX_sess_accept(SSL_CTX*);
long SSL_CTX_sess_connect(SSL_CTX*);
long SSL_CTX_sess_accept_good(SSL_CTX*);
long SSL_CTX_sess_connect_good(SSL_CTX*);
long SSL_CTX_sess_accept_renegotiate(SSL_CTX*);
long SSL_CTX_sess_connect_renegotiate(SSL_CTX*);
long SSL_CTX_sess_hits(SSL_CTX*);
long SSL_CTX_sess_cb_hits(SSL_CTX*);
long SSL_CTX_sess_cache_full(SSL_CTX*);
long SSL_CTX_sess_misses(SSL_CTX*);
long SSL_CTX_sess_timeouts(SSL_CTX*);
long SSL_CTX_sess_number(SSL_CTX*);
long SSL_CTX_sess_get_cache_size(SSL_CTX*);

int SSL_CTX_get_verify_mode(SSL_CTX*);
int SSL_get_verify_mode(SSL*);
int SSL_CTX_get_verify_depth(SSL_CTX*);
int SSL_get_verify_depth(SSL*);

long SSL_get_default_timeout(SSL*);
long SSL_CTX_get_session_cache_mode(SSL_CTX*);
int  SSL_session_reused(SSL*);


enum { /* ssl Constants */
    SSL_BAD_FILETYPE    = -5,
    SSL_BAD_FILE        = -4,
    SSL_NOT_IMPLEMENTED = -3,
    SSL_UNKNOWN         = -2,
    SSL_FATAL_ERROR     = -1,
    SSL_NORMAL_SHUTDOWN =  0,
    SSL_ERROR_NONE      =  0,
    SSL_SUCCESS	        =  1,

    SSL_FILETYPE_ASN1    = 10,
    SSL_FILETYPE_PEM     = 11,
    SSL_FILETYPE_DEFAULT = 10, /* ASN1 */

    SSL_VERIFY_NONE        = 20,
    SSL_VERIFY_PEER        = 21,
    SSL_VERIFY_CLIENT_ONCE = 22,

    SSL_SESS_CACHE_OFF                = 30,
    SSL_SESS_CACHE_CLIENT             = 31,
    SSL_SESS_CACHE_SERVER             = 32,
    SSL_SESS_CACHE_BOTH               = 33,
    SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34,
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35,
    
};


SSL_METHOD *SSLv3_method(void);
SSL_METHOD *SSLv3_server_method(void);
SSL_METHOD *SSLv3_client_method(void);
SSL_METHOD *TLSv1_server_method(void);  
SSL_METHOD *TLSv1_client_method(void);

int SSL_CTX_use_certificate_file(SSL_CTX*, const char*, int);
int SSL_CTX_use_PrivateKey_file(SSL_CTX*, const char*, int);
int SSL_CTX_set_cipher_list(SSL_CTX*, const char*);

long SSL_CTX_sess_set_cache_size(SSL_CTX*, long);
long SSL_CTX_set_tmp_dh(SSL_CTX*, DH*);

void OpenSSL_add_all_algorithms(void);


/* EVP stuff, des and md5, different file? */
typedef struct MAC MAC;
typedef MAC EVP_MD;

typedef struct BulkCipher BulkCipher;
typedef BulkCipher EVP_CIPHER;

typedef unsigned char DES_cblock[8];
typedef const  DES_cblock const_DES_cblock;
typedef struct DES_key_schedule{int x;} DES_key_schedule; /* msvc in c mode   */
                                                          /* won't take empty */
                                                             
const EVP_MD*     EVP_md5(void);
const EVP_CIPHER* EVP_des_ede3_cbc(void);

typedef unsigned char opaque;

int EVP_BytesToKey(const EVP_CIPHER*, const EVP_MD*, const opaque*,
                   const opaque*, int, int, opaque*, opaque*);

void DES_set_key_unchecked(const_DES_cblock*, DES_key_schedule*);
void DES_ede3_cbc_encrypt(const opaque*, opaque*, long, DES_key_schedule*,
                        DES_key_schedule*, DES_key_schedule*, DES_cblock*, int);



#ifdef __cplusplus
}      /* extern "C" */
#endif


#endif /* yaSSLopenssl_h__ */
