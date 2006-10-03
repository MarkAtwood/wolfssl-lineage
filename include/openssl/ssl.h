/* ssl.h                                
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


/*  ssl.h defines openssl compatibility layer 
 *
 */



#ifndef CYASSL_OPENSSL_H_
#define CYASSL_OPENSSL_H_

#include <stdio.h>   /* ERR_print fp */
#include "rsa.h"


#undef X509_NAME   /* wincrypt.h clash */

#ifdef __cplusplus
    extern "C" {
#endif


void InitCyaSSL();   /* need to call once to load library (session cache) */
void FreeCyaSSL();   /* call when done to free session cache */


typedef struct SSL          SSL;          
typedef struct SSL_SESSION  SSL_SESSION;
typedef struct SSL_METHOD   SSL_METHOD;
typedef struct SSL_CTX      SSL_CTX;

typedef struct X509       X509;


/* redeclare guard */
#define SSL_TYPES_DEFINED




/* because mySQL dereferences to use error and current_cert, even after calling
 * get functions for local references */

typedef struct X509_STORE_CTX {
    int   error;
    int   error_depth;
    X509* current_cert;
} X509_STORE_CTX;


SSL_METHOD *SSLv3_server_method(void);
SSL_METHOD *SSLv3_client_method(void);
SSL_METHOD *TLSv1_server_method(void);  
SSL_METHOD *TLSv1_client_method(void);

int SSL_CTX_use_certificate_file(SSL_CTX*, const char*, int);
int SSL_CTX_use_PrivateKey_file(SSL_CTX*, const char*, int);

SSL_CTX* SSL_CTX_new(SSL_METHOD*);
SSL* SSL_new(SSL_CTX*);
int  SSL_set_fd (SSL*, int);
int  SSL_connect(SSL*);
int  SSL_write(SSL*, const void*, int);
int  SSL_read(SSL*, void*, int);
int  SSL_accept(SSL*);
void SSL_CTX_free(SSL_CTX*);
void SSL_free(SSL*);
int  SSL_shutdown(SSL*);

int  SSL_get_error(SSL*, int);

int          SSL_set_session(SSL *ssl, SSL_SESSION *session);
SSL_SESSION* SSL_get_session(SSL* ssl);


typedef int (*VerifyCallback)(int, X509_STORE_CTX*);
typedef int (*pem_password_cb)(char*, int, int, void*);

void SSL_CTX_set_verify(SSL_CTX*, int, VerifyCallback verify_callback);

int  SSL_CTX_load_verify_locations(SSL_CTX*, const char*, const char*);

int  SSL_pending(SSL*);


enum { /* ssl Constants */
    SSL_BAD_CERTTYPE    = -8,
    SSL_BAD_STAT        = -7,
    SSL_BAD_PATH        = -6,
    SSL_BAD_FILETYPE    = -5,
    SSL_BAD_FILE        = -4,
    SSL_NOT_IMPLEMENTED = -3,
    SSL_UNKNOWN         = -2,
    SSL_FATAL_ERROR     = -1,
    SSL_NORMAL_SHUTDOWN =  0,
    SSL_ERROR_NONE      =  0,   /* for most functions */
    SSL_FAILURE         =  0,   /* for some functions */
    SSL_SUCCESS	        =  1,

    SSL_FILETYPE_ASN1    = 10,
    SSL_FILETYPE_PEM     = 11,
    SSL_FILETYPE_DEFAULT = 10, /* ASN1 */

    SSL_VERIFY_NONE                 = 0,
    SSL_VERIFY_PEER                 = 1,
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    SSL_VERIFY_CLIENT_ONCE          = 4,

    SSL_SESS_CACHE_OFF                = 30,
    SSL_SESS_CACHE_CLIENT             = 31,
    SSL_SESS_CACHE_SERVER             = 32,
    SSL_SESS_CACHE_BOTH               = 33,
    SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34,
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35,

    SSL_OP_MICROSOFT_SESS_ID_BUG            = 50,
    SSL_OP_NETSCAPE_CHALLENGE_BUG           = 51,
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 52,
    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG      = 53,
    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER       = 54,
    SSL_OP_MSIE_SSLV2_RSA_PADDING           = 55,
    SSL_OP_SSLEAY_080_CLIENT_DH_BUG         = 56,
    SSL_OP_TLS_D5_BUG                       = 57,
    SSL_OP_TLS_BLOCK_PADDING_BUG            = 58,
    SSL_OP_TLS_ROLLBACK_BUG                 = 59,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS      = 60,
    SSL_OP_ALL                              = 61,
    SSL_OP_SINGLE_DH_USE                    = 62,
    SSL_OP_EPHEMERAL_RSA                    = 63,
    SSL_OP_NO_SSLv2                         = 64,
    SSL_OP_NO_SSLv3                         = 65,
    SSL_OP_NO_TLSv1                         = 66,
    SSL_OP_PKCS1_CHECK_1                    = 67,
    SSL_OP_PKCS1_CHECK_2                    = 68,
    SSL_OP_NETSCAPE_CA_DN_BUG               = 69,
    SSL_OP_NON_EXPORT_FIRST                 = 70,
    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG  = 71,

    SSL_ERROR_WANT_READ        = 80,
    SSL_ERROR_WANT_WRITE       = 81,
    SSL_ERROR_SYSCALL          = 82,
    SSL_ERROR_WANT_X509_LOOKUP = 83,
    SSL_ERROR_ZERO_RETURN      = 84,
    SSL_ERROR_SSL              = 85,

    SSL_SENT_SHUTDOWN     = 90,
    SSL_RECEIVED_SHUTDOWN = 91,
    SSL_CB_LOOP           = 92,
    SSL_ST_CONNECT        = 93,
    SSL_ST_ACCEPT         = 94,
    SSL_CB_ALERT          = 95,
    SSL_CB_READ           = 96,
    SSL_CB_HANDSHAKE_DONE = 97

};


enum { /* X509 Constants */
    X509_V_OK                                 =  0,
    X509_V_ERR_CERT_CHAIN_TOO_LONG            =  1,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT      =  2,
    X509_V_ERR_CERT_NOT_YET_VALID             =  3,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD =  4,
    X509_V_ERR_CERT_HAS_EXPIRED               =  5,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD  =  6,
    X509_FILETYPE_PEM                         =  7,
    X509_LU_X509                              =  8,
    X509_LU_CRL                               =  9,
    X509_V_ERR_CRL_SIGNATURE_FAILURE          = 10,
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 11,
    X509_V_ERR_CRL_HAS_EXPIRED                = 12,
    X509_V_ERR_CERT_REVOKED                   = 13

};

enum {  /* ERR Constants */
    ERR_TXT_STRING = 1,
    EVP_R_BAD_DECRYPT = 2
};




#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CyaSSL_openssl_h__ */
