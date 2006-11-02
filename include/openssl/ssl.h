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


#undef X509_NAME   /* wincrypt.h clash */

#ifdef __cplusplus
    extern "C" {
#endif


typedef struct SSL          SSL;          
typedef struct SSL_SESSION  SSL_SESSION;
typedef struct SSL_METHOD   SSL_METHOD;
typedef struct SSL_CTX      SSL_CTX;

typedef struct X509       X509;


/* redeclare guard */
#define SSL_TYPES_DEFINED




typedef struct X509_STORE_CTX X509_STORE_CTX;


SSL_METHOD *SSLv3_server_method(void);
SSL_METHOD *SSLv3_client_method(void);
SSL_METHOD *TLSv1_server_method(void);  
SSL_METHOD *TLSv1_client_method(void);
SSL_METHOD *TLSv1_1_server_method(void);  
SSL_METHOD *TLSv1_1_client_method(void);

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


void SSL_load_error_strings(void);
int  SSL_library_init();
long SSL_CTX_set_session_cache_mode(SSL_CTX*, long);
int  SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);

/* only supports full name from cipher_name[] delimited by : */
int  SSL_CTX_set_cipher_list(SSL_CTX*, const char*);

char* ERR_error_string(unsigned long,char*);
void  ERR_error_string_n(unsigned long e, char *buf, size_t len);

/* CyaSSL extension, provide last error from SSL_get_error
   since not using thread storage error queue */
void  ERR_print_errors_fp(FILE*, int err);


enum { /* ssl Constants */
    SSL_ERROR_NONE      =  0,   /* for most functions */
    SSL_FAILURE         =  0,   /* for some functions */
    SSL_SUCCESS	        =  1,

    SSL_BAD_CERTTYPE    = -8,
    SSL_BAD_STAT        = -7,
    SSL_BAD_PATH        = -6,
    SSL_BAD_FILETYPE    = -5,
    SSL_BAD_FILE        = -4,
    SSL_NOT_IMPLEMENTED = -3,
    SSL_UNKNOWN         = -2,
    SSL_FATAL_ERROR     = -1,

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

    SSL_ERROR_WANT_READ        =  2,
    SSL_ERROR_WANT_WRITE       =  3,
    SSL_ERROR_SYSCALL          = 82,
    SSL_ERROR_WANT_X509_LOOKUP = 83,
    SSL_ERROR_ZERO_RETURN      = 84,
    SSL_ERROR_SSL              = 85,

    SSL_SENT_SHUTDOWN     = 90,
    SSL_RECEIVED_SHUTDOWN = 91,
};




/* CyaSSL extensions */

/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
int CyaSSL_check_domain_name(SSL* ssl, const char* dn);

void InitCyaSSL();   /* need to call once to load library (session cache) */
void FreeCyaSSL();   /* call when done to free session cache */

int  CyaSSL_Debugging_ON();   /* turn logging on, only if compiled in */
void CyaSSL_Debugging_OFF();  /* turn logging off */


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CyaSSL_openssl_h__ */
