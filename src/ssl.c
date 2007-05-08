/* ssl.c
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
#include "cyassl_error.h"
#include "coding.h"

#ifdef OPENSSL_EXTRA
    #include "openssl/evp.h"
    #include "openssl/hmac.h"
    #include "openssl/crypto.h"
    #include "openssl/des.h"
    #include "../ctaocrypt/include/hmac.h"
    #include "../ctaocrypt/include/random.h"
    #include "../ctaocrypt/include/des3.h"
#endif

#include <stdlib.h>
#include <assert.h>


static int ProcessFile(SSL_CTX*, const char*, int format, int type);


#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */



SSL_CTX* SSL_CTX_new(SSL_METHOD* method)
{
    SSL_CTX* ctx = (SSL_CTX*) malloc(sizeof(SSL_CTX));
    if (ctx)
        InitSSL_Ctx(ctx, method);

    return ctx;
}


void SSL_CTX_free(SSL_CTX* ctx)
{
    FreeSSL_Ctx(ctx);
}


SSL* SSL_new(SSL_CTX* ctx)
{

    SSL* ssl = (SSL*) malloc(sizeof(SSL));
    if (ssl)
        if (InitSSL(ssl, ctx) < 0) {
            FreeSSL(ssl);
            ssl = 0;
        }

    return ssl;
}


void SSL_free(SSL* ssl)
{
    FreeSSL(ssl);
}


int SSL_set_fd(SSL* ssl, int fd)
{
    ssl->socket = fd;
    return SSL_SUCCESS;
}


int SSL_write(SSL* ssl, const void* buffer, int sz)
{
    int ret;

    CYASSL_ENTER("SSL_write()");

    ret = SendData(ssl, buffer, sz);

    CYASSL_LEAVE("SSL_write()", ret);
    return ret;
}


int SSL_read(SSL* ssl, void* buffer, int sz)
{
    int ret; 

    CYASSL_ENTER("SSL_read()");

    ret = ReceiveData(ssl, (byte*)buffer, min(sz, MAX_RECORD_SIZE));

    CYASSL_LEAVE("SSL_read()", ret);
    return ret;
}


int SSL_shutdown(SSL* ssl)
{
    /* try to send alert, not an error if can't */
    if (!ssl->options.isClosed) {
        SendAlert(ssl, alert_warning, close_notify);
        ssl->options.isClosed = 1;  /* don't send close_notify twice */
    }

    return SSL_SUCCESS;
}


int SSL_get_error(SSL* ssl, int dummy)
{
    if (ssl->error == WANT_READ)
        return SSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
    else if (ssl->error == WANT_WRITE)
        return SSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
    return ssl->error;
}


char* ERR_error_string(unsigned long errNumber, char* buffer)
{
    static char* msg = "Please supply a buffer for error string";

    if (buffer) {
        SetErrorString(errNumber, buffer);
        return buffer;
    }

    return msg;
}


void ERR_error_string_n(unsigned long e, char* buf, size_t len)
{
    if (len) ERR_error_string(e, buf);
}


void ERR_print_errors_fp(FILE* fp, int err)
{
    char buffer[MAX_ERROR_SZ + 1];

    SetErrorString(err, buffer);
    fprintf(fp, "%s", buffer);
}


unsigned long ERR_get_error_line_data(const char**, int*, const char**, int *)
{
    /* Not implemented */
    return 0;
}


int SSL_pending(SSL* ssl)
{
    return ssl->buffers.bufferedData.buffer ?
           ssl->buffers.bufferedData.length : 0;
}


/* just one for now TODO: add dir support from path */
int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* file,
                                  const char* path)
{
    return ProcessFile(ctx, file, SSL_FILETYPE_PEM, CA_TYPE);
}


int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type)
{
    return ProcessFile(ctx, file, type, CERT_TYPE);
}


int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type)
{
    return ProcessFile(ctx, file, type, PRIVATEKEY_TYPE);
}


void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, VerifyCallback vc)
{
    if (mode & SSL_VERIFY_PEER)
        ctx->verifyPeer = 1;

    if (mode == SSL_VERIFY_NONE)
        ctx->verifyNone = 1;

    if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        ctx->failNoCert = 1;
}


SSL_SESSION* SSL_get_session(SSL* ssl)
{
    return GetSession(ssl);
}


int SSL_set_session(SSL* ssl, SSL_SESSION* session)
{
    return SetSession(ssl, session);
}


void SSL_load_error_strings(void)   /* compatibility only */
{}


int SSL_library_init(void)  /* compatiblity only */
{
    return SSL_SUCCESS;
}


int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file)
{
    /* add first to ctx, all tested implementations support this */
    return ProcessFile(ctx, file, SSL_FILETYPE_PEM, CA_TYPE);
}


/* on by default but allow user to turn off */
long SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, long mode)
{
    if (mode == SSL_SESS_CACHE_OFF)
        ctx->sessionCacheOff = 1;

    return SSL_SUCCESS;
}


int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* list)
{
    if (SetCipherList(ctx, list))
        return SSL_SUCCESS;
    else
        return SSL_FAILURE;
}


/* client only parts */
#ifndef NO_CYASSL_CLIENT

    SSL_METHOD* SSLv3_client_method(void)
    {
        SSL_METHOD* method = (SSL_METHOD*) malloc(sizeof(SSL_METHOD));
        if (method)
            InitSSL_Method(method, MakeSSLv3());
        return method;
    }


    int SSL_connect(SSL* ssl)
    {
        int neededState;

        CYASSL_ENTER("SSL_connect()");

        assert(ssl->options.side == CLIENT_END);

        if (ssl->writeBuffer.send.buffer) {
            if ( (ssl->error = SendBuffered(ssl)) == 0) {
                ssl->options.connectState++;
                CYASSL_MSG("connect state: Advanced from buffered send");
            }
            else {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
        }

        switch (ssl->options.connectState) {

        case CONNECT_BEGIN :
            /* always send client hello first */
            if ( (ssl->error = SendClientHello(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.connectState = CLIENT_HELLO_SENT;
            CYASSL_MSG("connect state: CLIENT_HELLO_SENT");

        case CLIENT_HELLO_SENT :
            neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                          SERVER_HELLODONE_COMPLETE;
            /* get response */
            while (ssl->options.serverState < neededState)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            ssl->options.connectState = FIRST_REPLY_DONE;
            CYASSL_MSG("connect state: FIRST_REPLY_DONE");

        case FIRST_REPLY_DONE :
            if (!ssl->options.resuming) {
                if ( (ssl->error = SendClientKeyExchange(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
            else {
                ssl->options.connectState = FIRST_REPLY_SECOND;
                CYASSL_MSG("connect state: FIRST_REPLY_SECOND");
            }

        case FIRST_REPLY_SECOND :

            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.connectState = FIRST_REPLY_THIRD;
            CYASSL_MSG("connect state: FIRST_REPLY_THIRD");

        case FIRST_REPLY_THIRD :

            if ( (ssl->error = SendFinished(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            ssl->options.connectState = FINISHED_DONE;
            CYASSL_MSG("connect state: FINISHED_DONE");

        case FINISHED_DONE :
            /* get response */
            while (ssl->options.serverState < SERVER_FINISHED_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
          
            ssl->options.connectState = SECOND_REPLY_DONE;
            CYASSL_MSG("connect state: SECOND_REPLY_DONE");

        case SECOND_REPLY_DONE:

            CYASSL_LEAVE("SSL_connect()", SSL_SUCCESS);
            return SSL_SUCCESS;

        default:
            CYASSL_MSG("Unknown connect state ERROR");
            return SSL_FATAL_ERROR; /* unknown connect state */
        }
    }

#endif /* NO_CYASSL_CLIENT */


/* server only parts */
#ifndef NO_CYASSL_SERVER

    SSL_METHOD* SSLv3_server_method(void)
    {
        SSL_METHOD* method = (SSL_METHOD*) malloc(sizeof(SSL_METHOD));
        if (method) {
            InitSSL_Method(method, MakeSSLv3());
            method->side = SERVER_END;
        }
        return method;
    }


    int SSL_accept(SSL* ssl)
    {
        assert(ssl->options.side == SERVER_END);

        CYASSL_ENTER("SSL_accept()");

        switch (ssl->options.acceptState) {
    
        case ACCEPT_BEGIN :
            /* get response */
            while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
            CYASSL_MSG("accept state ACCEPT_FIRST_REPLY_DONE");

        case ACCEPT_FIRST_REPLY_DONE :
            if ( (ssl->error = SendServerHello(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            if (!ssl->options.resuming) {
                if ( (ssl->error = SendCertificate(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }

                if ( (ssl->error = SendServerHelloDone(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
            ssl->options.acceptState = SERVER_HELLO_DONE;
            CYASSL_MSG("accept state SERVER_HELLO_DONE");

        case SERVER_HELLO_DONE :
            if (!ssl->options.resuming) {
                while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
                    if ( (ssl->error = ProcessReply(ssl)) < 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }
            }
            ssl->options.acceptState = ACCEPT_SECOND_REPLY_DONE;
            CYASSL_MSG("accept state  ACCEPT_SECOND_REPLY_DONE");
          
        case ACCEPT_SECOND_REPLY_DONE : 
            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            if ( (ssl->error = SendFinished(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            ssl->options.acceptState = ACCEPT_FINISHED_DONE;
            CYASSL_MSG("accept state ACCEPT_FINISHED_DONE");

        case ACCEPT_FINISHED_DONE :
            if (ssl->options.resuming)
                while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
                    if ( (ssl->error = ProcessReply(ssl)) < 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }

            ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
            CYASSL_MSG("accept state ACCEPT_THIRD_REPLY_DONE");

        case ACCEPT_THIRD_REPLY_DONE :
            CYASSL_LEAVE("SSL_accept()", SSL_SUCCESS);
            return SSL_SUCCESS;

        default :
            CYASSL_MSG("Unknown accept state ERROR");
            return SSL_FATAL_ERROR;
        }
    }

#endif /* NO_CYASSL_SERVER */



/* owns der */
static int AddCA(SSL_CTX* ctx, buffer der)
{
    word32      ret;
    DecodedCert cert;
    Signer*     signer = 0;

    InitDecodedCert(&cert, der.buffer);
    ret = ParseCert(&cert, der.length, CA_TYPE, NO_VERIFY, 0);

    if (ret == 0) {
        /* take over signer parts */
        signer = MakeSigner();
        if (!signer)
            ret = MEMORY_ERROR;
        else {
            signer->publicKey  = cert.publicKey;
            signer->pubKeySize = cert.pubKeySize;
            signer->name = cert.subject;
            memcpy(signer->hash, cert.subjectHash, SHA_DIGEST_SIZE);

            cert.publicKey = 0;  /* don't free here */
            cert.subject   = 0;

            signer->next = ctx->caList;
            ctx->caList  = signer;   /* takes ownership */
        }
    }

    FreeDecodedCert(&cert);
    free(der.buffer);

    if (ret == 0) return SSL_SUCCESS;
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
        return SSL_BAD_FILE;

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
        return SSL_BAD_FILE;
    }

    sz = end - begin;
    tmp = (byte*) malloc(sz);
    if (!tmp) {
        fclose(file);
        return MEMORY_ERROR;
    }

    fseek(file, begin, SEEK_SET);
    if (fread(tmp, sz, 1, file) != 1 || 
            (der->buffer = (byte*) malloc(sz)) == 0) {
        free(tmp);
        fclose(file);
        return FREAD_ERROR;
    }
   
    der->length = sz; 
    Base64Decode(tmp, sz, der->buffer, &der->length);

    free(tmp);
    fclose(file);

    return 0;
}


static int ProcessFile(SSL_CTX* ctx, const char* file, int format, int type)
{
    buffer der; 
    der.buffer = 0;

    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM)
        return SSL_BAD_FILETYPE;

    if (format == SSL_FILETYPE_PEM) {
        if (PemToDer(file, type == PRIVATEKEY_TYPE ? type : CERT_TYPE, &der)
                < 0) {
            free(der.buffer);
            return SSL_BAD_FILE;
        }
    }
    else {  /* ASN1 (DER) */
        long   sz;
        FILE*  input = fopen(file, "rb");

        if (!input)
            return SSL_BAD_FILE;
        
        fseek(input, 0, SEEK_END);
        sz = ftell(input);
        rewind(input);

        der.buffer = (byte*) malloc(sz);
        if (!der.buffer) return MEMORY_ERROR;
        der.length = sz;
        sz = fread(der.buffer, sz, 1, input);
        if (sz != 1) {
            fclose(input);
            free(der.buffer);
            return SSL_BAD_FILE;
        }
        fclose(input);
    }

    if (type == CA_TYPE)
        return AddCA(ctx, der);     /* takes der over */
    else if (type == CERT_TYPE)
        ctx->certificate = der;     /* takes der over */
    else if (type == PRIVATEKEY_TYPE)
        ctx->privateKey = der;      /* takes der over */
    else {
        free(der.buffer);
        return SSL_BAD_CERTTYPE;
    }

    return SSL_SUCCESS;
}


static SSL_SESSION* sessions = 0;

/* quiet compiler */
#ifndef SINGLE_THREADED
    static CyaSSL_Mutex mutex; /* sessions mutex */
#endif


void InitCyaSSL(void)
{
    InitMutex(&mutex);
}


void FreeCyaSSL(void)
{
    SSL_SESSION* next;

    LockMutex(&mutex);

    next = sessions;
    while( (sessions = next) ) {
        next = sessions->next;
        free(sessions);
    }

    UnLockMutex(&mutex);

    FreeMutex(&mutex);
}


SSL_SESSION* GetSession(SSL* ssl)
{
    SSL_SESSION* current, *ret = 0;
    const byte* id = ssl->arrays.sessionID;

    if (ssl->options.sessionCacheOff)
        return 0;

    LockMutex(&mutex);

    current = sessions;
    while (current) {
        if (memcmp(current->sessionID, id, ID_LEN) == 0) {
            if (LowResTimer() < (current->bornOn + current->timeout))
                ret = current;
            break;
        }
        current = current->next;
    }

    UnLockMutex(&mutex);

    return ret;
}


int SetSession(SSL* ssl, SSL_SESSION* session)
{
    if (ssl->options.sessionCacheOff)
        return SSL_FAILURE;

    if (LowResTimer() < (session->bornOn + session->timeout)) {
        ssl->session  = *session;
        ssl->options.resuming = 1;

        return SSL_SUCCESS;
    }
    return SSL_FAILURE;  /* session timed out */
}


void AddSession(SSL* ssl)
{
    SSL_SESSION* sess;

    if (ssl->options.sessionCacheOff)
        return;

    sess = (SSL_SESSION*) malloc(sizeof(SSL_SESSION));
    if (sess) {
        memcpy(sess->masterSecret, ssl->arrays.masterSecret, SECRET_LEN);
        memcpy(sess->sessionID, ssl->arrays.sessionID, ID_LEN);

        sess->timeout = DEFAULT_TIMEOUT;
        sess->bornOn  = LowResTimer();

        LockMutex(&mutex);

        sess->next = sessions;
        sessions   = sess;

        UnLockMutex(&mutex);
    }
}


/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
int CyaSSL_check_domain_name(SSL* ssl, const char* dn)
{
    if (ssl->buffers.domainName.buffer)
        free(ssl->buffers.domainName.buffer);

    ssl->buffers.domainName.length = strlen(dn) + 1;
    ssl->buffers.domainName.buffer =
                     (byte*) malloc(ssl->buffers.domainName.length);

    if (ssl->buffers.domainName.buffer) {
        strncpy((char*)ssl->buffers.domainName.buffer, dn,
                ssl->buffers.domainName.length);
        return SSL_SUCCESS;
    }
    else {
        ssl->error = MEMORY_ERROR;
        return SSL_FAILURE;
    }
}



#ifdef OPENSSL_EXTRA

    unsigned long SSLeay(void)
    {
        return SSLEAY_VERSION_NUMBER;
    }


    const char* SSLeay_version(int type)
    {
        static const char* version = "SSLeay CyaSSL compatibility";
        return version;
    }


    void MD5_Init(MD5_CTX* md5)
    {
        assert(sizeof(MD5_CTX) >= sizeof(Md5));
        InitMd5((Md5*)md5);
    }


    void MD5_Update(MD5_CTX* md5, const void* input, unsigned long sz)
    {
        Md5Update((Md5*)md5, (const byte*)input, sz);
    }


    void MD5_Final(byte* input, MD5_CTX* md5)
    {
        Md5Final((Md5*)md5, input);
    }


    void SHA_Init(SHA_CTX* sha)
    {
        assert(sizeof(SHA_CTX) >= sizeof(Sha));
        InitSha((Sha*)sha);
    }


    void SHA_Update(SHA_CTX* sha, const void* input, unsigned long sz)
    {
        ShaUpdate((Sha*)sha, (const byte*)input, sz);
    }


    void SHA_Final(byte* input, SHA_CTX* sha)
    {
        ShaFinal((Sha*)sha, input);
    }


    const EVP_MD* EVP_md5(void)
    {
        static const char* type = "MD5";
        return type;
    }


    const EVP_MD* EVP_sha1(void)
    {
        static const char* type = "SHA";
        return type;
    }


    void EVP_MD_CTX_init(EVP_MD_CTX* ctx)
    {
        /* do nothing */ 
    }


    int EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx)
    {
        return 0;
    }    


    int EVP_DigestInit(EVP_MD_CTX* ctx, const EVP_MD* type)
    {
        if (strncmp(type, "MD5", 3) == 0) {
             ctx->macType = MD5;
             MD5_Init((MD5_CTX*)&ctx->hash);
        }
        else if (strncmp(type, "SHA", 3) == 0) {
             ctx->macType = SHA;
             SHA_Init((SHA_CTX*)&ctx->hash);
        }
        else
             return -1;

        return 0;
    }


    int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* data, size_t sz)
    {
        if (ctx->macType == MD5) 
            MD5_Update((MD5_CTX*)&ctx->hash, data, sz);
        else if (ctx->macType == SHA) 
            SHA_Update((SHA_CTX*)&ctx->hash, data, sz);
        else
            return -1;

        return 0;
    }


    int EVP_DigestFinal(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)
    {
        if (ctx->macType == MD5) {
            MD5_Final(md, (MD5_CTX*)&ctx->hash);
            if (s) *s = MD5_DIGEST_SIZE;
        }
        else if (ctx->macType == SHA) {
            SHA_Final(md, (SHA_CTX*)&ctx->hash);
            if (s) *s = SHA_DIGEST_SIZE;
        }
        else
            return -1;

        return 0;
    }


    int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)
    {
        return EVP_DigestFinal(ctx, md, s);
    }


    unsigned char* HMAC(const EVP_MD* evp_md, const void* key, int key_len,
        const unsigned char* d, int n, unsigned char* md, unsigned int* md_len)
    {
        Hmac hmac;

        if (!md) return 0;  /* no static buffer support */

        if (strncmp(evp_md, "MD5", 3) == 0) {
            HmacSetKey(&hmac, MD5, key, key_len);
            if (md_len) *md_len = MD5_DIGEST_SIZE;
        }
        else if (strncmp(evp_md, "SHA", 3) == 0) {
            HmacSetKey(&hmac, SHA, key, key_len);    
            if (md_len) *md_len = SHA_DIGEST_SIZE;
        }
        else
            return 0;

        HmacUpdate(&hmac, d, n);
        HmacFinal(&hmac, md);
    
        return md;
    }

    unsigned long ERR_get_error(void)
    {
        /* TODO: */
        return 0;
    }


    int RAND_status(void)
    {
        return 1;  /* CTaoCrypt provides enough seed */
    }


    int RAND_bytes(unsigned char* buf, int num)
    {
        RNG rng;

        if (InitRng(&rng))
           return 0;

        RNG_GenerateBlock(&rng, buf, num);

        return 1;
    }


    int DES_key_sched(const_DES_cblock* key, DES_key_schedule* schedule)
    {
        memcpy(schedule, key, sizeof(const_DES_cblock));
        return 0;
    }


    void DES_cbc_encrypt(const unsigned char* input, unsigned char* output,
                     long length, DES_key_schedule* schedule, DES_cblock* ivec,
                     int enc)
    {
        Des des;
        Des_SetKey(&des, (const byte*)schedule, (const byte*)ivec, !enc);

        if (enc)
            Des_CbcEncrypt(&des, output, input, length);
        else
            Des_CbcDecrypt(&des, output, input, length);
    }


    /* correctly sets ivec for next call */
    void DES_ncbc_encrypt(const unsigned char* input, unsigned char* output,
                     long length, DES_key_schedule* schedule, DES_cblock* ivec,
                     int enc)
    {
        Des des;
        Des_SetKey(&des, (const byte*)schedule, (const byte*)ivec, !enc);

        if (enc)
            Des_CbcEncrypt(&des, output, input, length);
        else
            Des_CbcDecrypt(&des, output, input, length);

        memcpy(ivec, output + length - sizeof(DES_cblock), sizeof(DES_cblock));
    }


    #ifndef NO_CYASSL_SERVER

        void SSL_set_accept_state(SSL* ssl)
        {
            ssl->options.side = SERVER_END;
        }

        #ifdef NO_TLS

            SSL_METHOD *SSLv23_server_method(void)
            {
                SSL_METHOD* method = (SSL_METHOD*) malloc(sizeof(SSL_METHOD));
                if (method) {
                    InitSSL_Method(method, MakeSSLv3());
                    method->side = SERVER_END;
                }
                return method;
            }

        #endif /* NO_TLS */

    #endif /* NO_CYASSL_SERVER */


    long SSL_CTX_set_options(SSL_CTX* ctx, long opt)
    {
        /* TDOD: */
        return SSL_SUCCESS;
    }


    int SSL_CTX_check_private_key(SSL_CTX* ctx)
    {
        /* TODO: check private against public for RSA match */
        return SSL_NOT_IMPLEMENTED;
    }


    void SSL_set_shutdown(SSL* ssl, int opt)
    {
        /* TODO: */
    }


    void ERR_free_strings(void)
    {
        /* handled internally */
    }


    void ERR_remove_state(unsigned long state)
    {
        /* TODO: GetErrors().Remove(); */
    }


    void EVP_cleanup(void)
    {
        /* nothing to do here */
    }


    void CRYPTO_cleanup_all_ex_data(void)
    {
        /* nothing to do here */
    }


    long SSL_CTX_set_mode(SSL_CTX* ctx, long mode)
    {
        /* TODO: */
        return mode;
    }


    long SSL_CTX_get_mode(SSL_CTX* ctx)
    {
        /* TODO: */
        return 0;
    }


    void SSL_CTX_set_default_read_ahead(SSL_CTX* ctx, int m)
    {
        /* TODO: maybe? */
    }


#endif /* OPENSSL_EXTRA */

