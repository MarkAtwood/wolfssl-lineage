/* ssl.cpp                                
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

/*  SSL source implements all openssl compatibility API functions
 *
 *  TODO: notes are mostly api additions to allow compilation with mysql
 *  they don't affect normal RSA mode but need to be completed
 */


#include "openssl/ssl.h"
#include "handshake.hpp"
#include <fstream>



SSL* SSL_new(SSL_CTX* ctx)
{
    try {
        return new SSL(ctx);
    }
    catch (...) {
        return 0;
    }
}


int SSL_set_fd(SSL* ssl, int fd)
{
    ssl->set_socket().set_fd(fd);
    return SSL_SUCCESS;
}


int SSL_connect(SSL* ssl)
{
    try {
        sendClientHello(*ssl);
        processReply(*ssl);

        sendClientKeyExchange(*ssl);
        sendChangeCipher(*ssl);
        sendFinished(*ssl, client_end);
        ssl->flushBuffer();
        processReply(*ssl);

        return SSL_SUCCESS;
    }
    catch (Error& err) {
       ssl->set_error(err);
       return SSL_FATAL_ERROR;
    }
    catch (...) {
        return SSL_UNKNOWN;
    }
}


int SSL_write(SSL* ssl, const void* buffer, int sz)
{
    try {
        const Data data(sz, static_cast<const opaque*>(buffer));
        return sendData(*ssl, data);
    }
    catch (Error& err) {
        ssl->set_error(err);
        return SSL_FATAL_ERROR;
    }
    catch (...) {
        return SSL_UNKNOWN;
    }
}


int SSL_read(SSL* ssl, void* buffer, int sz)
{
    try {
       Data data(sz, static_cast<opaque*>(buffer));
       return receiveData(*ssl, data);
    }
    catch (Error& err) {
        ssl->set_error(err);
        return SSL_FATAL_ERROR;
    }
    catch (...) {
        return SSL_UNKNOWN;
    }
}


int SSL_accept(SSL* ssl)
{
    try {
        processReply(*ssl);
        sendServerHello(*ssl);
        sendCertificate(*ssl);
        sendServerHelloDone(*ssl);
        ssl->flushBuffer();

        processReply(*ssl);
        sendChangeCipher(*ssl);
        sendFinished(*ssl, server_end);
        ssl->flushBuffer();

        return SSL_SUCCESS;
    }
    catch (Error& err) {
        ssl->set_error(err);
        return SSL_FATAL_ERROR;
    }
    catch (...) {
        return SSL_UNKNOWN;
    }
}


int SSL_do_handshake(SSL* ssl)
{
    if (ssl->get_security().entity_ == client_end)
        return SSL_connect(ssl);
    else
        return SSL_accept(ssl);
}


void SSL_free(SSL* ssl)
{
    delete ssl;
}


int SSL_clear(SSL* ssl)
{
    // TODO: reset
    ssl->set_socket().closeSocket();
    return SSL_SUCCESS;
}


int SSL_shutdown(SSL* ssl)
{
    // TODO: send close_notify see if receive one back, reset
    ssl->set_socket().closeSocket();
    return SSL_SUCCESS;
}


SSL_SESSION* SSL_get_session(SSL* ssl)
{
    SSL_SESSION session(ssl);
    return session.session_;
}


long SSL_SESSION_set_timeout(SSL_SESSION*, long)
{
    return SSL_NOT_IMPLEMENTED;  // TODO:
}


long SSL_CTX_get_session_cache_mode(SSL_CTX*)
{
    return SSL_NOT_IMPLEMENTED;  // TODO:
}


long SSL_get_default_timeout(SSL* ssl)
{
    return SSL_NOT_IMPLEMENTED;  // TODO:
}


const char* SSL_get_cipher_name(SSL* ssl)
{ 
    return SSL_get_cipher(ssl); 
}


const char* SSL_get_cipher(SSL* ssl)
{
    return ssl->get_security().cipher_name_;
}


char* SSL_get_shared_ciphers(SSL* ssl, char* buf, int len)
{
    return strncpy(buf, "Not Implemented, SSLv2 only", len);
}


const char* SSL_get_cipher_list(SSL* /* ssl */, int /* priority */)
{
    return 0;  // TODO:
}



const char* SSL_get_version(SSL*)
{
    static const char* version = "SSLv3";
    return version;
}


int SSL_get_error(SSL* ssl, int previous)
{
    return ssl->get_states().errorNumber_;
}


X509* SSL_get_peer_certificate(SSL* ssl)
{
    // TODO: return peer cert from manager in X509
    return 0;
}


void X509_free(X509* x)
{
    delete x;
}


X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX* ctx)
{
    return ctx->current_cert;
}


int X509_STORE_CTX_get_error(X509_STORE_CTX* ctx)
{
    return ctx->error;
}


int X509_STORE_CTX_get_error_depth(X509_STORE_CTX* ctx)
{
    // TODO: add depth
    return 0;
}


char* X509_NAME_oneline(X509_NAME* name, char* buffer, int sz)
{
    // TODO: return first line in buffer of size sz, may need to creat
    // !!!  malloc or new, caller responsible for freeing???
    return buffer;
}


X509_NAME* X509_get_issuer_name(X509*)
{
    // TODO: return issue name in X509_NAME format
    return 0;
}


X509_NAME* X509_get_subject_name(X509*)
{
    // TODO: return subject name in X509_NAME format
    return 0;
}


void SSL_load_error_strings(void)   // compatibility only 
{
}


SSL_METHOD *SSLv3_method(void)
{
    return new SSL_METHOD;
}


SSL_METHOD *SSLv3_server_method(void)
{
    return new SSL_METHOD(server_end);
}


SSL_METHOD *SSLv3_client_method(void)
{
    return new SSL_METHOD;
}


SSL_METHOD *TLSv1_server_method(void)
{
    // TODO: undo rollback support
    return new SSL_METHOD(server_end);
}


SSL_METHOD *TLSv1_client_method(void)
{
    // TODO: undo rollback support
    return new SSL_METHOD;
}


void SSL_set_connect_state(SSL*)
{
    // already a client by default
}


void SSL_set_accept_state(SSL* ssl)
{
    ssl->set_security().entity_ = server_end;
}

long SSL_get_verify_result(SSL*)
{
    // TODO: verify if peer checked
    return X509_V_OK;
}


int SSL_session_reused(SSL*)
{
    return 0;  // no re-use for now TODO:
}


SSL_CTX* SSL_CTX_new(SSL_METHOD* method)
{
    return new SSL_CTX(method);
}


void SSL_CTX_free(SSL_CTX* ctx)
{
    delete ctx;
}


long SSL_CTX_sess_set_cache_size(SSL_CTX* ctx, long sz)
{
    // not implemented yet TODO:
    return SSL_NOT_IMPLEMENTED;
}


long SSL_CTX_set_tmp_dh(SSL_CTX*, DH*)
{
    // not implemented yet TODO:
    return SSL_NOT_IMPLEMENTED;
}


int read_file(SSL_CTX* ctx, const char* file, int format, CertType type)
{
    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM)
        return SSL_BAD_FILETYPE;

    std::ifstream input(file, std::ios::in | std::ios::binary | std::ios::ate);
    if (!input.is_open())
        return SSL_BAD_FILE;

    x509*& x = (type == Cert) ? ctx->certificate_ : ctx->privateKey_;
    
    if (format == SSL_FILETYPE_ASN1) {
        size_t sz = input.tellg();
        input.seekg(0, std::ios::beg);    
        x = new x509(sz);  // takes ownership
        input.read(reinterpret_cast<char*>(x->set_buffer()), sz);
    }
    else
        x = PemToDer(file, type);

    return SSL_SUCCESS;
}


int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int format)
{
    return read_file(ctx, file, format, Cert);
}


int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int format)
{
    return read_file(ctx, file, format, PrivateKey);
}


int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* list)
{
    return SSL_SUCCESS; 
}


void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, VerifyCallback verify_callback)
{
    // TODO: set client verify to mode
}


int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* file,
                                  const char* path)
{
    // TODO: load CA file from path, PEM base64, could be chain
    return SSL_NOT_IMPLEMENTED;
}


int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx)
{
    // TODO: figure out?, implement
    return SSL_NOT_IMPLEMENTED;
}


int  SSL_CTX_set_session_id_context(SSL_CTX*, const unsigned char*,
                                    unsigned int)
{
    // TODO: create and store session id for reuse and verify
    return SSL_NOT_IMPLEMENTED;
}


int  SSL_CTX_check_private_key(SSL_CTX* ctx)
{
    // TODO: check private against public for RSA match
    return SSL_NOT_IMPLEMENTED;
}


// TODO: all session stats
long SSL_CTX_sess_accept(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_connect(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_accept_good(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_connect_good(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_accept_renegotiate(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_connect_renegotiate(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_hits(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_cb_hits(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_cache_full(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_misses(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_timeouts(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_number(SSL_CTX*)
{
    return 0;  // TODO:
}


long SSL_CTX_sess_get_cache_size(SSL_CTX*)
{
    return 0;  // TODO:
}
// end session stats TODO:


int SSL_CTX_get_verify_mode(SSL_CTX*)
{
    return 0;  // TODO:
}


int SSL_get_verify_mode(SSL*)
{
    return 0;  // TODO:
}


int SSL_CTX_get_verify_depth(SSL_CTX*)
{
    return 0;  // TODO:
}


int SSL_get_verify_depth(SSL*)
{
    return 0;  // TODO:
}


void OpenSSL_add_all_algorithms(void)  // compatibility only
{
}


DH* DH_new(void)
{
    DH* dh = new DH;
    dh->p = dh->g = 0;
    return dh;
}


void DH_free(DH* dh)
{
    delete dh->g;
    delete dh->p;
    delete dh;
}


// convert positive big-endian num of length sz into retVal, which may need to 
// be created
BIGNUM* BN_bin2bn(const unsigned char* num, int sz, BIGNUM* retVal)
{
    using std::auto_ptr;
    bool created = false;
    auto_ptr<BIGNUM> bn;

    if (!retVal) {
        created = true;
        bn = auto_ptr<BIGNUM>(new BIGNUM);
        retVal = bn.get();
    }

    retVal->assign(num, sz);

    if (created)
        return bn.release();
    else
        return retVal;
}


unsigned long ERR_get_error_line_data(const char**, int*, const char**, int *)
{
    //return SSL_NOT_IMPLEMENTED;
    return 0;
}


void ERR_print_errors_fp(FILE* fp)
{
    // need ssl access to implement TODO:
    //fprintf(fp, "%s", ssl.get_states().errorString_.c_str());
}


char* ERR_error_string(unsigned long err, char* buffer)
{
    // TODO:
    static char* msg = "Not Implemented";
    if (buffer)
        return strncpy(buffer, msg, strlen(msg));

    return msg;
}


const char* X509_verify_cert_error_string(long /* error */)
{
    // TODO:
    static const char* msg = "Not Implemented";
    return msg;
}


const EVP_MD* EVP_md5(void)
{
    // TODO: fix this impl
    // return new MD5;
    return 0;
}


const EVP_CIPHER* EVP_des_ede3_cbc(void)
{
    // TODO: fix this impl
    // return new DES_EDE;
    return 0;
}


int EVP_BytesToKey(const EVP_CIPHER* type, const EVP_MD* md, const byte* salt,
                   const byte* data, int sz, int count, byte* key, byte* iv)
{
    // TODO: create key and iv from possible salt, and data using type and md
    return SSL_NOT_IMPLEMENTED;
}



void DES_set_key_unchecked(const_DES_cblock* key, DES_key_schedule* schedule)
{
    // TODO: create schedule from key without checking strength
}


void DES_ede3_cbc_encrypt(const byte* input, byte* output, long length,
                          DES_key_schedule* ks1, DES_key_schedule* ks2,
                          DES_key_schedule* ks3, DES_cblock* ivec, int enc)
{
    // TODO: cipher input into output with keys and IV
}
