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
#include <stdlib.h>


#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */



SSL_METHOD* SSLv3_client_method()
{
    SSL_METHOD* method = (SSL_METHOD*) malloc(sizeof(SSL_METHOD));
    if (method)
        InitSSL_Method(method, MakeSSLv3());
    return method;
}


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
    ctx = 0;
}


SSL* SSL_new(SSL_CTX* ctx)
{
    SSL* ssl = (SSL*) malloc(sizeof(SSL));
    if (ssl)
        InitSSL(ssl, ctx);
    return ssl;
}


void SSL_free(SSL* ssl)
{
    FreeSSL(ssl);
    ssl = 0;
}


int SSL_set_fd(SSL* ssl, int fd)
{
    ssl->socket = fd;
    return SSL_SUCCESS;
}


int SSL_connect(SSL* ssl)
{
    /* always send client hello first */
    if (SendClientHello(ssl) != 0)
        return SSL_FATAL_ERROR;

    /* get response */
    while (ssl->serverState < SERVER_HELLODONE_COMPLETE)
        if (ProcessReply(ssl) < 0)
            return SSL_FATAL_ERROR;

    if (SendClientKeyExchange(ssl) != 0)
        return SSL_FATAL_ERROR;

    if (SendChangeCipher(ssl) != 0)
        return SSL_FATAL_ERROR;

    if (SendFinished(ssl) != 0)
        return SSL_FATAL_ERROR;

    /* get response */
    while (ssl->serverState < SERVER_FINISHED_COMPLETE)
        if (ProcessReply(ssl) < 0)
            return SSL_FATAL_ERROR;
          
    return SSL_SUCCESS;
}


int SSL_write(SSL* ssl, const void* buffer, int sz)
{
    return SendData(ssl, buffer, sz);
}


int SSL_read(SSL* ssl, void* buffer, int sz)
{
    return ReceiveData(ssl, buffer, min(sz, MAX_RECORD_SIZE));
}


int SSL_shutdown(SSL* ssl)
{
    /* try to send alert, not an error if can't */
    SendAlert(ssl, alert_warning, close_notify);

    return SSL_SUCCESS;
}


/* just one for now TODO: add dir support from path */
int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* file,
                                  const char* path)
{
    return read_file(ctx, file, SSL_FILETYPE_PEM, CA_TYPE);
}


