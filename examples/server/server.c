/* server.c */

#include "openssl/ssl.h"
#include "../test.h"


#ifdef NON_BLOCKING
    void NonBlockingSSL_Accept(SSL* ssl)
    {
        int ret = SSL_accept(ssl);
        while (ret != SSL_SUCCESS && SSL_get_error(ssl, 0) ==
                                     SSL_ERROR_WANT_READ) {
            printf("... server would block\n");
            #ifdef _WIN32
                Sleep(1000);
            #else
                sleep(1);
            #endif
            ret = SSL_accept(ssl);
        }
        if (ret != SSL_SUCCESS)
            err_sys("SSL_accept failed");
    }
#endif


THREAD_RETURN CYASSL_API server_test(void* args)
{
    SOCKET_T sockfd   = 0;
    int      clientfd = 0;

    SSL_METHOD* method = 0;
    SSL_CTX*    ctx    = 0;
    SSL*        ssl    = 0;

    char msg[] = "I hear you fa shizzle!";
    char input[1024];
    int  idx;
   
    ((func_args*)args)->return_code = -1; /* error state */
#ifndef NO_TLS
    method = TLSv1_server_method();
#else
    method = SSLv3_server_method();
#endif
    ctx    = SSL_CTX_new(method);

    if (SSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
        err_sys("can't load ca file");

    if (SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
        err_sys("can't load server cert file");

    if (SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
        err_sys("can't load server key file");

    ssl = SSL_new(ctx);
    tcp_accept(&sockfd, &clientfd, (func_args*)args);
    CloseSocket(sockfd);

    SSL_set_fd(ssl, clientfd);

#ifdef NON_BLOCKING
    tcp_set_nonblocking(&clientfd);
    NonBlockingSSL_Accept(ssl);
#else
    if (SSL_accept(ssl) != SSL_SUCCESS)
        err_sys("SSL_accept failed");
#endif

    idx = SSL_read(ssl, input, sizeof(input));
    if (idx > 0) {
        input[idx] = 0;
        printf("Client message: %s\n", input);
    }
    
    if (SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    
    CloseSocket(clientfd);
    ((func_args*)args)->return_code = 0;
    return 0;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        StartTCP();

        args.argc = argc;
        args.argv = argv;

        InitCyaSSL();
        server_test(&args);
        FreeCyaSSL();

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */



