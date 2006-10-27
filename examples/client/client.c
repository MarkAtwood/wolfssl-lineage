/* client.c */

#include "openssl/ssl.h"
#include "../test.h"


/*
#define TEST_RESUME 
*/

#ifdef NON_BLOCKING
    void NonBlockingSSL_Connect(SSL* ssl)
    {
        int ret = SSL_connect(ssl);
        while (ret != SSL_SUCCESS && SSL_get_error(ssl, 0) ==
                                     SSL_ERROR_WANT_READ) {
            printf("... client would block\n");
            #ifdef _WIN32
                Sleep(1000);
            #else
                sleep(1);
            #endif
            ret = SSL_connect(ssl);
        }
        if (ret != SSL_SUCCESS)
            err_sys("SSL_connect failed");
    }
#endif


void client_test(void* args)
{
    SOCKET_T sockfd = 0;

    SSL_METHOD*  method  = 0;
    SSL_CTX*     ctx     = 0;
    SSL*         ssl     = 0, *sslResume = 0;
    SSL_SESSION* session = 0;

    char msg[] = "hello cyassl!";
    char reply[1024];
    int  input;

    ((func_args*)args)->return_code = -1; /* error state */
#ifndef NO_TLS
    method  = TLSv1_client_method();
#else
    method  = SSLv3_client_method();
#endif
    ctx     = SSL_CTX_new(method);
    
    if (SSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
        err_sys("can't load ca file");

    ssl = SSL_new(ctx);
    tcp_connect(&sockfd);
    SSL_set_fd(ssl, sockfd);

#ifdef NON_BLOCKING
    tcp_set_nonblocking(&sockfd);
    NonBlockingSSL_Connect(ssl);
#else
    if (SSL_connect(ssl) != SSL_SUCCESS)
        err_sys("SSL_connect failed");
#endif

    if (SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    input = SSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
        reply[input] = 0;
        printf("Server response: %s\n", reply);
    }
   
#ifdef TEST_RESUME
    session   = SSL_get_session(ssl);
    sslResume = SSL_new(ctx);
#endif

    SSL_shutdown(ssl);
    SSL_free(ssl);
    CloseSocket(sockfd);

#ifdef TEST_RESUME
    tcp_connect(&sockfd);
    SSL_set_fd(sslResume, sockfd);
    SSL_set_session(sslResume, session);
    
    if (SSL_connect(sslResume) != SSL_SUCCESS) err_sys("SSL resume failed");
  
    if (SSL_write(sslResume, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    input = SSL_read(sslResume, reply, sizeof(reply));
    if (input > 0) {
        reply[input] = 0;
        printf("Server response: %s\n", reply);
    }

    SSL_shutdown(sslResume);
    SSL_free(sslResume);
#endif /* TEST_RESUME */

    SSL_CTX_free(ctx);
    CloseSocket(sockfd);

    ((func_args*)args)->return_code = 0;
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
        client_test(&args);
        FreeCyaSSL();

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */

