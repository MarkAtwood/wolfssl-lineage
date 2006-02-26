/* client.c */

#include "openssl/ssl.h"
#include "../test.h"

/* #define TEST_RESUME */


int main(int argc, char** argv)
{
    SOCKET_T sockfd = 0;

    SSL_METHOD*  method  = 0;
    SSL_CTX*     ctx     = 0;
    SSL*         ssl     = 0, *sslResume = 0;
    SSL_SESSION* session = 0;

    char msg[] = "hello cyassl!";
    char reply[1024];

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

    InitCyaSSL();
    method  = SSLv3_client_method();
    ctx     = SSL_CTX_new(method);
    
    if (SSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
        err_sys("can't load ca file");

    ssl = SSL_new(ctx);
    tcp_connect(&sockfd);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) != SSL_SUCCESS)
        err_sys("SSL_connect failed");

    if (SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    reply[SSL_read(ssl, reply, sizeof(reply))] = 0;
    printf("Server response: %s\n", reply);

#ifdef TEST_RESUME
    session   = SSL_get_session(ssl);
    sslResume = SSL_new(ctx);
#endif

    SSL_shutdown(ssl);
    SSL_free(ssl);

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif


#ifdef TEST_RESUME
    tcp_connect(&sockfd);
    SSL_set_fd(sslResume, sockfd);
    SSL_set_session(sslResume, session);
    
    if (SSL_connect(sslResume) != SSL_SUCCESS) err_sys("SSL resume failed");
  
    if (SSL_write(sslResume, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    reply[SSL_read(sslResume, reply, sizeof(reply))] = 0;
    printf("Server response: %s\n", reply);

    SSL_shutdown(sslResume);
    SSL_free(sslResume);
#endif /* TEST_RESUME */

    SSL_CTX_free(ctx);

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    FreeCyaSSL();
    return 0;
}
