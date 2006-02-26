/* server.c */

#include "openssl/ssl.h"
#include "../test.h"



int main(int argc, char** argv)
{
    SOCKET_T sockfd   = 0;
    int      clientfd = 0;

    SSL_METHOD* method = 0;
    SSL_CTX*    ctx    = 0;
    SSL*        ssl    = 0;

    char msg[] = "I hear you fa shizzle!";
    char input[1024];

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

    InitCyaSSL();
    method = SSLv3_server_method();
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
    tcp_accept(&sockfd, &clientfd);

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    SSL_set_fd(ssl, clientfd);

    if (SSL_accept(ssl) != SSL_SUCCESS)
        err_sys("SSL_accept failed");

    input[SSL_read(ssl, input, sizeof(input))] = 0;
    printf("Client message: %s\n", input);

    if (SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    SSL_shutdown(ssl);
    SSL_CTX_free(ctx);
    SSL_free(ssl);

#ifdef _WIN32
    closesocket(clientfd);
#else
    close(clientfd);
#endif

    FreeCyaSSL();
    return 0;
}
