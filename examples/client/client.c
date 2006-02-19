/* client.c */

#include "openssl/ssl.h"
#include "../test.h"


const char* caCert = "../../certs/ca-cert.pem";

int main(int argc, char** argv)
{
    SOCKET_T sockfd = 0;

    SSL_METHOD* method = SSLv3_client_method();
    SSL_CTX*    ctx = SSL_CTX_new(method);
    SSL*        ssl = 0;

    char msg[] = "hello cyassl!";
    char reply[1024];

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

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

    SSL_shutdown(ssl);
    SSL_CTX_free(ctx);
    SSL_free(ssl);

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    return 0;
}
