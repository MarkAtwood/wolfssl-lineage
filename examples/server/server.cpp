/* server.cpp */

#include "openssl/ssl.h"   /* openssl compatibility test */
#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
    #include <winsock2.h>
	typedef int socklen_t;
#else
    #include <string.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
#endif /* WIN32 */


void err_sys(const char* msg)
{
    printf("yassl server error: %s\n", msg);
    exit(EXIT_FAILURE);
}

const char* loopback  = "127.0.0.1";
const short yasslPort = 11111; 

const char* cert = "../../certs/cert.der";
const char* key  = "../../certs/key.der";

int main(int argc, char** argv)
{
    SSL_METHOD* method = TLSv1_server_method();
    SSL_CTX*    ctx = SSL_CTX_new(method);

    if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_ASN1)
         != SSL_SUCCESS) err_sys("failed to use certificate: certs/cert.der");

    if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_ASN1)
         != SSL_SUCCESS) err_sys("failed to use key file: certs/key.der");

#ifdef WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
    int sockfd;
#else
    unsigned int sockfd;
#endif // WIN32

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    addr.sin_port = htons(yasslPort);
    if (argc == 2)
        addr.sin_addr.s_addr = inet_addr(argv[1]);
    else
        addr.sin_addr.s_addr = inet_addr(loopback);
    if ( bind(sockfd, (const sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
    if ( listen(sockfd, 3) != 0) err_sys("tcp listen failed");

    sockaddr_in client;
    socklen_t client_len = sizeof(client);
    int clientfd = accept(sockfd, (sockaddr*)&client, &client_len);
    if (clientfd == -1) err_sys("tcp accept failed");

#ifdef WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);
    if ( SSL_accept(ssl) != SSL_SUCCESS) err_sys("SSL_accept failed");

    printf("Using Cipher Suite %s\n", SSL_get_cipher(ssl));

    char command[1024];
    command[SSL_read(ssl, command, sizeof(command))] = 0;
    printf("First client command: %s\n", command);

    char msg[] = "I hear you, fa shizzle!";
    if ( SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed"); 

#ifdef WIN32
    closesocket(clientfd);
#else
    close(clientfd);
#endif
    SSL_CTX_free(ctx);
    SSL_free(ssl);

    return 0;
}
