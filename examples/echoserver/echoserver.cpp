/* echoserver.cpp */

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
    fputs("yassl server error: ", stderr);
    fputs(msg, stderr);
    exit(EXIT_FAILURE);
}

const char* loopback  = "127.0.0.1";
const short yasslPort = 11111; 

const char* cert = "../../certs/cert.der";
const char* key  = "../../certs/key.der";

using namespace yaSSL;


int main(int argc, char** argv)
{
#ifdef WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
    int sockfd;
#else
    unsigned int sockfd;
#endif // WIN32

    FILE* fout = stdout;

    if (argc >= 2) fout = fopen(argv[1], "w");

    if (!fout) err_sys("can't open output file");

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    addr.sin_port = htons(yasslPort);
    addr.sin_addr.s_addr = inet_addr(loopback);

    if (bind(sockfd, (const sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
    if (listen(sockfd, 3) != 0) err_sys("tcp listen failed");

    SSL_METHOD* method = TLSv1_server_method();
    SSL_CTX*    ctx = SSL_CTX_new(method);

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_ASN1)
         != SSL_SUCCESS) err_sys("failed to use certificate: certs/cert.der");

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_ASN1)
         != SSL_SUCCESS) err_sys("failed to use key file: certs/key.der");

    bool shutdown(false);
    while (!shutdown) {
        sockaddr_in client;
        socklen_t   client_len = sizeof(client);
        int         clientfd = accept(sockfd, (sockaddr*)&client, &client_len);
        if (clientfd == -1) err_sys("tcp accept failed");

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientfd);
        if (SSL_accept(ssl) != SSL_SUCCESS) err_sys("SSL_accept failed");

        char command[1024];
        int echoSz(0);
        while ( (echoSz = SSL_read(ssl, command, sizeof(command))) > 0) {
           
            if ( strncmp(command, "quit", 4) == 0) {
                printf("client sent quit command: shutting down!");
                shutdown = true;
                break;
            }

            command[echoSz] = 0;
            fputs(command, fout);

            if (SSL_write(ssl, command, echoSz) != echoSz)
                err_sys("SSL_write failed");
        }

        SSL_free(ssl);
    }

#ifdef WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    SSL_CTX_free(ctx);

    return 0;
}
