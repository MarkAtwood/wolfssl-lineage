/* client.cpp  */

#include "openssl/ssl.h"  /* openssl compatibility test */
#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
    #include <winsock2.h>
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
    printf("yassl client error: %s\n", msg);
    exit(EXIT_FAILURE);
}


const char* loopback  = "127.0.0.1";
const short yasslPort = 11111;


int main(int argc, char** argv)
{
    SSL_METHOD* method = TLSv1_client_method();
    SSL_CTX*    ctx = SSL_CTX_new(method);

#ifdef WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
    int sockfd;
#else
    unsigned int sockfd;
#endif /* WIN32  */

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;

    servaddr.sin_port = htons(yasslPort);
    if (argc == 2)
        servaddr.sin_addr.s_addr = inet_addr(argv[1]);
    else
        servaddr.sin_addr.s_addr = inet_addr(loopback);
    if ( connect(sockfd, (const sockaddr*)&servaddr, sizeof(servaddr)) != 0)
        err_sys("tcp connect failed");

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if ( SSL_connect(ssl) != SSL_SUCCESS) err_sys("SSL_connect failed");

    char msg[] = "hello yassl!";
    if ( SSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
        err_sys("SSL_write failed");

    char reply[1024];
    reply[SSL_read(ssl, reply, sizeof(reply))] = 0;
    printf("Server response: %s\n", reply);

#ifdef WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif 
    SSL_CTX_free(ctx);
    SSL_free(ssl);

    return 0;
}
