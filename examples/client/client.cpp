/* client.cpp  */

#include "openssl/ssl.h"  /* openssl compatibility test */
#include <stdio.h>

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

    servaddr.sin_port = htons(11111);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int ret = connect(sockfd, (const sockaddr*)&servaddr, sizeof(servaddr));

    SSL* ssl = SSL_new(ctx);
    ret = SSL_set_fd(ssl, sockfd);
    ret = SSL_connect(ssl);

    char msg[] = "hello yassl!";
    ret = SSL_write(ssl, msg, sizeof(msg));

    char reply[1024];
    ret = SSL_read(ssl, reply, sizeof(reply));
    reply[ret] = 0;

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
