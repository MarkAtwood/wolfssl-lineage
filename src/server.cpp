/* server.cpp */

#include "openssl/ssl.h"   /* openssl compatibility test */
#include <stdio.h>

#ifdef WIN32
    #include <winsock2.h>
	typedef int socklen_t;
#else
    #include <string.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
#endif /* WIN32 */




int main(int argc, char** argv)
{
    SSL_METHOD* method = TLSv1_server_method();
    SSL_CTX*    ctx = SSL_CTX_new(method);

    SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/key.der", SSL_FILETYPE_ASN1);

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

    addr.sin_port = htons(11111);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int ret = bind(sockfd, (const sockaddr*)&addr, sizeof(addr));
    ret = listen(sockfd, 3);

    sockaddr_in client;
    socklen_t client_len = sizeof(client);
    int clientfd = accept(sockfd, (sockaddr*)&client, &client_len);

#ifdef WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    SSL* ssl = SSL_new(ctx);
    ret = SSL_set_fd(ssl, clientfd);
    ret = SSL_accept(ssl);

    printf("Using Cipher Suite %s\n", SSL_get_cipher(ssl));

    char command[1024];
    ret = SSL_read(ssl, command, sizeof(command));
    command[ret] = 0;

    printf("First client command: %s\n", command);

    char msg[] = "I hear you, fa shizzle!";
    ret = SSL_write(ssl, msg, sizeof(msg));

#ifdef WIN32
    closesocket(clientfd);
#else
    close(clientfd);
#endif
    SSL_CTX_free(ctx);
    SSL_free(ssl);

    return 0;
}
