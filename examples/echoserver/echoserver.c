/* echoserver.c */

#include "openssl/ssl.h"
#include "../test.h"

#define ECHO_OUT

int main(int argc, char** argv)
{
    SOCKET_T    sockfd = 0;
    SSL_METHOD* method = 0;
    SSL_CTX*    ctx    = 0;

    int   shutdown = 0;
    FILE* fout;

#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif


#ifdef ECHO_OUT
    fout = stdout;
    if (argc >= 2) fout = fopen(argv[1], "w");
    if (!fout) err_sys("can't open output file");
#endif

    tcp_listen(&sockfd);

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

#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER)
    /* signal ready to tcp_accept */
    func_args& server_args = *((func_args*)args);
    tcp_ready& ready = *server_args.signal_;
    pthread_mutex_lock(&ready.mutex_);
    ready.ready_ = true;
    pthread_cond_signal(&ready.cond_);
    pthread_mutex_unlock(&ready.mutex_);
#endif

    while (!shutdown) {
        SSL* ssl = 0;
        char command[1024];
        int  echoSz = 0;

        struct sockaddr_in client;
        socklen_t   client_len = sizeof(client);
        int         clientfd   = accept(sockfd, (struct sockaddr*)&client,
                                        (ACCEPT_THIRD_T)&client_len);
        if (clientfd == -1) err_sys("tcp accept failed");

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientfd);
        if (SSL_accept(ssl) != SSL_SUCCESS) err_sys("SSL_accept failed");

        while ( (echoSz = SSL_read(ssl, command, sizeof(command))) > 0) {
           
            if ( strncmp(command, "quit", 4) == 0) {
                printf("client sent quit command: shutting down!\n");
                shutdown = 1;
                break;
            }
            else if ( strncmp(command, "GET", 3) == 0) {
                char type[]   = "HTTP/1.0 200 ok\r\nContent-type:"
                                " text/html\r\n\r\n";
                char header[] = "<html><body BGCOLOR=\"#ffffff\">\n<pre>\n";
                char body[]   = "greetings from yaSSL\n";
                char footer[] = "</body></html>\r\n\r\n";
            
                strncpy(command, type, sizeof(type));
                echoSz = sizeof(type) - 1;

                strncpy(&command[echoSz], header, sizeof(header));
                echoSz += sizeof(header) - 1;
                strncpy(&command[echoSz], body, sizeof(body));
                echoSz += sizeof(body) - 1;
                strncpy(&command[echoSz], footer, sizeof(footer));
                echoSz += sizeof(footer);

                if (SSL_write(ssl, command, echoSz) != echoSz)
                    err_sys("SSL_write failed");
                break;
            }
            command[echoSz] = 0;

        #ifdef ECHO_OUT
            fputs(command, fout);
        #endif

            if (SSL_write(ssl, command, echoSz) != echoSz)
                err_sys("SSL_write failed");
        }
        SSL_free(ssl);
        #ifdef _WIN32
            closesocket(clientfd);
        #else
            close(clientfd);
        #endif
    }

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    SSL_CTX_free(ctx);
    FreeCyaSSL();

    return 0;
}

