/* echoserver.cpp */

#include "../../testsuite/test.hpp"


#ifndef NO_MAIN_DRIVER
    #define ECHO_OUT

    THREAD_RETURN YASSL_API echoserver_test(void*);
    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;

        echoserver_test(&args);
        return args.return_code;
    }

#endif // NO_MAIN_DRIVER


THREAD_RETURN YASSL_API echoserver_test(void* args)
{
#ifdef WIN32
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

    SOCKET_T sockfd = 0;
    int      argc = 0;
    char**   argv = 0;

    set_args(argc, argv, *static_cast<func_args*>(args));

#ifdef ECHO_OUT
    FILE* fout = stdout;
    if (argc >= 2) fout = fopen(argv[1], "w");
    if (!fout) err_sys("can't open output file");
#endif

    tcp_listen(sockfd);

    SSL_METHOD* method = TLSv1_server_method();
    SSL_CTX*    ctx    = SSL_CTX_new(method);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
    set_serverCerts(ctx);

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
                printf("client sent quit command: shutting down!\n");
                shutdown = true;
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
    }

#ifdef WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    SSL_CTX_free(ctx);

    ((func_args*)args)->return_code = 0;
    return 0;
}
