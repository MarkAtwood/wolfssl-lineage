// test.hpp

#ifndef yaSSL_TEST_HPP
#define yaSSL_TEST_HPP

#include "openssl/ssl.h"   /* openssl compatibility test */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef WIN32
    #include <winsock2.h>
    #include <process.h>
    #define SOCKET_T int
#else
    #include <string.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #define SOCKET_T unsigned int
#endif /* WIN32 */


#if defined(__MACH__) || defined(WIN32)
    typedef int socklen_t;
#endif


#ifdef _WIN32
    typedef unsigned int  THREAD_RETURN;
    typedef unsigned long THREAD_TYPE;
    #define YASSL_API __stdcall
#else
    typedef void*         THREAD_RETURN;
    typedef pthread_t     THREAD_TYPE;
    #define YASSL_API 
#endif


struct func_args {
    int    argc;
    char** argv;
    int    return_code;

    func_args(int c = 0, char** v = 0) : argc(c), argv(v) {}
};

typedef THREAD_RETURN YASSL_API THREAD_FUNC(void*);

void start_thread(THREAD_FUNC, func_args*, THREAD_TYPE*);
void join_thread(THREAD_TYPE);

const char* const loopback  = "127.0.0.1";
const short yasslPort = 11111; 


// client
const char* const cert = "../../certs/client-cert.pem";
const char* const key  = "../../certs/client-key.pem";

const char* const certSuite = "../certs/client-cert.pem";
const char* const keySuite  = "../certs/client-key.pem";

const char* const certDebug = "../../../certs/client-cert.pem";
const char* const keyDebug  = "../../../certs/client-key.pem";


// server
const char* const svrCert = "../../certs/server-cert.pem";
const char* const svrKey  = "../../certs/server-key.pem";

const char* const svrCert2 = "../certs/server-cert.pem";
const char* const svrKey2  = "../certs/server-key.pem";

const char* const svrCert3 = "../../../certs/server-cert.pem";
const char* const svrKey3  = "../../../certs/server-key.pem";


// CA 
const char* const caCert  = "../../certs/ca-cert.pem";
const char* const caCert2 = "../certs/ca-cert.pem";
const char* const caCert3 = "../../../certs/ca-cert.pem";


using namespace yaSSL;


inline void err_sys(const char* msg)
{
    printf("yassl server error: %s\n", msg);
    exit(EXIT_FAILURE);
}


inline void store_ca(SSL_CTX* ctx)
{
    // To allow testing from serveral dirs
    if (SSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
        if (SSL_CTX_load_verify_locations(ctx, caCert2, 0) != SSL_SUCCESS)
            if (SSL_CTX_load_verify_locations(ctx, caCert3, 0) != SSL_SUCCESS)
                err_sys("failed to use certificate: certs/cacert.pem");
}


// client
inline void set_certs(SSL_CTX* ctx)
{
    store_ca(ctx);

    // To allow testing from serveral dirs
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM)
        != SSL_SUCCESS)
        if (SSL_CTX_use_certificate_file(ctx, certSuite, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
            if (SSL_CTX_use_certificate_file(ctx, certDebug, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
                err_sys("failed to use certificate: certs/client-cert.pem");
    
    // To allow testing from several dirs
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)
         != SSL_SUCCESS) 
         if (SSL_CTX_use_PrivateKey_file(ctx, keySuite, SSL_FILETYPE_PEM)
            != SSL_SUCCESS) 
                if (SSL_CTX_use_PrivateKey_file(ctx,keyDebug,SSL_FILETYPE_PEM)
                    != SSL_SUCCESS) 
                    err_sys("failed to use key file: certs/client-key.pem");
}


// server
inline void set_serverCerts(SSL_CTX* ctx)
{
    store_ca(ctx);

    // To allow testing from serveral dirs
    if (SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
        != SSL_SUCCESS)
        if (SSL_CTX_use_certificate_file(ctx, svrCert2, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
            if (SSL_CTX_use_certificate_file(ctx, svrCert3, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
                err_sys("failed to use certificate: certs/server-cert.pem");
    
    // To allow testing from several dirs
    if (SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
         != SSL_SUCCESS) 
         if (SSL_CTX_use_PrivateKey_file(ctx, svrKey2, SSL_FILETYPE_PEM)
            != SSL_SUCCESS) 
                if (SSL_CTX_use_PrivateKey_file(ctx, svrKey3,SSL_FILETYPE_PEM)
                    != SSL_SUCCESS) 
                    err_sys("failed to use key file: certs/server-key.pem");
}


inline void set_args(int& argc, char**& argv, func_args& args)
{
    argc = args.argc;
    argv = args.argv;
    args.return_code = -1; // error state
}


inline void tcp_socket(SOCKET_T& sockfd, sockaddr_in& addr)
{
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    addr.sin_port = htons(yasslPort);
    addr.sin_addr.s_addr = inet_addr(loopback);
}


inline void tcp_connect(SOCKET_T& sockfd)
{
    sockaddr_in addr;
    tcp_socket(sockfd, addr);

    if (connect(sockfd, (const sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}


inline void tcp_listen(SOCKET_T& sockfd)
{
    sockaddr_in addr;
    tcp_socket(sockfd, addr);

    if (bind(sockfd, (const sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
    if (listen(sockfd, 3) != 0)
        err_sys("tcp listen failed");
}


inline void tcp_accept(SOCKET_T& sockfd, int& clientfd)
{
    tcp_listen(sockfd);

    sockaddr_in client;
    socklen_t client_len = sizeof(client);
    clientfd = accept(sockfd, (sockaddr*)&client, &client_len);

    if (clientfd == -1)
        err_sys("tcp accept failed");
}

#endif // yaSSL_TEST_HPP

