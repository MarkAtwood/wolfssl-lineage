/* test.h */

#ifndef CyaSSL_TEST_H
#define CyaSSL_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include "types.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <process.h>
    #define SOCKET_T int
#else
    #include <string.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #ifdef NON_BLOCKING
        #include <fcntl.h>
    #endif
    #define SOCKET_T unsigned int
#endif /* _WIN32 */


#if defined(__MACH__) || defined(_WIN32)
    typedef int socklen_t;
#endif


/* HPUX doesn't use socklent_t for third parameter to accept */
#if !defined(__hpux__)
    typedef socklen_t* ACCEPT_THIRD_T;
#else
    typedef int*       ACCEPT_THIRD_T;
#endif


#ifdef _WIN32
    #define CloseSocket(s) closesocket(s)
    #define StartTCP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }
#else
    #define CloseSocket(s) close(s)
    #define StartTCP() 
#endif


#ifndef _POSIX_THREADS
    typedef unsigned int  THREAD_RETURN;
    typedef unsigned long THREAD_TYPE;
    #define CYASSL_API __stdcall
#else
    typedef void*         THREAD_RETURN;
    typedef pthread_t     THREAD_TYPE;
    #define CYASSL_API 
#endif


#ifndef NO_MAIN_DRIVER
    static const char* caCert = "../../certs/ca-cert.pem";
    static const char* svrCert = "../../certs/server-cert.pem";
    static const char* svrKey  = "../../certs/server-key.pem";
#else
    static const char* caCert = "../certs/ca-cert.pem";
    static const char* svrCert = "../certs/server-cert.pem";
    static const char* svrKey  = "../certs/server-key.pem";
#endif


typedef struct tcp_ready {
    int ready;              /* predicate */
#ifdef _POSIX_THREADS
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
#endif
} tcp_ready;    


void InitTcpReady();
void FreeTcpReady();


typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
    tcp_ready* signal;
} func_args;


typedef THREAD_RETURN CYASSL_API THREAD_FUNC(void*);

void start_thread(THREAD_FUNC, func_args*, THREAD_TYPE*);
void join_thread(THREAD_TYPE);

/* yaSSL */
static const char* const yasslIP   = "127.0.0.1";
static const word16      yasslPort = 11111;


static INLINE void err_sys(const char* msg)
{
    printf("yassl error: %s\n", msg);
    exit(EXIT_FAILURE);
}


static INLINE void tcp_socket(SOCKET_T* sockfd, struct sockaddr_in* addr,
                              const char* peer, word16 port)
{
    const char* host = peer;

    /* peer could be in human readable form */
    if (isalpha(peer[0])) {
        struct hostent* entry = gethostbyname(peer);

        if (entry) {
            struct sockaddr_in tmp;
            memset(&tmp, 0, sizeof(struct sockaddr_in));
            memcpy(&tmp.sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            host = inet_ntoa(tmp.sin_addr);
        }
        else
            err_sys("no entry for host");
    }
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;

    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = inet_addr(host);
}


static INLINE void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port)
{
    struct sockaddr_in addr;
    tcp_socket(sockfd, &addr, ip, port);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}


static INLINE void tcp_listen(SOCKET_T* sockfd)
{
    struct sockaddr_in addr;
    tcp_socket(sockfd, &addr, yasslIP, yasslPort);

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
    if (listen(*sockfd, 3) != 0)
        err_sys("tcp listen failed");
}


static INLINE void tcp_accept(SOCKET_T* sockfd, int* clientfd, func_args* args)
{
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    tcp_listen(sockfd);

#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER)
    /* signal ready to tcp_accept */
    {
    tcp_ready* ready = args->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
    }
#endif

    *clientfd = accept(*sockfd, (struct sockaddr*)&client,
                      (ACCEPT_THIRD_T)&client_len);
    if (*clientfd == -1)
        err_sys("tcp accept failed");
}


static INLINE void tcp_set_nonblocking(SOCKET_T* sockfd)
{
#ifdef NON_BLOCKING
    #ifdef _WIN32
        unsigned long blocking = 1;
        int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
    #else
        int flags = fcntl(*sockfd, F_GETFL, 0);
        int ret = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
    #endif
#endif
}



#endif /* CyaSSL_TEST_H */

