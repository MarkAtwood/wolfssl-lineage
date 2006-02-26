/* test.h */

#ifndef CyaSSL_TEST_H
#define CyaSSL_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "types.h"

#ifdef _WIN32
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


#ifndef _POSIX_THREADS
    typedef unsigned int  THREAD_RETURN;
    typedef unsigned long THREAD_TYPE;
    #define YASSL_API __stdcall
#else
    typedef void*         THREAD_RETURN;
    typedef pthread_t     THREAD_TYPE;
    #define YASSL_API 
#endif


static const char* caCert = "../../certs/ca-cert.pem";
static const char* svrCert = "../../certs/server-cert.pem";
static const char* svrKey  = "../../certs/server-key.pem";


typedef struct tcp_ready {
    /* put in pthread stuff later */
    int ready;  /* predicate */
} tcp_ready;    


typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
    tcp_ready* signal_;
} func_args;

/*
func_args(int c = 0, char** v = 0) : argc(c), argv(v) {}
void SetSignal(tcp_ready* p) { signal_ = p; }
*/

typedef THREAD_RETURN YASSL_API THREAD_FUNC(void*);

void start_thread(THREAD_FUNC, func_args*, THREAD_TYPE*);
void join_thread(THREAD_TYPE);

/* yaSSL */
const char* const yasslIP   = "127.0.0.1";
const word16      yasslPort = 11111;


INLINE void err_sys(const char* msg)
{
    printf("yassl error: %s\n", msg);
    exit(EXIT_FAILURE);
}


INLINE void tcp_socket(SOCKET_T* sockfd, struct sockaddr_in* addr)
{
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;

    addr->sin_port = htons(yasslPort);
    addr->sin_addr.s_addr = inet_addr(yasslIP);
}


INLINE void tcp_connect(SOCKET_T* sockfd)
{
    struct sockaddr_in addr;
    tcp_socket(sockfd, &addr);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}


INLINE void tcp_listen(SOCKET_T* sockfd)
{
    struct sockaddr_in addr;
    tcp_socket(sockfd, &addr);

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp bind failed");
    if (listen(*sockfd, 3) != 0)
        err_sys("tcp listen failed");
}


INLINE void tcp_accept(SOCKET_T* sockfd, int* clientfd)
{
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    tcp_listen(sockfd);

#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER)
    /* signal ready to tcp_accept */
    tcp_ready* ready = *args->signal_;
    pthread_mutex_lock(&ready->mutex_);
    ready->ready_ = true;
    pthread_cond_signal(&ready->cond_);
    pthread_mutex_unlock(&ready->mutex_);
#endif

    *clientfd = accept(*sockfd, (struct sockaddr*)&client,
                      (ACCEPT_THIRD_T)&client_len);
    if (*clientfd == -1)
        err_sys("tcp accept failed");
}


#endif /* CyaSSL_TEST_H */

