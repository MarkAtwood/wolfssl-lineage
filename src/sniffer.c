/* sniffer.c
 *
 * Copyright (C) 2006-2010 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef CYASSL_SNIFFER

#include "openssl/ssl.h"
#include "cyassl_int.h"
#include "cyassl_error.h"
#include "sniffer.h"
#include <string.h>


#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif


/* Misc constants */
enum {
    MAX_SERVER_ADDRESS = 128,
    ETHER_IF_ADDR_LEN  = 6,   /* ethernet interface address length */
    LOCAL_IF_ADDR_LEN  = 4,   /* localhost interface address length, !windows */
    TCP_PROTO          = 6,   /* TCP_PROTOCOL */
    IP_HDR_SZ          = 20,  /* IP header legnth, min */
    TCP_HDR_SZ         = 20,  /* TCP header legnth, min */
    IPV4               = 4,   /* IP version 4 */
    TCP_PROTOCOL       = 6,   /* TCP Protocol id */
};


/* Sniffer Server holds info for each server/port monitored */
typedef struct SnifferServer {
    SSL_CTX*   ctx;                            /* SSL context */
    char       address[MAX_SERVER_ADDRESS];    /* passed in server address */
    word32     server;                         /* IPV4 netowrk order address */
    int        port;                           /* server port */
} SnifferServer;


/* Sniffer Session holds info for each client/server SSL/TLS session */
typedef struct SnifferSession {
    SnifferServer* context;         /* server context */
    word32         server;          /* server address in network byte order */
    word32         client;          /* client address in network byte order */
    word16         srvPort;         /* server port */
    word16         cliPort;         /* client port */

    byte           srvRandom[RAN_LEN];        /* server's hello random */
    byte           cliRandom[RAN_LEN];        /* client's hello random */
    byte           masterSecret[SECRET_LEN];  /* master secret */

    Keys           keys;                      /* keys and assoc secrets */

} SnifferSession;


static SnifferServer  Server;
static SnifferSession Session;

/* add mutex for server list */
static SnifferServer  ServerList[5];
static int RegisteredServers = 0;


typedef struct IpInfo {
    int    length;        /* length of this header */
    int    total;         /* total length of fragment */
    word32 src;           /* network order source address */
    word32 dst;           /* network order destination address */
} IpInfo;


typedef struct TcpInfo {
    int    srcPort;       /* source port */
    int    dstPort;       /* source port */
    int    length;        /* length of this header */
    word32 sequence;      /* sequence number */
} TcpInfo;


static int SetPassword(char* passwd, int sz, int rw, void* userdata)
{
    strncpy(passwd, userdata, sz);
    return strlen(userdata);
}


typedef struct EthernetHdr {
    byte   dst[ETHER_IF_ADDR_LEN];    /* destination host address */ 
    byte   src[ETHER_IF_ADDR_LEN];    /* source  host address */ 
    word16 type;                      /* IP, ARP, etc */ 
} EthernetHdr;


typedef struct IpHdr {
    byte    ver_hl;              /* version/header length */
    byte    tos;                 /* type of service */
    word16  length;              /* total length */
    word16  id;                  /* identification */
    word16  offset;              /* fragment offset field */
    byte    ttl;                 /* time to live */
    byte    protocol;            /* protocol */
    word16  sum;                 /* checksum */
    word32  src;                 /* source address */
    word32  dst;                 /* destination address */
} IpHdr;


#define IP_HL(ip)      ( (((ip)->ver_hl) & 0x0f) * 4)
#define IP_V(ip)       ( ((ip)->ver_hl) >> 4)

typedef struct TcpHdr {
    word16  srcPort;            /* source port */
    word16  dstPort;            /* destination port */
    word32  sequence;           /* sequence number */ 
    word32  ack;                /* acknoledgment number */ 
    byte    offset;             /* data offset, reserved */
    byte    flags;              /* option flags */
    word16  window;             /* window */
    word16  sum;                /* checksum */
    word16  urgent;             /* urgent pointer */
} TcpHdr;

#define TCP_LEN(tcp)  ( (((tcp)->offset & 0xf0) >> 4) * 4)


/* See if this IPV4 network order address has been registered */
/* return 1 is true, 0 is false */
static int IsServerRegistered(word32 addr)
{
    int ret = 0, i;     /* false */

    /* lock mutex */
    for (i = 0; i < RegisteredServers; i++) {
        if (ServerList[i].server == addr) {
            ret = 1;
            break;
        }
    }
    /* unlock mutex */

    return ret;
}


/* See if this port has been registered to watch */
/* return 1 is true, 0 is false */
static int IsPortRegistered(word32 port)
{
    int ret = 0, i;     /* false */

    /* lock mutex */
    for (i = 0; i < RegisteredServers; i++) {
        if (ServerList[i].port == port) {
            ret = 1;
            break;
        }
    }
    /* unlock mutex */

    return ret;
}


/* Sets the private key for a specific server and port  */
/* returns 0 on success, -1 on error */
int ssl_SetPrivateKey(const char* serverAddress, int port, const char* keyFile,
                      const char* password, char* error)
{
    int ret;

    SnifferServer* sniffer = &Server;

    strncpy(sniffer->address, serverAddress, MAX_SERVER_ADDRESS);
    sniffer->port = port;
    sniffer->ctx = SSL_CTX_new(SSLv23_server_method());
    if (!sniffer->ctx) {
        /* set error to out of memory */
        return -1;
    }

    if (password){
        SSL_CTX_set_default_passwd_cb(sniffer->ctx, SetPassword);
        SSL_CTX_set_default_passwd_cb_userdata(sniffer->ctx, (void*)password);
    }
    ret = SSL_CTX_use_PrivateKey_file(sniffer->ctx, keyFile, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        /* set error to key file error */
        return -1;
    }
    return 0;
}


/* Check IP Header for IPV4, TCP, and a registered server address */
/* returns 0 on success, -1 on error */
static int CheckIpHdr(IpHdr* iphdr, IpInfo* info, char* error)
{
    int    version = IP_V(iphdr);

    if (version != IPV4) {
        /* set error to wrong IP version */ 
        return -1;
    }

    if (iphdr->protocol != TCP_PROTOCOL) { 
        /* set error to wrong Protocol type */
        return -1;
    }

    if (!IsServerRegistered(iphdr->src) && !IsServerRegistered(iphdr->dst)) {
        /* set error to Server Not Registered */
        return -1;
    }

    info->length  = IP_HL(iphdr);
    info->total   = ntohs(iphdr->length);
    info->src     = iphdr->src;
    info->dst     = iphdr->dst;

    return 0;
}


/* Check TCP Header for a registered port */
/* returns 0 on success, -1 on error */
static int CheckTcpHdr(TcpHdr* tcphdr, TcpInfo* info, char* error)
{
    info->srcPort   = ntohs(tcphdr->srcPort);
    info->dstPort   = ntohs(tcphdr->dstPort);
    info->length    = TCP_LEN(tcphdr);
    info->sequence  = ntohl(tcphdr->sequence);

    if (!IsPortRegistered(info->srcPort) && !IsPortRegistered(info->srcPort)) {
        /* set error to Server Port Not Registered */
        return -1;
    }

    return 0;
}


/* Decode Record Layer Header */
static int GetRecordHeader(const byte* input, RecordLayerHeader* rh, int* size)
{
    memcpy(rh, input, RECORD_HEADER_SZ);
    *size = ntohs(*((word16*)rh->length));

    if (*size > (MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA))
        return LENGTH_ERROR;

    return 0;
}


/* Process HandShake input */
static int DoHandShake(const byte* input, int* sslBytes, IpInfo* ipInfo,
                       TcpInfo* tcpInfo, char* error)
{

    return 0;
}


/* Passes in an IP/TCP packet for decoding (ethernet/localhost frame) removed */
/* returns Number of bytes on success, 0 for no data yet, and -1 on error */
int ssl_DecodePacket(const byte* packet, int length, byte* data, char* error)
{
    TcpInfo           tcpInfo;
    IpInfo            ipInfo;
    const byte*       sslFrame;
    const byte*       end = packet + length;
    int               sslBytes;                /* ssl bytes unconsumed */
    int               rhSize;
    int               ret;
    RecordLayerHeader rh;

    if (length < IP_HDR_SZ) {
        /* set error to short packet */
        return -1;
    }
    if (CheckIpHdr((IpHdr*)packet, &ipInfo, error) != 0)
        return -1;

    if (length < (ipInfo.length + TCP_HDR_SZ)) {
        /* set error to short packet */
        return -1;
    }
    if (CheckTcpHdr((TcpHdr*)(packet + ipInfo.length), &tcpInfo, error) != 0)
        return -1;

    sslFrame = (byte*)(packet + ipInfo.length + tcpInfo.length);
    if (sslFrame >= end) {
        /* set error to short packet */
        return -1;
    }
    sslBytes = end - sslFrame;
    if (sslBytes < RECORD_HEADER_SZ) {
        /* set error to short packet */
        return -1;
    }
    if (GetRecordHeader(sslFrame, &rh, &rhSize) != 0) {
        /* set error to bad record header */
        return -1;
    }
    sslBytes -= RECORD_HEADER_SZ;
    if (rhSize > sslBytes) {
        /* set error to short packet */
        return -1;
    }

    switch ((enum ContentType)rh.type) {
        case handshake:
            ret = DoHandShake(sslFrame, &sslBytes, &ipInfo, &tcpInfo, error);
            break;
        case change_cipher_spec:
            break;
        case application_data:
            break;
        case alert:
            break;
        default:
            /* set error to UNKNOWN_RECORD_TYPE */
            return -1;
    }

    return 0;
}


/* Enables (if traceFile)/ Disables debug tracing */
/* returns 0 on success, -1 on error */
int ssl_Trace(const char* traceFile, char* error)
{

    return 0;
}




#endif /* CYASSL_SNIFFER */
