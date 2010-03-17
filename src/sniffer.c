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
#include <arpa/inet.h>




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
    TRACE_MSG_SZ       = 80,  /* Trace Message buffer size */
    HASH_SIZE          = 499, /* Session Hash Table Rows */
};


static int TraceOn = 1;       /* TAO switch back to 0 when done testing */
static FILE* TraceFile = 0;


static INLINE void Trace(const char* msg)
{
    if (TraceOn)
        //fprintf(TraceFile, "%s\n", msg);   /* TAO switch back when done */
        fprintf(stderr, "%s\n", msg);
}


/* Sniffer Server holds info for each server/port monitored */
typedef struct SnifferServer {
    SSL_CTX*       ctx;                          /* SSL context */
    char           address[MAX_SERVER_ADDRESS];  /* passed in server address */
    word32         server;                       /* netowrk order address */
    int            port;                         /* server port */
    struct SnifferServer* next;                  /* for list */
} SnifferServer;


/* Sniffer Session holds info for each client/server SSL/TLS session */
typedef struct SnifferSession {
    SnifferServer* context;         /* server context */
    SSL*           sslServer;       /* SSL server side decode */
    SSL*           sslClient;       /* SSL client side decode */
    word32         server;          /* server address in network byte order */
    word32         client;          /* client address in network byte order */
    word16         srvPort;         /* server port */
    word16         cliPort;         /* client port */
    byte           side;            /* which end is current packet headed */
    byte           cipherOn;        /* indicates whether cipher is active */
    struct SnifferSession* next;    /* for hash table list */
} SnifferSession;


/* Sniffer Server List and mutex */
static SnifferServer* ServerList = 0;
static CyaSSL_Mutex ServerListMutex;


/* Session Hash Table and mutex */
static SnifferSession* SessionTable[HASH_SIZE];
static CyaSSL_Mutex SessionMutex;


/* Initialize overall Sniffer */
void InitSniffer(void)
{
    InitMutex(&ServerListMutex);
    InitMutex(&SessionMutex);
}


/* Free overall Sniffer */
void FreeSniffer(void)
{
    FreeMutex(&SessionMutex);
    FreeMutex(&ServerListMutex);
}


/* Initialize a SnifferServer */
void InitSnifferServer(SnifferServer* sniffer)
{
    sniffer->ctx = 0;
    memset(sniffer->address, 0, MAX_SERVER_ADDRESS);
    sniffer->server   = 0;
    sniffer->port     = 0;
    sniffer->next     = 0;
}


/* Initialize a Sniffer Session */
void InitSession(SnifferSession* session)
{
    session->context   = 0;
    session->sslServer = 0;
    session->sslClient = 0;
    session->server    = 0;
    session->client    = 0;
    session->srvPort   = 0;
    session->cliPort   = 0;
    session->side      = 0;
    session->cipherOn  = 0;
    session->next      = 0;
}


/* IP Info from IP Header */
typedef struct IpInfo {
    int    length;        /* length of this header */
    int    total;         /* total length of fragment */
    word32 src;           /* network order source address */
    word32 dst;           /* network order destination address */
} IpInfo;


/* TCP Info from TCP Header */
typedef struct TcpInfo {
    int    srcPort;       /* source port */
    int    dstPort;       /* source port */
    int    length;        /* length of this header */
    word32 sequence;      /* sequence number */
} TcpInfo;


/* Password Setting Callback */
static int SetPassword(char* passwd, int sz, int rw, void* userdata)
{
    strncpy(passwd, userdata, sz);
    return strlen(userdata);
}


/* Ethernet Header */
typedef struct EthernetHdr {
    byte   dst[ETHER_IF_ADDR_LEN];    /* destination host address */ 
    byte   src[ETHER_IF_ADDR_LEN];    /* source  host address */ 
    word16 type;                      /* IP, ARP, etc */ 
} EthernetHdr;


/* IP Header */
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

/* TCP Header */
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
    int ret = 0;     /* false */
    SnifferServer* sniffer;

    LockMutex(&ServerListMutex);
    
    sniffer = ServerList;
    while (sniffer) {
        if (sniffer->server == addr) {
            ret = 1;
            break;
        }
        sniffer = sniffer->next;
    }
    
    UnLockMutex(&ServerListMutex);

    return ret;
}


/* See if this port has been registered to watch */
/* return 1 is true, 0 is false */
static int IsPortRegistered(word32 port)
{
    int ret = 0;    /* false */
    SnifferServer* sniffer;
    
    LockMutex(&ServerListMutex);
    
    sniffer = ServerList;
    while (sniffer) {
        if (sniffer->port == port) {
            ret = 1; 
            break;
        }
        sniffer = sniffer->next;
    }
    
    UnLockMutex(&ServerListMutex);

    return ret;
}


/* Get SnifferServer from IP and Port */
static SnifferServer* GetSnifferServer(IpInfo* ipInfo, TcpInfo* tcpInfo)
{
    SnifferServer* sniffer;
    
    LockMutex(&ServerListMutex);
    
    sniffer = ServerList;
    while (sniffer) {
        if (sniffer->port == tcpInfo->srcPort && sniffer->server == ipInfo->src)
            break;
        if (sniffer->port == tcpInfo->dstPort && sniffer->server == ipInfo->dst)
            break;
        sniffer = sniffer->next;
    }
    
    UnLockMutex(&ServerListMutex);
    
    return sniffer;
}


/* Hash the Session Info, return hash row */
static int SessionHash(IpInfo* ipInfo, TcpInfo* tcpInfo)
{
    int hash = (int)ipInfo->src * (int)ipInfo->dst;
    hash *= tcpInfo->srcPort * tcpInfo->dstPort;
    
    return hash % HASH_SIZE;
}


/* Get SnifferSession from IP and Port */
static SnifferSession* GetSnifferSession(IpInfo* ipInfo, TcpInfo* tcpInfo)
{
    SnifferSession* session;
    
    int row = SessionHash(ipInfo, tcpInfo);
    
    LockMutex(&SessionMutex);
    
    session = SessionTable[row];
    while (session) {
        if (session->server == ipInfo->src && session->client == ipInfo->dst &&
                    session->srvPort == tcpInfo->srcPort &&
                    session->cliPort == tcpInfo->dstPort)
            break;
        if (session->client == ipInfo->src && session->server == ipInfo->dst &&
                    session->cliPort == tcpInfo->srcPort &&
                    session->srvPort == tcpInfo->dstPort)
            break;
        
        session = session->next;
    }
    
    UnLockMutex(&SessionMutex);
    
    return session;
}


/* Sets the private key for a specific server and port  */
/* returns 0 on success, -1 on error */
int ssl_SetPrivateKey(const char* serverAddress, int port, const char* keyFile,
                      const char* password, char* error)
{
    int ret;

    SnifferServer* sniffer = (SnifferServer*)malloc(sizeof(SnifferServer));
    if (sniffer == NULL) {
        /* set error to out of memory */
        Trace("out of memory");
        return -1;
    }
    InitSnifferServer(sniffer);

    strncpy(sniffer->address, serverAddress, MAX_SERVER_ADDRESS);
    sniffer->server = inet_addr(sniffer->address);
    sniffer->port = port;
    /* start in client mode since SSL_new needs a cert for server */
    sniffer->ctx = SSL_CTX_new(TLSv1_client_method());
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
    Trace("Added new Sniffer Server");
    
    LockMutex(&ServerListMutex);
    
    sniffer->next = ServerList;
    ServerList = sniffer;
    
    UnLockMutex(&ServerListMutex);
    
    return 0;
}


/* Check IP Header for IPV4, TCP, and a registered server address */
/* returns 0 on success, -1 on error */
static int CheckIpHdr(IpHdr* iphdr, IpInfo* info, char* error)
{
    int    version = IP_V(iphdr);

    Trace("checking IP header");
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
        Trace("Server address not registered");
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
    Trace("checking TCP header");
    info->srcPort   = ntohs(tcphdr->srcPort);
    info->dstPort   = ntohs(tcphdr->dstPort);
    info->length    = TCP_LEN(tcphdr);
    info->sequence  = ntohl(tcphdr->sequence);

    if (!IsPortRegistered(info->srcPort) && !IsPortRegistered(info->dstPort)) {
        /* set error to Server Port Not Registered */
        Trace("Server Port not registered");
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


/* Process Client Key Exchange, RSA only */
static int ProcessClientKeyExchange(const byte* input, int* sslBytes,
                                    SnifferSession* session, char* error)
{
    word32 idx = 0;
    RsaKey key;
    int    ret;
    
    InitRsaKey(&key, 0);
   
    ret = RsaPrivateKeyDecode(session->context->ctx->privateKey.buffer,
                          &idx, &key, session->context->ctx->privateKey.length);
    if (ret == 0) {
        int length = RsaEncryptSize(&key);
        
        if (IsTLS(session->sslServer)) 
            input += 2;     /* tls pre length */
        
        ret = RsaPrivateDecrypt(input, length, 
                  session->sslServer->arrays.preMasterSecret, SECRET_LEN, &key);
        
        if (ret != SECRET_LEN) {
            /* set error to RSA Private Decrypt error */
            Trace("RSA Private Decrypt error");
            FreeRsaKey(&key);
            return -1;
        }
        session->sslServer->arrays.preMasterSz = SECRET_LEN;
        
        /* store for client side as well */
        memcpy(session->sslClient->arrays.preMasterSecret,
               session->sslServer->arrays.preMasterSecret, SECRET_LEN);
        session->sslClient->arrays.preMasterSz = SECRET_LEN;
        
        #ifdef SHOW_SECRETS
        {
            int i;
            printf("pre master secret: ");
            for (i = 0; i < SECRET_LEN; i++)
                printf("%02x", session->sslServer->arrays.preMasterSecret[i]);
            printf("\n");
        }
        #endif
    }
    else {
        /* set error to private key decode error */
        Trace("RSA Private Key Decode error");
        FreeRsaKey(&key);
        return -1;
    }
    
    if (SetCipherSpecs(session->sslServer) != 0) {
        /* set error to bad set cipher spec */
        Trace("Bad Set Cipher Spec");
        return -1;
    }
   
    if (SetCipherSpecs(session->sslClient) != 0) {
        /* set error to bad set cipher spec */
        Trace("Bad Set Cipher Spec");
        return -1;
    }
    
    MakeMasterSecret(session->sslServer);
    MakeMasterSecret(session->sslClient);
#ifdef SHOW_SECRETS
    {
        int i;
        printf("server master secret: ");
        for (i = 0; i < SECRET_LEN; i++)
            printf("%02x", session->sslServer->arrays.masterSecret[i]);
        printf("\n");
        
        printf("client master secret: ");
        for (i = 0; i < SECRET_LEN; i++)
            printf("%02x", session->sslClient->arrays.masterSecret[i]);
        printf("\n");
    }
#endif   
    
    FreeRsaKey(&key);
    return ret;
}


/* Process Server Hello */
static int ProcessServerHello(const byte* input, int* sslBytes,
                              SnifferSession* session, char* error)
{
    ProtocolVersion pv;
    byte            b;
    int             toRead = sizeof(ProtocolVersion) + RAN_LEN + ENUM_LEN;

    /* make sure can read through session len */
    if (toRead > *sslBytes) {
        /* set error to short packet */
        Trace("can't read through random on Server Hello");
        return -1;
    }
    
    memcpy(&pv, input, sizeof(ProtocolVersion));
    input     += sizeof(ProtocolVersion);
    *sslBytes -= sizeof(ProtocolVersion);
           
    session->sslServer->version = pv;
    session->sslClient->version = pv;
           
    memcpy(session->sslServer->arrays.serverRandom, input, RAN_LEN);
    memcpy(session->sslClient->arrays.serverRandom, input, RAN_LEN);
    input    += RAN_LEN;
    *sslBytes -= RAN_LEN;
    
    b = *input++;
    *sslBytes -= 1;
    
    /* make sure can read through compression */
    if ( (b + SUITE_LEN + ENUM_LEN) > *sslBytes) {
        /* set error to short packet */
        Trace("can't read through compression on Server Hello");
        return -1;
    }
    input     += b;
    *sslBytes -= b;
    
    (void)*input++;  /* eat first byte, always 0 */
    b = *input++;
    session->sslServer->options.cipherSuite = b;
    session->sslClient->options.cipherSuite = b;
    *sslBytes -= SUITE_LEN;
    
#ifdef SHOW_SECRETS
    {
        int i;
        printf("cipher suite = 0x%02x\n",
               session->sslServer->options.cipherSuite);
        printf("server random: ");
        for (i = 0; i < RAN_LEN; i++)
            printf("%02x", session->sslServer->arrays.serverRandom[i]);
        printf("\n");
    }
#endif   
    return 0;
}


/* Process normal Client Hello */
static int ProcessClientHello(const byte* input, int* sslBytes, 
                              SnifferSession* session, char* error)
{
    /* make sure can read up to session len */
    int toRead = sizeof(ProtocolVersion) + RAN_LEN + ENUM_LEN;
    if (toRead > *sslBytes) {
        /* set erorr to short packet */
        Trace("can't read up to session len on Client Hello");
        return -1;
    }
    
    /* skip, get negotiated one from server hello */
    input    += sizeof(ProtocolVersion);
    memcpy(session->sslServer->arrays.clientRandom, input, RAN_LEN);
    memcpy(session->sslClient->arrays.clientRandom, input, RAN_LEN);
    
#ifdef SHOW_SECRETS
    {
        int i;
        printf("client random: ");
        for (i = 0; i < RAN_LEN; i++)
            printf("%02x", session->sslServer->arrays.clientRandom[i]);
        printf("\n");
    }
#endif
    
    return 0;
}


/* Process HandShake input */
static int DoHandShake(const byte* input, int* sslBytes, IpInfo* ipInfo,
                       TcpInfo* tcpInfo, SnifferSession* session, char* error)
{
    byte type;
    int  size;
    int  ret = 0;
    
    if (*sslBytes < HANDSHAKE_HEADER_SZ) {
        /* set error to short packet */
        Trace("Incomplete HandShake Header");
        return -1;
    }
    type = input[0];
    size = (input[1] << 16) | (input[2] << 8) | input[3];
    
    input     += HANDSHAKE_HEADER_SZ;
    *sslBytes -= HANDSHAKE_HEADER_SZ;
    
    printf("sslBytes = %d\n", *sslBytes);
    printf("size = %d\n", size);
    
    if (*sslBytes < size) {
        /* set error to short packet */
        Trace("Incomplete HandShake data");
        return -1;
    }
    
    switch (type) {
        case hello_verify_request:
            Trace("Got hello verify request");
            break;
        case server_hello:
            Trace("Got server hello");
            ret = ProcessServerHello(input, sslBytes, session, error);
            break;
        case certificate_request:
            Trace("Got certificate request");
            break;
        case server_key_exchange:
            Trace("Got server key exchange");
            break;
        case certificate:
            Trace("Got certificate");
            break;
        case server_hello_done:
            Trace("Got server hello done");
            break;
        case finished:
            Trace("Got finished");
            {
                SSL*   ssl;
                word32 inOutIdx = 0;
                
                if (session->side == SERVER_END)
                    ssl = session->sslServer;
                else
                    ssl = session->sslClient;
                ret = DoFinished(ssl, input, &inOutIdx, SNIFF);
                
                printf("DoFinished ret = %d\n", ret);
            }
            break;
        case client_hello:
            Trace("Got Client Hello");
            ret = ProcessClientHello(input, sslBytes, session, error);
            break;
        case client_key_exchange:
            Trace("Got client key exchange");
            ret = ProcessClientKeyExchange(input, sslBytes, session, error);
            break;
        case certificate_verify:
            Trace("Got certificate verify");
            break;
        default:
            Trace("Got UNKOWN handshake type");
            /* set error to unknown handshake type */
            return -1;
    }   

    return ret;
}


/* Decrypt input into plain output */
static void Decrypt(SSL* ssl, byte* output, const byte* input, word32 sz)
{
    switch (ssl->specs.bulk_cipher_algorithm) {
        #ifdef BUILD_ARC4
        case rc4:
            Arc4Process(&ssl->decrypt.arc4, output, input, sz);
            break;
        #endif
            
        #ifdef BUILD_DES3
        case triple_des:
            Des3_CbcDecrypt(&ssl->decrypt.des3, output, input, sz);
            break;
        #endif
            
        #ifdef BUILD_AES
        case aes:
            AesCbcDecrypt(&ssl->decrypt.aes, output, input, sz);
            break;
        #endif
            
        #ifdef BUILD_HC128
        case hc128:
            Hc128_Process(&ssl->decrypt.hc128, output, input, sz);
            break;
        #endif
            
        #ifdef BUILD_RABBIT
        case rabbit:
            RabbitProcess(&ssl->decrypt.rabbit, output, input, sz);
            break;
        #endif
    }
}


/* Decrypt input message into output, adjust output steam if needed */
static const byte* DecryptMessage(SSL* ssl, const byte* input, word32 sz,
                                  byte* output)
{
    Decrypt(ssl, output, input, sz);
    ssl->keys.encryptSz = sz;
    if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
        return output + ssl->specs.block_size;     /* go past TLSv1.1 IV */
    
    return output;
}


/* Find an existing session or create a new one */
static SnifferSession* FindSession(IpInfo* ipInfo, TcpInfo* tcpInfo)
{
    SnifferSession* session = 0;
    
    /* try to get exisiting sniffer sesison */
    session = GetSnifferSession(ipInfo, tcpInfo);
    if (session == 0) {
        int row;
        
        Trace("Creating a new Sniffer Session");
        /* create a new one */
        session = (SnifferSession*)malloc(sizeof(SnifferSession));
        if (session == NULL) {
            /* set error to out of memory */
            Trace("Out of memory");
            return 0;
        }
        InitSession(session);
        session->server  = ipInfo->dst;
        session->client  = ipInfo->src;
        session->srvPort = tcpInfo->dstPort;
        session->cliPort = tcpInfo->srcPort;
                
        session->context = GetSnifferServer(ipInfo, tcpInfo);
        if (session->context == NULL) {
            /* set error to no server registered */
            Trace("No Server registered for this packet");
            free(session);
            return 0;
        }
        
        session->sslServer = SSL_new(session->context->ctx);
        session->sslClient = SSL_new(session->context->ctx);
        if (session->sslClient == NULL) {
            if (session->sslServer) {
                SSL_free(session->sslClient);
                session->sslClient = 0;
            }
            /* set error to no new SSL */
            Trace("Unable to get new SSL");
            free(session);
            return 0;
        }
        /* put server back into server mode */
        session->sslServer->options.side = SERVER_END;
        
        row = SessionHash(ipInfo, tcpInfo);

        /* add it to the session table */
        LockMutex(&SessionMutex);
        
        session->next = SessionTable[row];
        SessionTable[row] = session;
        
        UnLockMutex(&SessionMutex);
    }
    
    /* determine side */
    if (ipInfo->dst == session->context->server &&
                       tcpInfo->dstPort == session->context->port)
        session->side = SERVER_END;
    else
        session->side = CLIENT_END;
    
    return session;
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
    SnifferSession*   session = 0;
    char              traceMsg[TRACE_MSG_SZ];

    Trace("Got a packet to decode");
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
    if (sslFrame > end) {
        /* set error to short packet */
        return -1;
    }
    sslBytes = end - sslFrame;
    if (sslBytes == 0) {
        Trace("No Actual Data");
        return 0;
    }
    snprintf(traceMsg, TRACE_MSG_SZ, "\nGot %d SSL Bytes\n", sslBytes);
    Trace(traceMsg);
    if (sslBytes < RECORD_HEADER_SZ) {
        /* set error to short packet */
        return -1;
    }
    if (GetRecordHeader(sslFrame, &rh, &rhSize) != 0) {
        /* set error to bad record header */
        return -1;
    }
    sslFrame += RECORD_HEADER_SZ;
    sslBytes -= RECORD_HEADER_SZ;
    if (rhSize > sslBytes) {
        /* set error to short packet */
        return -1;
    }
    
    session = FindSession(&ipInfo, &tcpInfo);
    if (!session) {
        /* set error to bad session */
        Trace("Unable to find/create session");
        return -1;
    }
    
    /* decrypt if needed */
    if (session->cipherOn) {
        if (session->side == SERVER_END) {
            sslFrame = DecryptMessage(session->sslServer, sslFrame, rhSize,
                       session->sslServer->buffers.inputBuffer.buffer);
        }
        else {
            sslFrame = DecryptMessage(session->sslClient, sslFrame, rhSize,
                       session->sslClient->buffers.inputBuffer.buffer);
        }
    }
    
    switch ((enum ContentType)rh.type) {
        case handshake:
            Trace("Got a handhskae message");
            ret = DoHandShake(sslFrame, &sslBytes, &ipInfo, &tcpInfo, session,
                              error);
            break;
        case change_cipher_spec:
            session->cipherOn = 1;
            Trace("Got a change cipher spec mesaage");
            break;
        case application_data:
            Trace("Got application data");
            {
                SSL*   ssl;
                word32 inOutIdx = 0;
                
                if (session->side == SERVER_END)
                    ssl = session->sslServer;
                else
                    ssl = session->sslClient;
                ret = DoApplicationData(ssl, (byte*)sslFrame, &inOutIdx);
                if (ret == 0) {
                    ret = ssl->buffers.clearOutputBuffer.length;
                    memcpy(data, ssl->buffers.clearOutputBuffer.buffer, ret);
                    ssl->buffers.clearOutputBuffer.length = 0;
                    return ret;
                }
            }
            break;
        case alert:
            Trace("Got an alert message");
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
    if (traceFile) {
        TraceFile = fopen(traceFile, "a");
        if (!TraceFile) {
            /* set error to bad traceFile */
            return -1;
        }
        TraceOn = 1;
    }
    return 0;
}




#endif /* CYASSL_SNIFFER */
