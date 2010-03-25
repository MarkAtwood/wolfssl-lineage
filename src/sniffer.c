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
#include "sniffer_error.h"
#include <string.h>

#ifndef _WIN32
	#include <arpa/inet.h>
#endif

#include <assert.h>





/* Misc constants */
enum {
    MAX_SERVER_ADDRESS = 128, /* maximum server address length */
    MAX_ERROR_LEN      = 80,  /* maximum error length */
    ETHER_IF_ADDR_LEN  = 6,   /* ethernet interface address length */
    LOCAL_IF_ADDR_LEN  = 4,   /* localhost interface address length, !windows */
    TCP_PROTO          = 6,   /* TCP_PROTOCOL */
    IP_HDR_SZ          = 20,  /* IP header legnth, min */
    TCP_HDR_SZ         = 20,  /* TCP header legnth, min */
    IPV4               = 4,   /* IP version 4 */
    TCP_PROTOCOL       = 6,   /* TCP Protocol id */
    TRACE_MSG_SZ       = 80,  /* Trace Message buffer size */
    HASH_SIZE          = 499, /* Session Hash Table Rows */
    PSEUDO_HDR_SZ      = 12,  /* TCP Pseudo Header size in bytes */
    FATAL_ERROR_STATE  =  1,  /* SnifferSession fatal error state */
};


#ifdef _WIN32

static HMODULE dllModule;  /* for error string resources */

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	static int didInit = 0;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if (didInit == 0) {
            dllModule = hModule;
			ssl_InitSniffer();
			didInit = 1;
		}
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
		if (didInit) {
			ssl_FreeSniffer();
			didInit = 0;
		}
        break;
    }
    return TRUE;
}

#endif /* _WIN32 */


static int TraceOn = 0;         /* Trace is off by default */
static FILE* TraceFile = 0;


/* windows uses .rc talbe for this */
#ifndef _WIN32

static const char* const msgTable[] =
{
    /* 1 */
    "Out of Memory",
    "New SSL Sniffer Server Registered",
    "Checking IP Header",
    "SSL Sniffer Server Not Registered",
    "Checking TCP Header",

    /* 6 */
    "SSL Sniffer Server Port Not Registered",
    "RSA Private Decrypt Error",
    "RSA Private Decdoe Error",
    "Set Cipher Spec Error",
    "Server Hello Input Malformed",

    /* 11 */
    "Couldn't Resume Session Error",
    "Server Did Resumption",
    "Client Hello Input Malformed",
    "Client Trying to Resume",
    "Handshake Input Malformed",

    /* 16 */
    "Got Hello Verify msg",
    "Got Server Hello msg",
    "Got Cert Request msg",
    "Got Server Key Exchange msg",
    "Got Cert msg",

    /* 21 */
    "Got Server Hello Done msg",
    "Got Finished msg",
    "Got Client Hello msg",
    "Got Client Key Exchange msg",
    "Got Cert Verify msg",

    /* 26 */
    "Got Unknown Handshake msg",
    "New SSL Sniffer Session created",
    "Couldn't create new SSL",
    "Got a Packet to decode",
    "No data present",

    /* 31 */
    "Session Not Found",
    "Got an Old Client Hello msg",
    "Old Client Hello Input Malformed",
    "Old Client Hello OK",
    "Bad Old Client Hello",

    /* 36 */
    "Bad Record Header",
    "Record Header Input Malformed",
    "Got a HandShake msg",
    "Bad HandShake msg",
    "Got a Change Cipher Spec msg",

    /* 41 */
    "Got Application Data msg",
    "Bad Application Data",
    "Got an Alert msg",
    "Another msg to Process",
    "Removing Session From Table",
    
    /* 46 */
    "Bad Key File",
    "Wrong IP Version",
    "Wrong Protocol type",
    "Packet Short for header processing",
    "Got Unknown Record Type",
    
    /* 51 */
    "Can't Open Trace File",
};


/* *nix version uses table above */
static void GetError(int idx, char* buffer)
{
    strncpy(buffer, msgTable[idx - 1], MAX_ERROR_LEN);
}


#else /* _WIN32 */


/* Windows version uses .rc table */
static void GetError(int idx, char* buffer)
{
    if (!LoadStringA(dllModule, idx, buffer, MAX_ERROR_LEN))
        buffer[0] = 0;
}


#endif /* _WIN32 */


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
    word32         cliSeqStart;     /* client start sequence */
    word32         srvSeqStart;     /* server start sequence */
    word32         cliExpected;     /* client expected sequence (relative) */
    word32         srvExpected;     /* server expected sequence (relative) */
    byte           side;            /* which end is current packet headed */
    byte           serverCipherOn;  /* indicates whether cipher is active */
    byte           clientCipherOn;  /* indicates whether cipher is active */
    byte           resuming;        /* did this session come from resumption */
    byte           cached;          /* have we cached this session yet */
    byte           clientHello;     /* processed client hello yet, for SSLv2 */
    byte           finCount;        /* get both FINs before removing */
    byte           fatalError;      /* fatal error state */
    struct SnifferSession* next;    /* for hash table list */
} SnifferSession;


/* Sniffer Server List and mutex */
static SnifferServer* ServerList = 0;
static CyaSSL_Mutex ServerListMutex;


/* Session Hash Table and mutex */
static SnifferSession* SessionTable[HASH_SIZE];
static CyaSSL_Mutex SessionMutex;


/* Initialize overall Sniffer */
void ssl_InitSniffer(void)
{
    InitCyaSSL();
    InitMutex(&ServerListMutex);
    InitMutex(&SessionMutex);
}


/* Free Sniffer Server's resources/self */
static void FreeSnifferServer(SnifferServer* server)
{
    if (server)
        SSL_CTX_free(server->ctx);
    free(server);
}


/* Free Sniffer Session's resources/self */
static void FreeSnifferSession(SnifferSession* session)
{
    if (session) {
        SSL_free(session->sslClient);
        SSL_free(session->sslServer);
    }
    free(session);
}


/* Free overall Sniffer */
void ssl_FreeSniffer(void)
{
    SnifferServer*  server;
    SnifferServer*  removeServer;
    SnifferSession* session;
    SnifferSession* removeSession;
    int i;

    LockMutex(&ServerListMutex);
    LockMutex(&SessionMutex);
    
    server = ServerList;
    while (server) {
        removeServer = server;
        server = server->next;
        FreeSnifferServer(removeServer);
    }

    for (i = 0; i < HASH_SIZE; i++) {
        session = SessionTable[i];
        while (session) {
            removeSession = session;
            session = session->next;
            FreeSnifferSession(removeSession);
        }
    }

    UnLockMutex(&SessionMutex);
    UnLockMutex(&ServerListMutex);

    FreeMutex(&SessionMutex);
    FreeMutex(&ServerListMutex);
    FreeCyaSSL();
}


/* Initialize a SnifferServer */
static void InitSnifferServer(SnifferServer* sniffer)
{
    sniffer->ctx = 0;
    memset(sniffer->address, 0, MAX_SERVER_ADDRESS);
    sniffer->server   = 0;
    sniffer->port     = 0;
    sniffer->next     = 0;
}


/* Initialize a Sniffer Session */
static void InitSession(SnifferSession* session)
{
    session->context        = 0;
    session->sslServer      = 0;
    session->sslClient      = 0;
    session->server         = 0;
    session->client         = 0;
    session->srvPort        = 0;
    session->cliPort        = 0;
    session->cliSeqStart    = 0;
    session->srvSeqStart    = 0;
    session->cliExpected    = 0;
    session->srvExpected    = 0;
    session->side           = 0;
    session->serverCipherOn = 0;
    session->clientCipherOn = 0;
    session->resuming       = 0;
    session->cached         = 0;
    session->clientHello    = 0;
    session->finCount       = 0;
    session->fatalError     = 0;
    session->next           = 0;
}


/* Use platform specific GetError to write to tracfile if tracing */ 
static void Trace(int idx) 
{
    if (TraceOn) {
        char buffer[MAX_ERROR_LEN];
        GetError(idx, buffer);
        fprintf(TraceFile, "%s\n", buffer);
        fprintf(stderr,    "%s\n", buffer);  /* TAO remove when done */
    }
}


/* Set user error string */
static void SetError(int idx, char* error, SnifferSession* session, int fatal)
{
    GetError(idx, error);
    Trace(idx);
    if (session && fatal == FATAL_ERROR_STATE)
        session->fatalError = 1;
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
    byte   fin;           /* FIN set */
    byte   rst;           /* RST set */
    byte   syn;           /* SYN set */
    byte   ack;           /* ACK set */
} TcpInfo;


/* Tcp Pseudo Header for Checksum calculation */
typedef struct TcpPseudoHdr {
    word32  src;        /* source address */
    word32  dst;        /* destination address */
    byte    rsv;        /* reserved, always 0 */
    byte    protocol;   /* IP protocol */
    word16  legnth;     /* tcp header length + data length (doesn't include */
                        /* pseudo header length) network order */
} TcpPseudoHdr;


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
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

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
static word32 SessionHash(IpInfo* ipInfo, TcpInfo* tcpInfo)
{
    word32 hash = ipInfo->src * ipInfo->dst;
    hash *= tcpInfo->srcPort * tcpInfo->dstPort;
    
    return hash % HASH_SIZE;
}


/* Get Exisiting SnifferSession from IP and Port */
static SnifferSession* GetSnifferSession(IpInfo* ipInfo, TcpInfo* tcpInfo)
{
    SnifferSession* session;
    
    word32 row = SessionHash(ipInfo, tcpInfo);
    assert(row >= 0 && row <= HASH_SIZE);
    
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
    
    /* determine side */
    if (session) {
        if (ipInfo->dst == session->context->server &&
            tcpInfo->dstPort == session->context->port)
            session->side = SERVER_END;
        else
            session->side = CLIENT_END;
    }    
    
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
        SetError(MEMORY_STR, error, NULL, 0);
        return -1;
    }
    InitSnifferServer(sniffer);

    strncpy(sniffer->address, serverAddress, MAX_SERVER_ADDRESS);
    sniffer->server = inet_addr(sniffer->address);
    sniffer->port = port;
    /* start in client mode since SSL_new needs a cert for server */
    sniffer->ctx = SSL_CTX_new(SSLv3_client_method());
    if (!sniffer->ctx) {
        SetError(MEMORY_STR, error, NULL, 0);
        return -1;
    }

    if (password){
        SSL_CTX_set_default_passwd_cb(sniffer->ctx, SetPassword);
        SSL_CTX_set_default_passwd_cb_userdata(sniffer->ctx, (void*)password);
    }
    ret = SSL_CTX_use_PrivateKey_file(sniffer->ctx, keyFile, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        SetError(KEY_FILE_STR, error, NULL, 0);
        return -1;
    }
    Trace(NEW_SERVER_STR);
    
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

    Trace(IP_CHECK_STR);
    if (version != IPV4) {
        SetError(BAD_IPVER_STR, error, NULL, 0); 
        return -1;
    }

    if (iphdr->protocol != TCP_PROTOCOL) { 
        SetError(BAD_PROTO_STR, error, NULL, 0);
        return -1;
    }

    if (!IsServerRegistered(iphdr->src) && !IsServerRegistered(iphdr->dst)) {
        SetError(SERVER_NOT_REG_STR, error, NULL, 0);
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
    Trace(TCP_CHECK_STR);
    info->srcPort   = ntohs(tcphdr->srcPort);
    info->dstPort   = ntohs(tcphdr->dstPort);
    info->length    = TCP_LEN(tcphdr);
    info->sequence  = ntohl(tcphdr->sequence);
    info->fin       = tcphdr->flags & TCP_FIN;
    info->rst       = tcphdr->flags & TCP_RST;
    info->syn       = tcphdr->flags & TCP_SYN;
    info->ack       = tcphdr->flags & TCP_ACK;

    if (!IsPortRegistered(info->srcPort) && !IsPortRegistered(info->dstPort)) {
        SetError(SERVER_PORT_NOT_REG_STR, error, NULL, 0);
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
            SetError(RSA_DECRYPT_STR, error, session, FATAL_ERROR_STATE);
            FreeRsaKey(&key);
            return -1;
        }
        ret = 0;  /* not in error state */
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
        SetError(RSA_DECODE_STR, error, session, FATAL_ERROR_STATE);
        FreeRsaKey(&key);
        return -1;
    }
    
    if (SetCipherSpecs(session->sslServer) != 0) {
        SetError(BAD_CIPHER_SPEC_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
   
    if (SetCipherSpecs(session->sslClient) != 0) {
        SetError(BAD_CIPHER_SPEC_STR, error, session, FATAL_ERROR_STATE);
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
        SetError(SERVER_HELLO_INPUT_STR, error, session, FATAL_ERROR_STATE);
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
        SetError(SERVER_HELLO_INPUT_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
    memcpy(session->sslServer->arrays.sessionID, input, ID_LEN);
    input     += b;
    *sslBytes -= b;
    
    (void)*input++;  /* eat first byte, always 0 */
    b = *input++;
    session->sslServer->options.cipherSuite = b;
    session->sslClient->options.cipherSuite = b;
    *sslBytes -= SUITE_LEN;
    
    if (memcmp(session->sslServer->arrays.sessionID,
               session->sslClient->arrays.sessionID, ID_LEN) == 0) {
        /* resuming */
        SSL_SESSION* resume = GetSession(session->sslServer,
                                       session->sslServer->arrays.masterSecret);
        if (resume == NULL) {
            SetError(BAD_SESSION_RESUME_STR, error, session, FATAL_ERROR_STATE);
            return -1;
        }
        /* make sure client has master secret too */
        memcpy(session->sslClient->arrays.masterSecret,
               session->sslServer->arrays.masterSecret, SECRET_LEN);
        session->resuming = 1;
        
        Trace(SERVER_DID_RESUMPTION_STR);
        if (SetCipherSpecs(session->sslServer) != 0) {
            SetError(BAD_CIPHER_SPEC_STR, error, session, FATAL_ERROR_STATE);
            return -1;
        }
        
        if (SetCipherSpecs(session->sslClient) != 0) {
            SetError(BAD_CIPHER_SPEC_STR, error, session, FATAL_ERROR_STATE);
            return -1;
        }
        
        if (session->sslServer->options.tls) {
            DeriveTlsKeys(session->sslServer);
            DeriveTlsKeys(session->sslClient);
        }
        else {
            DeriveKeys(session->sslServer);
            DeriveKeys(session->sslClient);
        }
    }
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
    byte sessionLen;
    /* make sure can read up to session len */
    int toRead = sizeof(ProtocolVersion) + RAN_LEN + ENUM_LEN;
    if (toRead > *sslBytes) {
        /* set erorr to short packet */
        Trace(CLIENT_HELLO_INPUT_STR);
        return -1;
    }
    
    /* skip, get negotiated one from server hello */
    input     += sizeof(ProtocolVersion);
    *sslBytes -= sizeof(ProtocolVersion);
    
    memcpy(session->sslServer->arrays.clientRandom, input, RAN_LEN);
    memcpy(session->sslClient->arrays.clientRandom, input, RAN_LEN);
    
    input     += RAN_LEN;
    *sslBytes -= RAN_LEN;
    
    /* store session in case trying to resume */
    sessionLen = *input++;
    if (sessionLen) {
        if (ID_LEN > *sslBytes) {
            SetError(CLIENT_HELLO_INPUT_STR, error, session, FATAL_ERROR_STATE);
            return -1;
        }
        Trace(CLIENT_RESUME_TRY_STR);
        memcpy(session->sslClient->arrays.sessionID, input, ID_LEN);
    }
#ifdef SHOW_SECRETS
    {
        int i;
        printf("client random: ");
        for (i = 0; i < RAN_LEN; i++)
            printf("%02x", session->sslServer->arrays.clientRandom[i]);
        printf("\n");
    }
#endif
    
    session->clientHello = 1;
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
        SetError(HANDSHAKE_INPUT_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
    type = input[0];
    size = (input[1] << 16) | (input[2] << 8) | input[3];
    
    input     += HANDSHAKE_HEADER_SZ;
    *sslBytes -= HANDSHAKE_HEADER_SZ;
    
    if (*sslBytes < size) {
        SetError(HANDSHAKE_INPUT_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
    
    switch (type) {
        case hello_verify_request:
            Trace(GOT_HELLO_VERIFY_STR);
            break;
        case server_hello:
            Trace(GOT_SERVER_HELLO_STR);
            ret = ProcessServerHello(input, sslBytes, session, error);
            break;
        case certificate_request:
            Trace(GOT_CERT_REQ_STR);
            break;
        case server_key_exchange:
            Trace(GOT_SERVER_KEY_EX_STR);
            break;
        case certificate:
            Trace(GOT_CERT_STR);
            break;
        case server_hello_done:
            Trace(GOT_SERVER_HELLO_DONE_STR);
            break;
        case finished:
            Trace(GOT_FINISHED_STR);
            {
                SSL*   ssl;
                word32 inOutIdx = 0;
                
                if (session->side == SERVER_END)
                    ssl = session->sslServer;
                else
                    ssl = session->sslClient;
                ret = DoFinished(ssl, input, &inOutIdx, SNIFF);
                
                if (ret == 0 && session->cached == 0) {
                    AddSession(session->sslServer);
                    session->cached = 1;
                }
            }
            break;
        case client_hello:
            Trace(GOT_CLIENT_HELLO_STR);
            ret = ProcessClientHello(input, sslBytes, session, error);
            break;
        case client_key_exchange:
            Trace(GOT_CLIENT_KEY_EX_STR);
            ret = ProcessClientKeyExchange(input, sslBytes, session, error);
            break;
        case certificate_verify:
            Trace(GOT_CERT_VER_STR);
            break;
        default:
            SetError(GOT_UNKNOWN_HANDSHAKE_STR, error, session, 0);
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


/* remove session from session table */
static void RemoveSession(SnifferSession* session, IpInfo* ipInfo,
                        TcpInfo* tcpInfo)
{
    SnifferSession* previous = 0;
    SnifferSession* current;
    word32          row = SessionHash(ipInfo, tcpInfo);
    
    assert(row >= 0 && row <= HASH_SIZE);
    Trace(REMOVE_SESSION_STR);
    
    LockMutex(&SessionMutex);
    
    current = SessionTable[row];
    
    while (current) {
        if (current == session) {
            if (previous)
                previous->next = current->next;
            else
                SessionTable[row] = current->next;
            FreeSnifferSession(session);
            printf("\n found it \n");
            break;
        }
        previous = current;
        current  = current->next;
    }
    
    UnLockMutex(&SessionMutex);
}


/* Create a new Sniffer Session */
static SnifferSession* CreateSession(IpInfo* ipInfo, TcpInfo* tcpInfo,
                                     char* error)
{
    SnifferSession* session = 0;
    int row;
        
    Trace(NEW_SESSION_STR);
    /* create a new one */
    session = (SnifferSession*)malloc(sizeof(SnifferSession));
    if (session == NULL) {
        SetError(MEMORY_STR, error, NULL, 0);
        return 0;
    }
    InitSession(session);
    session->server  = ipInfo->dst;
    session->client  = ipInfo->src;
    session->srvPort = tcpInfo->dstPort;
    session->cliPort = tcpInfo->srcPort;
    session->cliSeqStart = tcpInfo->sequence;
    session->cliExpected = 1;  /* relative */
                
    session->context = GetSnifferServer(ipInfo, tcpInfo);
    if (session->context == NULL) {
        SetError(SERVER_NOT_REG_STR, error, NULL, 0);
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
        SetError(BAD_NEW_SSL_STR, error, session, FATAL_ERROR_STATE);
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
        
    /* determine headed side */
    if (ipInfo->dst == session->context->server &&
        tcpInfo->dstPort == session->context->port)
        session->side = SERVER_END;
    else
        session->side = CLIENT_END;        
    
    return session;
}


/* Process Old Client Hello Input */
static int DoOldHello(SnifferSession* session, const byte* sslFrame,
                      int* rhSize, int* sslBytes, char* error)
{
    const byte* input = sslFrame;
    byte        b0, b1;
    word32      idx = 0;
    int         ret;

    Trace(GOT_OLD_CLIENT_HELLO_STR);
    b0 = *input++;
    b1 = *input++;
    *sslBytes -= 2;
    *rhSize = ((b0 & 0x7f) << 8) | b1;

    if (*rhSize > *sslBytes) {
        SetError(OLD_CLIENT_INPUT_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }

    ret = ProcessOldClientHello(session->sslServer, input, &idx, *sslBytes,
                                *rhSize);    
    if (ret < 0) {
        SetError(BAD_OLD_CLIENT_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
    
    Trace(OLD_CLIENT_OK_STR);
    memcpy(session->sslClient->arrays.clientRandom,
           session->sslServer->arrays.clientRandom, RAN_LEN);
    session->clientHello = 1;
    
    *sslBytes -= *rhSize;
    return 0;
}


/* Calculate the TCP checksum, see RFC 1071 */
/* return 0 for success, -1 on error */
/* can be called from decode() with
   TcpChecksum(&ipInfo, &tcpInfo, sslBytes, packet + ipInfo.length);
   could also add a 64bit version if type available and using this
*/
int TcpChecksum(IpInfo* ipInfo, TcpInfo* tcpInfo, int dataLen,
                const byte* packet)
{
    TcpPseudoHdr  pseudo;
    int           count = PSEUDO_HDR_SZ;
    const word16* data = (word16*)&pseudo;
    word32        sum = 0;
    word16        checksum;
    
    pseudo.src = ipInfo->src;
    pseudo.dst = ipInfo->dst;
    pseudo.rsv = 0;
    pseudo.protocol = TCP_PROTO;
    pseudo.legnth = htons(tcpInfo->length + dataLen);
    
    /* pseudo header sum */
    while (count >= 2) {
        sum   += *data++;
        count -= 2;
    }
    
    count = tcpInfo->length + dataLen;
    data = (word16*)packet;
    
    /* main sum */
    while (count > 1) {
        sum   += *data++;
        count -=2;
    }
    
    /* get left-over, if any */
    packet = (byte*)data;
    if (count > 0) {
        sum += *packet;
    }
    
    /* fold 32bit sum into 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    
    checksum = (word16)~sum;
    /* checksum should now equal 0, since included already calcd checksum */
    /* field, but tcp checksum offloading could negate calculation */
    if (checksum == 0)
        return 0;
    return -1;
}


/* Check IP and TCP headers, set payload */
/* returns 0 on success, -1 on error */
int CheckHeaders(IpInfo* ipInfo, TcpInfo* tcpInfo, const byte* packet,
                 int length, const byte** sslFrame, int* sslBytes, char* error)
{
    Trace(GOT_PACKET_STR);
    if (length < IP_HDR_SZ) {
        SetError(PACKET_HDR_SHORT_STR, error, NULL, 0);
        return -1;
    }
    if (CheckIpHdr((IpHdr*)packet, ipInfo, error) != 0)
        return -1;
    
    if (length < (ipInfo->length + TCP_HDR_SZ)) {
        SetError(PACKET_HDR_SHORT_STR, error, NULL, 0);
        return -1;
    }
    if (CheckTcpHdr((TcpHdr*)(packet + ipInfo->length), tcpInfo, error) != 0)
        return -1;
    
    *sslFrame = packet + ipInfo->length + tcpInfo->length;
    if (*sslFrame > packet + length) {
        SetError(PACKET_HDR_SHORT_STR, error, NULL, 0);
        return -1;
    }
    *sslBytes = packet + length - *sslFrame;
    
    return 0;
}


/* Create or Find existing session */
/* returns 0 on success (continue), -1 on error, 1 on success (end) */
static int CheckSession(IpInfo* ipInfo, TcpInfo* tcpInfo, int sslBytes,
                        SnifferSession** session, char* error)
{
    /* create a new SnifferSession on client SYN */
    if (tcpInfo->syn && !tcpInfo->ack) {
        *session = CreateSession(ipInfo, tcpInfo, error);
        if (*session == NULL) {
            *session = GetSnifferSession(ipInfo, tcpInfo);
            /* already had exisiting, so OK */
            if (*session)
                return 1;
            
            SetError(MEMORY_STR, error, NULL, 0);
            return -1;
        }
        return 1;
    }
    /* get existing sniffer session */
    else {
        *session = GetSnifferSession(ipInfo, tcpInfo);
        if (*session == NULL) {
            /* don't worry about extraneous RST or duplicate FINs */
            if (tcpInfo->fin || tcpInfo->rst)
                return 1;
            /* don't worry about duplicate ACKs either */
            if (sslBytes == 0 && tcpInfo->ack)
                return 1;
            
            SetError(BAD_SESSION_STR, error, NULL, 0);
            return -1;
        }        
    }
    return 0;
}


/* Check TCP Sequence status */
/* returns 0 on success (continue), -1 on error, 1 on success (end) */
int CheckSequence(TcpInfo* tcpInfo, SnifferSession* session, int sslBytes)
{
    /* init SEQ from server to client */
    if (tcpInfo->syn && tcpInfo->ack) {
        session->srvSeqStart = tcpInfo->sequence;
        session->srvExpected = 1;
        return 1;
    }
    
    /* adjust incoming server side */
    if (session->side == SERVER_END) {
        word32 real = tcpInfo->sequence - session->cliSeqStart;
        /* handle rollover of sequence */
        if (tcpInfo->sequence < session->cliSeqStart)
            real = 0xffffffffU - session->cliSeqStart + tcpInfo->sequence;
        
        printf("\tserver expected = %u\n", session->cliExpected);
        printf("\tserver real     = %u\n", real);
        
        if (real < session->cliExpected) {
            printf("\t oops duplicate\n");
            return 1;
        }
        
        session->cliExpected += sslBytes;
        if (tcpInfo->fin)
            session->cliExpected += 1;
    }
    
    /* adjust iincoming client side */
    if (session->side == CLIENT_END) {
        word32 real = tcpInfo->sequence - session->srvSeqStart;
        /* handle sequence rollover */
        if (tcpInfo->sequence < session->srvSeqStart)
            real = 0xffffffffU - session->srvSeqStart + tcpInfo->sequence;
        
        printf("\tclient expected = %u\n", session->srvExpected);
        printf("\tclient real     = %u\n", real);
        
        if (real < session->srvExpected) {
            printf("\t oops duplicate\n");
            return 0;
        }
        
        session->srvExpected += sslBytes;
        if (tcpInfo->fin)
            session->srvExpected += 1;
    }
    
    return 0;
}


/* Check Status before record processing */
/* returns 0 on success (continue), -1 on error, 1 on success (end) */
static int CheckPreRecord(IpInfo* ipInfo, TcpInfo* tcpInfo,const byte* sslFrame,
                          SnifferSession* session, int* sslBytes, char* error)
{
    /* remove SnifferSession on 2nd FIN or RST */
    if (tcpInfo->fin || tcpInfo->rst) {
        /* flag FIN and RST */
        if (tcpInfo->fin)
            session->finCount += 1;
        else if (tcpInfo->rst)
            session->finCount += 2;
        
        if (session->finCount >= 2) {
            RemoveSession(session, ipInfo, tcpInfo);
            return 1;
        }
    }
    
    if (*sslBytes == 0) {
        Trace(NO_DATA_STR);
        return 1;
    }
    
    if (*sslBytes < RECORD_HEADER_SZ) {
        SetError(RECORD_INPUT_STR, error, NULL, 0);
        return -1;
    }
    
    if (session->clientHello == 0 && *sslFrame != handshake) {
        int rhSize;
        int ret = DoOldHello(session, sslFrame, &rhSize, sslBytes, error);
        if (ret < 0)
            return -1;  /* error already set */
        if (*sslBytes <= 0)
            return 1;
    }
    
    return 0;
}


/* Process Message(s) from sslFrame */
/* return Number of bytes on success, 0 for no data yet, and -1 on error */
static int ProcessMessage(IpInfo* ipInfo, TcpInfo* tcpInfo,const byte* sslFrame,
                          SnifferSession* session, int sslBytes, byte* data,
                          const byte* end, char* error)
{
    const byte*       tmp;
    RecordLayerHeader rh;
    int               rhSize;
    int               ret;
    
doMessage:
    if (GetRecordHeader(sslFrame, &rh, &rhSize) != 0) {
        SetError(BAD_RECORD_HDR_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
    sslFrame += RECORD_HEADER_SZ;
    sslBytes -= RECORD_HEADER_SZ;
    if (rhSize > sslBytes) {
        SetError(RECORD_INPUT_STR, error, session, FATAL_ERROR_STATE);
        return -1;
    }
    tmp = sslFrame + rhSize;   /* may have more than one record to process */
    
    /* decrypt if needed */
    if (session->side == SERVER_END && session->serverCipherOn)
        sslFrame = DecryptMessage(session->sslServer, sslFrame, rhSize,
                                session->sslServer->buffers.inputBuffer.buffer);
    else if (session->side == CLIENT_END && session->clientCipherOn)
        sslFrame = DecryptMessage(session->sslClient, sslFrame, rhSize,
                                session->sslClient->buffers.inputBuffer.buffer);
            
    switch ((enum ContentType)rh.type) {
        case handshake:
            Trace(GOT_HANDSHAKE_STR);
            ret = DoHandShake(sslFrame, &sslBytes, ipInfo, tcpInfo, session,
                              error);
            if (ret != 0) {
                SetError(BAD_HANDSHAKE_STR, error, session, FATAL_ERROR_STATE);
                return -1;
            }
            break;
        case change_cipher_spec:
            if (session->side == SERVER_END)
                session->serverCipherOn = 1;
            else
                session->clientCipherOn = 1;
            Trace(GOT_CHANGE_CIPHER_STR);
            break;
        case application_data:
            Trace(GOT_APP_DATA_STR);
            {
                SSL*   ssl;
                word32 inOutIdx = 0;
                    
                /* TAO check for clear output before getting? */
                if (session->side == SERVER_END)
                    ssl = session->sslServer;
                else
                    ssl = session->sslClient;
                ret = DoApplicationData(ssl, (byte*)sslFrame, &inOutIdx);
                if (ret == 0) {
                    ret = ssl->buffers.clearOutputBuffer.length;
                    if (ret) {  /* may be blank message */
                        memcpy(data, ssl->buffers.clearOutputBuffer.buffer,ret);
                        ssl->buffers.clearOutputBuffer.length = 0;
                        assert(tmp >= end);
                        return ret;
                    }
                }
                else {
                    SetError(BAD_APP_DATA_STR, error,session,FATAL_ERROR_STATE);
                    return -1;
                }
            }
            break;
        case alert:
            Trace(GOT_ALERT_STR);
            break;
        default:
            SetError(GOT_UNKNOWN_RECORD_STR, error, session, FATAL_ERROR_STATE);
            return -1;
    }
    
    if (tmp < end) {
        Trace(ANOTHER_MSG_STR);
        sslFrame = tmp;
        sslBytes = end - tmp;
        goto doMessage;
    }    
    
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
    int               ret;
    SnifferSession*   session = 0;

    if (CheckHeaders(&ipInfo, &tcpInfo, packet, length, &sslFrame, &sslBytes,
                     error) != 0)
        return -1;
    
    ret = CheckSession(&ipInfo, &tcpInfo, sslBytes, &session, error);
    if (ret == -1)     return -1;
    else if (ret == 1) return  0;   /* done for now */
    
    ret = CheckSequence(&tcpInfo, session, sslBytes);
    if (ret == -1)     return -1;
    else if (ret == 1) return  0;   /* done for now */
    
    ret = CheckPreRecord(&ipInfo, &tcpInfo, sslFrame, session, &sslBytes,error);
    if (ret == -1)     return -1;
    else if (ret == 1) return  0;   /* done for now */

    return ProcessMessage(&ipInfo, &tcpInfo, sslFrame, session, sslBytes, data,
                          end, error);
}


/* Enables (if traceFile)/ Disables debug tracing */
/* returns 0 on success, -1 on error */
int ssl_Trace(const char* traceFile, char* error)
{
    if (traceFile) {
        TraceFile = fopen(traceFile, "a");
        if (!TraceFile) {
            SetError(BAD_TRACE_FILE_STR, error, NULL, 0);
            return -1;
        }
        TraceOn = 1;
    }
    else 
        TraceOn = 0;

    return 0;
}




#endif /* CYASSL_SNIFFER */
