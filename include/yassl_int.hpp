/* yassl_int.hpp                                
 *
 * Copyright (C) 2003 Sawtooth Consulting Ltd.
 *
 * This file is part of yaSSL.
 *
 * yaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * yaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/* yaSSL internal header defines SSL supporting types not specified in the
 * draft along with type conversion functions and openssl compatibility
 */


#ifndef yaSSL_INT_HPP
#define yaSSL_INT_HPP

#include "yassl_imp.hpp"
#include "crypto_wrapper.hpp"
#include "cert_wrapper.hpp"
#include "lock.hpp"
#include "log.hpp"


namespace yaSSL {


// State Machine for Record Layer Protocol
enum RecordLayerState {
    recordNotReady = 0,         // fatal error, no more processing
    recordReady
};


// State Machine for HandShake Protocol
enum HandShakeState {
    handShakeNotReady = 0,      // fatal error, no more processing
    preHandshake,               // initial state
    inHandshake,                // handshake started
    handShakeReady              // handshake done
};


// client input HandShake state, use if HandShakeState == inHandShake
enum ClientState {
    serverNull = 0,
    serverHelloComplete,
    serverCertComplete,
    serverKeyExchangeComplete,
    serverHelloDoneComplete,
    serverFinishedComplete	
};


// server input HandShake state, use if HandShakeState == inHandShake
enum ServerState {
    clientNull = 0,
    clientHelloComplete,
    clientKeyExchangeComplete,
    clientFinishedComplete        
};


class States {
    RecordLayerState recordLayer_;
    HandShakeState   handshakeLayer_;
    ClientState      clientState_;
    ServerState      serverState_;
    std::string      errorString_;
    int              errorNumber_;
public:
    States();

    const RecordLayerState& getRecord()    const;
    const HandShakeState&   getHandShake() const;
    const ClientState&      getClient()    const;
    const ServerState&      getServer()    const;
    const std::string&      getString()    const;
          int               getNumber()    const;

    RecordLayerState& useRecord();
    HandShakeState&   useHandShake();
    ClientState&      useClient();
    ServerState&      useServer();
    std::string&      useString();
    int&              useNumber();
private:
    States(const States&);              // hide copy
    States& operator=(const States&);   // and assign
};


class sslFactory {
    MessageFactory      messageFactory_;        // creates new messages by type
    HandShakeFactory    handShakeFactory_;      // creates new handshake types
    ServerKeyFactory    serverKeyFactory_;      // creates new server key types
    ClientKeyFactory    clientKeyFactory_;      // creates new client key types

    sslFactory();
public:
    const MessageFactory&   getMessage()   const;
    const HandShakeFactory& getHandShake() const;
    const ServerKeyFactory& getServerKey() const;
    const ClientKeyFactory& getClientKey() const;

    friend sslFactory& GetSSL_Factory();        // singleton creator
private:
    sslFactory(const sslFactory&);              // hide copy
    sslFactory& operator=(const sslFactory&);   // and assign   
};


// openSSL X509
struct X509 {
    // TODO: add NAME elements and CTX
};


// openSSL X509 names
struct X509_NAME {
    // TODO: name part
};


// openSSL bignum
struct BIGNUM {
    Integer int_;
    void assign(const byte* b, uint s) { int_.assign(b,s); }
};


// openSSL session
class SSL_SESSION {
    opaque      sessionID_[ID_LEN];
    opaque      master_secret_[SECRET_LEN];
    Cipher      suite_[SUITE_LEN];
    uint        bornOn_;                        // create time in seconds
    uint        timeout_;                       // timeout in seconds
    RandomPool& random_;                        // will clean master secret
public:
    explicit SSL_SESSION(RandomPool&);
    SSL_SESSION(const SSL&, RandomPool&);
    ~SSL_SESSION();

    const opaque* getID()      const;
    const opaque* getSecret()  const;
    const Cipher* getSuite()   const;
          uint    getBornOn()  const;
          uint    getTimeOut() const;

    SSL_SESSION& operator=(const SSL_SESSION&); // allow assign for resumption
private:
    SSL_SESSION(const SSL_SESSION&);            // hide copy
};


class Sessions {
    std::list<SSL_SESSION*> list_;
    RandomPool random_;                 // for session cleaning
    Mutex      mutex_;                  // no-op for single threaded
    uint       timeout_;                // in seconds from creation

    Sessions() {}                       // only GetSessions can create
public: 
    SSL_SESSION* lookup(const opaque*, SSL_SESSION* copy = 0);
    void         add(const SSL&);
    void         remove(const opaque*);

    uint get_timeOut() const;

    ~Sessions();

    friend Sessions& GetSessions(); // singleton creator
private:
    Sessions(const Sessions&);              // hide copy
    Sessions& operator=(const Sessions&);   // and assign
};


Sessions&   GetSessions();      // forward singletons
sslFactory& GetSSL_Factory();


// openSSL method and context types
class SSL_METHOD {
    ProtocolVersion version_;
    ConnectionEnd   side_;
    bool            verifyPeer_;
    bool            failNoCert_;
public:
    explicit SSL_METHOD(ConnectionEnd ce, ProtocolVersion pv);

    ProtocolVersion getVersion() const;
    ConnectionEnd   getSide()    const;

    void setVerifyPeer();
    void setFailNoCert();

    bool verifyPeer() const;
    bool failNoCert() const;
private:
    SSL_METHOD(const SSL_METHOD&);              // hide copy
    SSL_METHOD& operator=(const SSL_METHOD&);   // and assign
};


class SSL_CTX {
    SSL_METHOD* method_;
    x509*       certificate_;
    x509*       privateKey_;
public:
    explicit SSL_CTX(SSL_METHOD* meth);
    ~SSL_CTX();

    const x509*       getCert()   const;
    const x509*       getKey()    const;
    const SSL_METHOD* getMethod() const;

    void setVerifyPeer();
    void setFailNoCert();

    friend int read_file(SSL_CTX*, const char*, int, CertType);
private:
    SSL_CTX(const SSL_CTX&);            // hide copy
    SSL_CTX& operator=(const SSL_CTX&); // and assign
};


class Crypto {
    MAC*                mac_;                   // agreed upon mac
    BulkCipher*         cipher_;                // agreed upon cipher
    DiffieHellman*      dh_;                    // server dh parms
    RandomPool          random_;                // random number generator
    CertManager         cert_;                  // manages certificates
public:
    Crypto();
    ~Crypto();

    const MAC&           get_mac()         const;
    const BulkCipher&    get_cipher()      const;
    const DiffieHellman& get_dh()          const;
    const RandomPool&    get_random()      const;
    const CertManager&   get_certManager() const;
          
    MAC&           use_mac();
    BulkCipher&    use_cipher();
    DiffieHellman& use_dh();
    RandomPool&    use_random();
    CertManager&   use_certManager();

    void setDH(DiffieHellman* dh);
    void setMAC(MAC* mac);
    void setCipher(BulkCipher* c);
private:
    Crypto(const Crypto&);              // hide copy
    Crypto& operator=(const Crypto&);   // and assign
};


class sslHashes {
    MD5       md5HandShake_;          // md5 handshake hash
    SHA       shaHandShake_;          // sha handshake hash
    Finished  verify_;                // peer's verify hash
    Hashes    certVerify_;            // peer's cert verify hash
public:
    sslHashes() {}

    const MD5&      get_MD5()        const;
    const SHA&      get_SHA()        const;
    const Finished& get_verify()     const;
    const Hashes&   get_certVerify() const;

    MD5&      use_MD5();
    SHA&      use_SHA();
    Finished& use_verify();
    Hashes&   use_certVerify();
private:
    sslHashes(const sslHashes&);             // hide copy
    sslHashes& operator=(const sslHashes&); // and assign
};


class Buffers {
    typedef std::list<input_buffer*>  inputList;
    typedef std::list<output_buffer*> outputList;

    inputList  dataList_;                           // list of users app data
    outputList handShakeList_;                      // buffered handshake msgs
public:
    Buffers() {}
    ~Buffers();

    const inputList&  getData()      const;
    const outputList& getHandShake() const;

    inputList&  useData();
    outputList& useHandShake();
private:
    Buffers(const Buffers&);             // hide copy
    Buffers& operator=(const Buffers&); // and assign   
};


class Security {
    Connection    conn_;                          // connection information
    Parameters    parms_;                         // may be pending
    SSL_SESSION   resumeSession_;                 // if resuming
    bool          resuming_;                      // trying to resume
public:
    Security(ProtocolVersion pv, RandomPool& ran, ConnectionEnd ce);

    const Connection&  get_connection() const;
    const Parameters&  get_parms()      const;
    const SSL_SESSION& get_resume()     const;
          bool         get_resuming()   const;

    Connection&  use_connection();
    Parameters&  use_parms();
    SSL_SESSION& use_resume();

    void set_resuming(bool b);
private:
    Security(const Security&);              // hide copy
    Security& operator=(const Security&);   // and assign
};


// THE SSL type
class SSL {
    Crypto              crypto_;                // agreed crypto agents
    Security            secure_;                // Connection and Session parms
    States              states_;                // Record and HandShake states
    sslHashes           hashes_;                // handshake, finished hashes
    Socket              socket_;                // socket wrapper
    Buffers             buffers_;               // buffered handshakes and data
    Log                 log_;                   // logger
public:
    SSL(SSL_CTX* ctx);

    // gets and uses
    const Crypto&     getCrypto()   const;
    const Security&   getSecurity() const;
    const States&     getStates()   const;
    const sslHashes&  getHashes()   const;
    const sslFactory& getFactory()  const;
    const Socket&     getSocket()   const;

    Crypto&    useCrypto();
    Security&  useSecurity();
    States&    useStates();
    sslHashes& useHashes();
    Socket&    useSocket();
    Log&       useLog();

    // sets
    void set_pending(Cipher suite);
    void set_random(const opaque*, ConnectionEnd);
    void set_sessionID(const opaque*);
    void set_session(SSL_SESSION*);
    void set_preMaster(const opaque*, uint);
    void set_masterSecret(const opaque*);
    void set_error(const Error& e);

    // helpers
    bool isTLS() const;
    void makeMasterSecret();
    void makeTLSMasterSecret();
    void addData(input_buffer* data);
    void fillData(Data&);
    void addBuffer(output_buffer* b);
    void flushBuffer();
    void verifyState(const RecordLayerHeader&);
    void verifyState(const HandShakeHeader&);
    void verifyState(ClientState);
    void verifyState(ServerState);
    void verfiyHandShakeComplete();
    void matchSuite(const opaque*, uint length);
    void deriveKeys();
    void deriveTLSKeys();
    void init_dh();

    uint bufferedData();
    uint get_SEQIncrement(bool);

    const  byte*  get_macSecret(bool);
private:
    void storeKeys(const opaque*);
    void setKeys();
    void verifyClientState(HandShakeType);
    void verifyServerState(HandShakeType);

    SSL(const SSL&);                    // hide copy
    const SSL& operator=(const SSL&);   // and assign
};



// conversion functions
void c32to24(uint32, uint24&);
void c24to32(const uint24, uint32&);

uint32 c24to32(const uint24);

void ato16(const opaque*, uint16&);
void ato24(const opaque*, uint24&);

void c16toa(uint16, opaque*);
void c24toa(const uint24, opaque*);
void c32toa(uint32 u32, opaque*);


} // naemspace

#endif // yaSSL_INT_HPP
