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


#ifndef __yaSSL_int_hpp__
#define __yaSSL_int_hpp__

#include "yassl_imp.hpp"
#include "socket_wrapper.hpp"
#include "crypto_wrapper.hpp"
#include "cert_wrapper.hpp"
#include "factory.hpp"


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


struct States {
    RecordLayerState recordLayer_;
    HandShakeState   handshakeLayer_;
    ClientState      clientState_;
    ServerState      serverState_;
    std::string      errorString_;
    int              errorNumber_;

    States() : recordLayer_(recordReady), handshakeLayer_(preHandshake),
               clientState_(serverNull),  serverState_(clientNull),
               errorNumber_(0) {}
};


struct sslFactory {
    MessageFactory      messageFactory_;        // creates new messages by type
    HandShakeFactory    handShakeFactory_;      // creates new handshake types
    ServerKeyFactory    serverKeyFactory_;      // creates new server key types
    ClientKeyFactory    clientKeyFactory_;      // creates new client key types

    sslFactory() :           
            messageFactory_(InitMessageFactory),
            handShakeFactory_(InitHandShakeFactory),
            serverKeyFactory_(InitServerKeyFactory),
            clientKeyFactory_(InitClientKeyFactory) {}
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
    void assign(const byte* b, size_t s) { int_.assign(b,s); }
};


// openSSL session
struct SSL_SESSION {
    SSL_SESSION* session_;
    explicit SSL_SESSION(const SSL* ssl) : session_(0) {} 
                                                // TODO: store securityParms_
};


// openSSL method and context types
struct SSL_METHOD {
    ProtocolVersion version_;
    ConnectionEnd   side_;
    bool            rollback_;

    //SSL_METHOD() : version_(), side_(client_end), rollback_(false) {}
    explicit SSL_METHOD(ConnectionEnd ce, ProtocolVersion pv) 
        : version_(pv), side_(ce), rollback_(false) {}
};


struct SSL_CTX {
    SSL_METHOD* method_;
    x509*       certificate_;
    x509*       privateKey_;

    explicit SSL_CTX(SSL_METHOD* meth) : method_(meth), certificate_(0),
                                         privateKey_(0) {}
    ~SSL_CTX() { delete method_; delete certificate_; delete privateKey_; }

    const x509* getCert() { return certificate_; }
};


inline void deleteData(input_buffer* data) { delete data; }

// THE SSL type
class SSL {
    Connection          connection_;            // connection information
    SecurityParameters  securityParms_;         // may be pending  
    States              states_;                // Record and HandShake states
    CertManager         cert_;                  // manages certificates
    MD5                 md5HandShake_;          // md5 handshake hash
    SHA                 shaHandShake_;          // sha handshake hash
    Finished            verify_;                // peer's verify hashes
    RandomPool          random_;                // random number generator
    MAC*                mac_;                   // agreed upon mac
    BulkCipher*         cipher_;                // agreed upon cipher
    DiffieHellman*      dh_;                    // server dh parms
    sslFactory          factory_;               // creates new ssl objects
    Socket              socket_;                // socket wrapper
    Log                 log_;                   // logger
    Error               error_;                 // last error
    std::list<input_buffer*>  dataList_;        // list of users app data
    std::list<output_buffer*> handShakeList_;   // buffered handshake msgs
public:
    SSL(SSL_CTX* ctx);
    ~SSL();

    // gets and uses
    const Connection&         get_connection()  const { return connection_; }
    const SecurityParameters& get_security()    const { return securityParms_;}
    const States&             get_states()      const { return states_; }
    const CertManager&        get_certManager() const { return cert_; }
          CertManager&        use_certManager()       { return cert_; }

    const MD5& get_MD5() const { return md5HandShake_; }
    const SHA& get_SHA() const { return shaHandShake_; }
          MD5& use_MD5()       { return md5HandShake_; }
          SHA& use_SHA()       { return shaHandShake_; }

    const sslFactory& get_factory() const { return factory_; }
    const Finished&   get_verify()  const { return verify_; }

    const MAC&        get_mac()    const    { return *mac_; }
          MAC&        use_mac()             { return *mac_; }
    const BulkCipher& get_cipher() const    { return *cipher_; }
          BulkCipher& use_cipher()          { return *cipher_; }
    const DiffieHellman& get_dh()  const    { return *dh_; }
          DiffieHellman& use_dh()           { return *dh_; }
    const RandomPool& get_random() const    { return random_; }
    const Socket&     get_socket() const    { return socket_; }

    // sets
    void set_pending(Cipher suite);
    void set_random(const opaque*, ConnectionEnd);
    void set_sessionID(const opaque*);
    void set_preMaster(const opaque*, size_t);
    void set_error(const Error& e);
    void set_dh(DiffieHellman* dh) { dh_ = dh; }

    SecurityParameters& set_security()  { return securityParms_; }
    Finished&           set_verify()    { return verify_; }
    Socket&             set_socket()    { return socket_; }
    States&				set_states()    { return states_; }

    // helpers
    void   log(const char* msg) { log_.Trace(msg); }
    void   init_dh()      { dh_ = new DiffieHellman("certs/dh1024.p",random_);}
    bool   is_encrypted() { return securityParms_.pending_ == false; }
    bool   isTLS()        { return connection_.version_.major_ >= 3 && 
                                   connection_.version_.minor_ >= 1; }
    size_t get_SEQIncrement(bool);
    const  byte*  get_macSecret(bool);
    void   makeMasterSecret();
    void   makeTLSMasterSecret();
    void   addData(input_buffer* data) { dataList_.push_back(data); }
    void   fillData(Data&);
    void   addBuffer(output_buffer* ob) { handShakeList_.push_back(ob); }
    void   flushBuffer();
    size_t bufferedData();
    void   verifyState(const RecordLayerHeader&);
    void   verifyState(const HandShakeHeader&);
    void   verifyState(ClientState);
    void   verifyState(ServerState);
    void   verfiyHandShakeComplete();
    void   matchSuite(const opaque*, size_t length);
    void   restoreHashes(const MD5& md5, const SHA& sha) 
                        { md5HandShake_ = md5; shaHandShake_ = sha; }
private:
    void deriveKeys();
    void deriveTLSKeys();
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

#endif // __yaSSL_int_hpp__
