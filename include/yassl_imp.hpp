/* yassl_imp.hpp                                
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

/*  yaSSL implementation header defines all strucutres from the SSL.v3 
 *  specification "draft-freier-ssl-version3-02.txt"
 *  all page citations refer to this document unless otherwise noted.
 */


#ifndef yaSSL_IMP_HPP
#define yaSSL_IMP_HPP

#ifdef _MSC_VER
    // disable truncated debug symbols
    #pragma warning(disable:4786)
#endif

#include "yassl_types.hpp"
#include "buffer.hpp"
#include "factory.hpp"
#include <list>


namespace yaSSL {


class SSL;  // forward THE ssl type


struct ProtocolVersion {
    uint8 major_;
    uint8 minor_;     // major and minor SSL/TLS version numbers

    ProtocolVersion(uint8 maj = 3, uint8 min = 0) : major_(maj), minor_(min) {}
};


// Record Layer Header for PlainText, Compressed, and CipherText
struct RecordLayerHeader {
    ContentType     type_;
    ProtocolVersion version_;
    uint16          length_;             // should not exceed 2^14
};


// base for all messages
struct Message {
    virtual input_buffer& set(input_buffer&) =0;   
    virtual output_buffer& get(output_buffer&) const =0;

    virtual void Process(input_buffer&, SSL&) =0;
    virtual ContentType get_type() const =0;
    virtual uint16      get_length() const =0;

    virtual ~Message() {}
};


class ChangeCipherSpec : public Message {
    CipherChoice type_;
public:
    ChangeCipherSpec() : type_(change_cipher_spec_choice) {}

    friend input_buffer& operator>>(input_buffer&, ChangeCipherSpec&);
    friend output_buffer& operator<<(output_buffer&, const ChangeCipherSpec&);

    input_buffer& set(input_buffer& in) { return in >> *this; }
    output_buffer& get(output_buffer& out) const { return out << *this; }

    ContentType get_type()   const { return change_cipher_spec; }
    uint16      get_length() const { return SIZEOF_ENUM; }
    void Process(input_buffer&, SSL&);
private:
    ChangeCipherSpec(const ChangeCipherSpec&);            // hide copy
    ChangeCipherSpec& operator=(const ChangeCipherSpec&); // and assign
};



class Alert : public Message {
    AlertLevel       level_;
    AlertDescription description_;
public:
    Alert() {}
    Alert(AlertLevel al, AlertDescription ad) : level_(al), description_(ad) {}

    ContentType get_type()   const { return alert; }
    uint16      get_length() const { return SIZEOF_ENUM * 2; }
    void Process(input_buffer&, SSL&);

    friend input_buffer& operator>>(input_buffer&, Alert&);
    friend output_buffer& operator<<(output_buffer&, const Alert&);
   
    input_buffer& set(input_buffer& in) { return in >> *this; }
    output_buffer& get(output_buffer& out) const { return out << *this; }
private:
    Alert(const Alert&);            // hide copy
    Alert& operator=(const Alert&); // and assign
};


class Data : public Message {
    uint16        length_;
    opaque*       buffer_;         // read  buffer used by fillData input
    const opaque* write_buffer_;   // write buffer used by output operator
public:
    Data() : length_(0), buffer_(0), write_buffer_(0) {}
    Data(uint16 len, opaque* b) : length_(len), buffer_(b), write_buffer_(0) {}
    Data(uint16 len, const opaque* w) : length_(len), buffer_(0),
                                        write_buffer_(w) {}

    friend output_buffer& operator<<(output_buffer&, const Data&);

    input_buffer& set(input_buffer& in) { return in; }
    output_buffer& get(output_buffer& out) const { return out << *this; }

    ContentType   get_type()     const { return application_data; }
    uint16        get_length()   const { return length_; }
    const opaque* get_buffer()   const { return write_buffer_; }
    void          set_length(uint16 l) { length_ = l; }
    opaque*       set_buffer()         { return buffer_; }
    void Process(input_buffer&, SSL&);
private:
    Data(const Data&);            // hide copy
    Data& operator=(const Data&); // and assign
};


uint32 c24to32(const uint24);       // forward form internal header
void   c32to24(uint32, uint24&);


// HandShake header, same for each message type from page 20/21
class HandShakeHeader : public Message {
    HandShakeType      type_;
    uint24             length_;      // length of message
public:
    HandShakeHeader() {}

    ContentType   get_type()   const { return handshake; }
    uint16        get_length() const { return c24to32(length_); }
    HandShakeType get_handshakeType() const { return type_; }
    void Process(input_buffer&, SSL&);

    void set_type(HandShakeType hst) { type_ = hst; }
    void set_length(uint32 u32) { c32to24(u32, length_); }

    friend input_buffer& operator>>(input_buffer&, HandShakeHeader&);
    friend output_buffer& operator<<(output_buffer&, const HandShakeHeader&);

    input_buffer& set(input_buffer& in) { return in >> *this; }
    output_buffer& get(output_buffer& out) const { return out << *this; }
private:
    HandShakeHeader(const HandShakeHeader&);            // hide copy
    HandShakeHeader& operator=(const HandShakeHeader&); // and assign
};


// Base Class for all handshake messages
class HandShakeBase {
    int     length_;
public:
    int     get_length() const { return length_; }
    void    set_length(int l)  { length_ = l; }

    // for building buffer's type field
    virtual HandShakeType get_type() const { return no_shake; } // TODO: pure

    // handles dispactch of proper >>
    virtual input_buffer&  set(input_buffer& in) { return in; } // TODO: pure
    virtual output_buffer& get(output_buffer& out) const { return out; }
    // TODO: make pure

    virtual void Process(input_buffer&, SSL&) {}; // TODO: make pure

    virtual ~HandShakeBase() {}
};


struct HelloRequest : public HandShakeBase {
    input_buffer&  set(input_buffer& in)         { return in;}
    output_buffer& get(output_buffer& out) const { return out; }

    void Process(input_buffer&, SSL&) {}

    HandShakeType get_type() const { return hello_request; };
};


// The Client's Hello Message from page 23
class ClientHello : public HandShakeBase {
    ProtocolVersion     client_version_;
    Random              random_;
    uint8               id_len_;                         // session id length
    opaque              session_id_[ID_LEN];
    uint16              suite_len_;                      // cipher suite length
    opaque              cipher_suites_[MAX_SUITE_SZ];
    uint8               comp_len_;                       // compression length
    CompressionMethod   compression_methods_;  
public:
    friend input_buffer&  operator>>(input_buffer&, ClientHello&);
    friend output_buffer& operator<<(output_buffer&, const ClientHello&);
  
    input_buffer&  set(input_buffer& in)         { return in  >> *this; }
    output_buffer& get(output_buffer& out) const { return out << *this; }

    HandShakeType  get_type() const { return client_hello; };
    void Process(input_buffer&, SSL&);

    const opaque* get_random() const { return random_; }
    friend void buildClientHello(SSL&, ClientHello&, CompressionMethod);

    ClientHello() {}
    explicit ClientHello(ProtocolVersion pv) : client_version_(pv) {}
private:
    ClientHello(const ClientHello&);            // hide copy
    ClientHello& operator=(const ClientHello&); // and assign
};



// The Server's Hello Message from page 24
class ServerHello : public HandShakeBase {
    ProtocolVersion     server_version_;
    Random              random_;
    uint8               id_len_;                 // session id length
    opaque              session_id_[ID_LEN];
    opaque              cipher_suite_[SUITE_LEN];
    CompressionMethod   compression_method_;
public:
    explicit ServerHello(ProtocolVersion pv) : server_version_(pv) {}
    ServerHello() {}
    
        
    friend input_buffer&  operator>>(input_buffer&, ServerHello&);
    friend output_buffer& operator<<(output_buffer&, const ServerHello&);
   
    input_buffer&  set(input_buffer& in)         { return in  >> *this; }
    output_buffer& get(output_buffer& out) const { return out << *this; }

    HandShakeType  get_type() const { return server_hello; };
    void Process(input_buffer&, SSL&);

    const opaque* get_random() const { return random_; }
    friend void buildServerHello(SSL&, ServerHello&);
private:
    ServerHello(const ServerHello&);            // hide copy
    ServerHello& operator=(const ServerHello&); // and assign
};


class x509;  

// Certificate could be a chain
class Certificate : public HandShakeBase {
    const x509* cert_;
public:
    Certificate() : cert_(0) {}
    explicit Certificate(const x509* cert); 
    friend output_buffer& operator<<(output_buffer&, const Certificate&);

    const opaque* get_buffer() const;
  
    // Process handles input, needs SSL
    input_buffer&  set(input_buffer& in)         { return in; }
    output_buffer& get(output_buffer& out) const { return out << *this; }

    HandShakeType get_type() const { return certificate; }
    void Process(input_buffer&, SSL&);
private:
    Certificate(const Certificate&);            // hide copy
    Certificate& operator=(const Certificate&); // and assign
};



// RSA Public Key
struct ServerRSAParams {
    opaque rsa_modulus_[RSA_MOD];
    opaque rsa_exponent_[RSA_EXP];
};


// Ephemeral Diffie-Hellman Parameters
class ServerDHParams {
    int pSz_;
    int gSz_;
    int pubSz_;
    opaque* p_;
    opaque* g_;
    opaque* Ys_;
public:
    ServerDHParams() : pSz_(0), gSz_(0), pubSz_(0), p_(0), g_(0), Ys_(0) {}
    ~ServerDHParams() { delete[] Ys_; delete[] g_; delete[] p_; }

    int get_pSize()   const { return pSz_; }
    int get_gSize()   const { return gSz_; }
    int get_pubSize() const { return pubSz_; }

    const opaque* get_p()   const { return p_; }
    const opaque* get_g()   const { return g_; }
    const opaque* get_pub() const { return Ys_; }

    opaque* alloc_p(int sz)
    {
        p_ = new opaque[pSz_ = sz];
        return p_;
    }

    opaque* alloc_g(int sz)
    {
        g_ = new opaque[gSz_ = sz];
        return g_;
    }

    opaque* alloc_pub(int sz)
    {
        Ys_ = new opaque[pubSz_ = sz];
        return Ys_;
    }
private:
    ServerDHParams(const ServerDHParams&);            // hide copy
    ServerDHParams& operator=(const ServerDHParams&); // and assign
};


struct ServerKeyBase {
    virtual ~ServerKeyBase() {}
    virtual void build(SSL&) {}
    virtual void read(SSL&, input_buffer&) {}
    virtual int  get_length() const { return 0; }
    virtual opaque* get_serverKey() const { return 0; }
};


// Server random number for FORTEZZA KEA
struct Fortezza_Server : public ServerKeyBase {
    opaque r_s_[FORTEZZA_MAX];
};


struct SignatureBase {
    virtual ~SignatureBase() {}
};

struct anonymous_sa : public SignatureBase {};


struct Hashes {
    uint8 md5_[MD5_LEN];
    uint8 sha_[SHA_LEN];
};
    

struct rsa_sa : public SignatureBase {
    Hashes hases_;
};


struct dsa_sa : public SignatureBase {
    uint8 sha_[SHA_LEN];
};


struct Signature : public SignatureBase {};


// Server's Diffie-Hellman exchange
class DH_Server : public ServerKeyBase {
    ServerDHParams  parms_;
    opaque          signature_[RSA_KEA_SIG];   // signed rsa_sa hashes MAX size

    int             length_;                // total length of message
    opaque*         keyMessage_;            // total exchange message
public:
    DH_Server() : length_(0), keyMessage_(0) {}
    ~DH_Server() { delete[] keyMessage_; }

    void build(SSL&);
    void read(SSL&, input_buffer&);
    int  get_length() const { return length_; }
    opaque* get_serverKey() const { return keyMessage_; }
private:
    DH_Server(const DH_Server&);            // hide copy
    DH_Server& operator=(const DH_Server&); // and assign
};


// Server's RSA exchange
struct RSA_Server : public ServerKeyBase {
    ServerRSAParams params_;
    opaque          signature_[RSA_KEA_SIG];   // signed rsa_sa hashes
};


class ServerKeyExchange : public HandShakeBase {
    ServerKeyBase* server_key_;
public:
    explicit ServerKeyExchange(SSL& ssl) { createKey(ssl); }
    ServerKeyExchange() : server_key_(0) {}
    ~ServerKeyExchange() { delete server_key_; }

    void createKey(SSL&);
    void build(SSL& ssl) 
    { 
        server_key_->build(ssl); 
        set_length(server_key_->get_length());
    }

    const opaque* getKey()       const { return server_key_->get_serverKey(); }
    int           getKeyLength() const { return server_key_->get_length(); }

    input_buffer&  set(input_buffer& in)         { return in;} // process does
    output_buffer& get(output_buffer& out) const { return out << *this; }

    friend output_buffer& operator<<(output_buffer&, const ServerKeyExchange&);

    void Process(input_buffer&, SSL&);
    HandShakeType get_type() const { return server_key_exchange; };
private:
    ServerKeyExchange(const ServerKeyExchange&);            // hide copy
    ServerKeyExchange& operator=(const ServerKeyExchange&); // and assign
};



struct CertificateRequest : public HandShakeBase  {
    opaque* certificate_types_;
    opaque* certificate_authorities_;
};


struct ServerHelloDone : public HandShakeBase {
    ServerHelloDone() { set_length(0); }
    input_buffer&  set(input_buffer& in)         { return in;}
    output_buffer& get(output_buffer& out) const { return out; }

    void Process(input_buffer& input, SSL& ssl);

    HandShakeType get_type() const { return server_hello_done; };
};


struct PreMasterSecret {
    opaque  random_[SECRET_LEN];     // first two bytes Protocol Version
};


struct ClientKeyBase {
    virtual ~ClientKeyBase() {}
    virtual void build(SSL&) {}
    virtual void read(SSL&, input_buffer&) {}
    virtual int  get_length() const { return 0; }
    virtual opaque* get_clientKey() const { return 0; }
};


class EncryptedPreMasterSecret : public ClientKeyBase {
    opaque* secret_;
    int     length_;
public:
    EncryptedPreMasterSecret() : secret_(0), length_(0) {}
    ~EncryptedPreMasterSecret() { delete[] secret_; }
    void    build(SSL&);
    void    read(SSL&, input_buffer&);
    int     get_length()    const { return length_; }
    opaque* get_clientKey() const { return secret_; }
    void    alloc(int sz) { length_ = sz; secret_ = new opaque[sz]; }
private:
    // hide copy and assign
    EncryptedPreMasterSecret(const EncryptedPreMasterSecret&);           
    EncryptedPreMasterSecret& operator=(const EncryptedPreMasterSecret&);
};


// Fortezza Key Parameters from page 29
// hard code lengths cause only used here
struct FortezzaKeys : public ClientKeyBase {
    opaque  y_c_                      [128];    // client's Yc, public value
    opaque  r_c_                      [128];    // client's Rc
    opaque  y_signature_              [40];     // DSS signed public key
    opaque  wrapped_client_write_key_ [12];     // wrapped by the TEK
    opaque  wrapped_server_write_key_ [12];     // wrapped by the TEK
    opaque  client_write_iv_          [24];      
    opaque  server_write_iv_          [24];
    opaque  master_secret_iv_         [24];     // IV used to encrypt preMaster
    opaque  encrypted_preMasterSecret_[48];     // random & crypted by the TEK
};



// Diffie-Hellman public key from page 40/41
class  ClientDiffieHellmanPublic : public ClientKeyBase {
    PublicValueEncoding public_value_encoding_;
    int     length_;    // includes two byte length for message
    opaque* Yc_;        // length + Yc_
    // dh_Yc only if explicit, otherwise sent in certificate
    enum { KEY_OFFSET = 2 };
public:
    ClientDiffieHellmanPublic() : length_(0), Yc_(0) {}
    ~ClientDiffieHellmanPublic() { delete[] Yc_; }

    void    build(SSL&);
    void    read(SSL&, input_buffer&);
    int     get_length()    const { return length_; }
    opaque* get_clientKey() const { return Yc_; }
    void    alloc(int sz, bool offset = false) 
                { length_ = sz + (offset ? KEY_OFFSET : 0); 
                  Yc_ = new opaque[length_]; }
private:
    // hide copy and assign
    ClientDiffieHellmanPublic(const ClientDiffieHellmanPublic&);
    ClientDiffieHellmanPublic& operator=(const ClientDiffieHellmanPublic&);
};


class ClientKeyExchange : public HandShakeBase {
    ClientKeyBase*  client_key_;
public:
    explicit ClientKeyExchange(SSL& ssl) { createKey(ssl); }
    ClientKeyExchange() : client_key_(0) {}
    ~ClientKeyExchange() { delete client_key_; }

    void createKey(SSL&);
    void build(SSL& ssl) 
    { 
        client_key_->build(ssl); 
        set_length(client_key_->get_length());
    }

    const opaque* getKey()       const { return client_key_->get_clientKey(); }
    int           getKeyLength() const { return client_key_->get_length(); }

    friend output_buffer& operator<<(output_buffer&, const ClientKeyExchange&);
   
    input_buffer&  set(input_buffer& in)         { return in; } // process does
    output_buffer& get(output_buffer& out) const { return out << *this; }

    HandShakeType  get_type() const { return client_key_exchange; };
    void Process(input_buffer&, SSL&);
private:
    ClientKeyExchange(const ClientKeyExchange&);            // hide copy
    ClientKeyExchange& operator=(const ClientKeyExchange&); // and assign
};


struct CertificateVerify : public HandShakeBase {
    Signature signature_;
};


class Finished : public HandShakeBase {
    Hashes hashes_;
public:
    Finished() { set_length(FINISHED_SZ); }

    uint8* set_md5() { return hashes_.md5_; }
    uint8* set_sha() { return hashes_.sha_; }

    friend input_buffer& operator>>(input_buffer&, Finished&);
    friend output_buffer& operator<<(output_buffer&, const Finished&);

    input_buffer&  set(input_buffer& in)         { return in  >> *this;}
    output_buffer& get(output_buffer& out) const { return out << *this; }

    void Process(input_buffer&, SSL&);

    HandShakeType get_type() const { return finished; };
private:
    Finished(const Finished&);            // hide copy
    Finished& operator=(const Finished&); // and assign
};


class RandomPool;  // forward for connection


// SSL Connection defined on page 11
struct Connection {
    opaque          *pre_master_secret_;
    opaque          master_secret_[SECRET_LEN];
    opaque          client_random_[RAN_LEN];
    opaque          server_random_[RAN_LEN];
    opaque          sessionID_[ID_LEN];
    opaque          client_write_MAC_secret_[SHA_LEN]; // sha  is max size
    opaque          server_write_MAC_secret_[SHA_LEN];
    opaque          client_write_key_[DES_EDE_KEY_SZ]; // 3des is max size
    opaque          server_write_key_[DES_EDE_KEY_SZ];
    opaque          client_write_IV_[DES_IV_SZ];       //  des is max size
    opaque          server_write_IV_[DES_IV_SZ];
    uint32          sequence_number_;
    uint32          peer_sequence_number_;
    uint32          pre_secret_len_;                   // pre master length
    bool            send_server_key_;                  // server key exchange?
    bool            dh_init_needed_;                   // server dh init parms
    bool            master_clean_;                     // master secret clean?
    bool            TLS_;                              // TLSv1 or greater
    ProtocolVersion version_;
    RandomPool&     random_;

    Connection(ProtocolVersion v, RandomPool& ran) : pre_master_secret_(0),
        sequence_number_(0), peer_sequence_number_(0), pre_secret_len_(0),
        send_server_key_(false), dh_init_needed_(false), master_clean_(false),
        TLS_(v.major_ >= 3 && v.minor_ >= 1), version_(v), random_(ran) {}

    ~Connection() 
    { 
        CleanMaster(); CleanPreMaster(); delete[] pre_master_secret_;
    }

    void AllocPreSecret(uint sz) 
    { 
        pre_master_secret_ = new opaque[pre_secret_len_ = sz];
    }

    void CleanPreMaster();
    void CleanMaster();
private:
    Connection(const Connection&);              // hide copy
    Connection& operator=(const Connection&);   // and assign
};


// TLSv1 Security Spec, defined on page 56 of RFC 2246
struct Parameters {
    ConnectionEnd        entity_;
    BulkCipherAlgorithm  bulk_cipher_algorithm_;
    CipherType           cipher_type_;
    uint8                key_size_;
    uint8                iv_size_;
    IsExportable         is_exportable_;
    MACAlgorithm         mac_algorithm_;
    uint8                hash_size_;
    CompressionMethod    compression_algorithm_;
    KeyExchangeAlgorithm kea_;                        // yassl additions  
    bool                 pending_; 
    bool                 resumable_;                  // new conns by session
    uint16               encrypt_size_;               // current msg encrypt sz
    Cipher               suite_[SUITE_LEN];           // choosen suite
    uint8                suites_size_;
    Cipher               suites_[MAX_SUITE_SZ];
    char                 cipher_name_[MAX_SUITE_NAME];

    Parameters(ConnectionEnd);
private:
    Parameters(const Parameters&);              // hide copy
    Parameters& operator=(const Parameters&);   // and assing
};


// Message Factory definition
// uses the ContentType enumeration for unique id
typedef Factory<Message> MessageFactory;
void    InitMessageFactory(MessageFactory&);     // registers derived classes

// HandShake Factory definition
// uses the HandShakeType enumeration for unique id
typedef Factory<HandShakeBase> HandShakeFactory;  
void    InitHandShakeFactory(HandShakeFactory&); // registers derived classes

// ServerKey Factory definition
// uses KeyExchangeAlgorithm enumeration for unique  id
typedef Factory<ServerKeyBase> ServerKeyFactory;
void    InitServerKeyFactory(ServerKeyFactory&);

// ClientKey Factory definition
// uses KeyExchangeAlgorithm enumeration for unique  id
typedef Factory<ClientKeyBase> ClientKeyFactory;
void    InitClientKeyFactory(ClientKeyFactory&);


// Message Creators
Message* CreateHandShake();
Message* CreateCipherSpec();
Message* CreateAlert();
Message* CreateData();


// HandShake Creators
HandShakeBase* CreateCertificate();
HandShakeBase* CreateHelloRequest();
HandShakeBase* CreateClientHello();
HandShakeBase* CreateServerHello();
HandShakeBase* CreateServerKeyExchange();
HandShakeBase* CreateCertificateRequest();
HandShakeBase* CreateServerHelloDone();
HandShakeBase* CreateClientKeyExchange();
HandShakeBase* CreateCertificateVerify();
HandShakeBase* CreateFinished();


// ServerKey Exchange Creators
ServerKeyBase* CreateRSAServerKEA();
ServerKeyBase* CreateDHServerKEA();
ServerKeyBase* CreateFortezzaServerKEA();

// ClientKey Exchange Creators
ClientKeyBase* CreateRSAClient();
ClientKeyBase* CreateDHClient();
ClientKeyBase* CreateFortezzaClient();



input_buffer&  operator>>(input_buffer&,  RecordLayerHeader&);
output_buffer& operator<<(output_buffer&, const RecordLayerHeader&);

input_buffer&  operator>>(input_buffer&,  Message&);
output_buffer& operator<<(output_buffer&, const Message&);

input_buffer&  operator>>(input_buffer&,  HandShakeBase&);
output_buffer& operator<<(output_buffer&, const HandShakeBase&);


} // naemspace

#endif // yaSSL_IMP_HPP
