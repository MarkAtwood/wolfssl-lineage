/* yassl_imp.cpp                                
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

/*  yaSSL source implements all SSL.v3 secification structures.
 */

#include "yassl_imp.hpp"
#include "yassl_int.hpp"
#include "handshake.hpp"



// construct key exchange with known ssl parms
void ClientKeyExchange::createKey(SSL& ssl)
{
    const ClientKeyFactory& ckf = ssl.get_factory().clientKeyFactory_;
    client_key_ = ckf.CreateObject(ssl.get_security().kea_);
}


// construct key exchange with known ssl parms
void ServerKeyExchange::createKey(SSL& ssl)
{
    const ServerKeyFactory& skf = ssl.get_factory().serverKeyFactory_;
    server_key_ = skf.CreateObject(ssl.get_security().kea_);
}


// build/set PreMaster secret and encrypt, client side
void EncryptedPreMasterSecret::build(SSL& ssl)
{
    opaque tmp[SECRET_LEN];
    ssl.get_random().Fill(tmp, SECRET_LEN);
    ProtocolVersion pv = ssl.get_connection().version_;
    tmp[0] = pv.major_;
    tmp[1] = pv.minor_;
    ssl.set_preMaster(tmp, SECRET_LEN);

    const CertManager& cert = ssl.get_certManager();
    RSA rsa(cert.get_Key(), cert.get_KeyLength());
    bool tls = ssl.isTLS();     // if TLS, put length for encrypted data
    alloc(rsa.get_cipherLength() + (tls ? 2 : 0));
    byte* holder = secret_;
    if (tls) {
        byte len[2];
        c16toa(rsa.get_cipherLength(), len);
        memcpy(secret_, len, sizeof(len));
        holder += 2;
    }
    rsa.encrypt(holder, tmp, SECRET_LEN, ssl.get_random());
}


// build/set premaster and Client Public key, client side
void ClientDiffieHellmanPublic::build(SSL& ssl)
{
    DiffieHellman& dhServer = ssl.use_dh();
    DiffieHellman  dhClient(dhServer);

    size_t keyLength = dhClient.get_agreedKeyLength(); // pub and agree same

    alloc(keyLength, true);
    dhClient.makeAgreement(dhServer.get_publicKey());
    c16toa(keyLength, Yc_);
    memcpy(Yc_ + KEY_OFFSET, dhClient.get_publicKey(), keyLength);

    ssl.set_preMaster(dhClient.get_agreedKey(), keyLength);
}


// build server exhange, server side
void DH_Server::build(SSL& ssl)
{
    DiffieHellman& dhServer = ssl.use_dh();

    int pSz, gSz, pubSz;
    dhServer.set_sizes(pSz, gSz, pubSz);
    dhServer.get_parms(parms_.alloc_p(pSz), parms_.alloc_g(gSz),
                       parms_.alloc_pub(pubSz));

    length_ = 8; // pLen + gLen + YsLen + SigLen
    length_ += pSz + gSz + pubSz + RSA_KEA_SIG;  // TODO: fix 3X for DSA

    output_buffer tmp(length_);
    byte len[2];
    // P
    c16toa(pSz, len);
    tmp.write(len, sizeof(len));
    tmp.write(parms_.get_p(), pSz);
    // G
    c16toa(gSz, len);
    tmp.write(len, sizeof(len));
    tmp.write(parms_.get_g(), gSz);
    // Ys
    c16toa(pubSz, len);
    tmp.write(len, sizeof(len));
    tmp.write(parms_.get_pub(), pubSz);

    // Sig
    byte sig[RSA_KEA_SIG];
    byte hash[FINISHED_SZ];
    MD5  md5;
    SHA  sha;

    // md5
    md5.update(ssl.get_connection().client_random_, RAN_LEN);
    md5.update(ssl.get_connection().server_random_, RAN_LEN);
    md5.update(tmp.get_buffer(), tmp.get_size());
    md5.get_digest(hash);

    // sha
    sha.update(ssl.get_connection().client_random_, RAN_LEN);
    sha.update(ssl.get_connection().server_random_, RAN_LEN);
    sha.update(tmp.get_buffer(), tmp.get_size());
    sha.get_digest(&hash[MD5_LEN]);

    const CertManager& cert = ssl.get_certManager();
    RSA   rsa(cert.get_privateKey(), cert.get_privateKeyLength(), false);

    rsa.sign(sig, hash, sizeof(hash), ssl.get_random());

    rsa.verify(hash, sizeof(hash), sig, 64);

    c16toa(RSA_KEA_SIG, len);
    tmp.write(len, sizeof(len));
    tmp.write(sig, sizeof(sig));

    // key message
    keyMessage_ = new opaque[length_];
    memcpy(keyMessage_, tmp.get_buffer(), tmp.get_size());
}


// read PreMaster secret and decrypt, server side
void EncryptedPreMasterSecret::read(SSL& ssl, input_buffer& input)
{
    const CertManager& cert = ssl.get_certManager();
    RSA rsa(cert.get_privateKey(), cert.get_privateKeyLength(), false);
    uint16 cipherLen = rsa.get_cipherLength();
    if (ssl.isTLS()) {
        byte len[2];
        input.read(len, sizeof(len));
        ato16(len, cipherLen);
    }
    alloc(cipherLen);
    input.read(secret_, length_);

    opaque preMasterSecret[SECRET_LEN];
    rsa.decrypt(preMasterSecret, secret_, length_, ssl.get_random());

    ssl.set_preMaster(preMasterSecret, SECRET_LEN);
    ssl.makeMasterSecret();
}


// read client's public key, server side
void ClientDiffieHellmanPublic::read(SSL& ssl, input_buffer& input)
{
    DiffieHellman& dh = ssl.use_dh();

    uint16 keyLength;
    byte tmp[2];
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, keyLength);

    alloc(keyLength);
    input.read(Yc_, length_);
    dh.makeAgreement(Yc_);

    ssl.set_preMaster(dh.get_agreedKey(), keyLength);
    ssl.makeMasterSecret();
}


// read server's p, g, public key and sig, client side
void DH_Server::read(SSL& ssl, input_buffer& input)
{
    uint16 length, messageTotal = 6; // pSz + gSz + pubSz
    byte tmp[2];

    // p
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, length);
    messageTotal += length;

    input.read(parms_.alloc_p(length), length);

    // g
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, length);
    messageTotal += length;

    input.read(parms_.alloc_g(length), length);

    // pub
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, length);
    messageTotal += length;

    input.read(parms_.alloc_pub(length), length);

    // save message for hash verify
    input_buffer message(messageTotal);
    input.set_current(input.get_current() - messageTotal);
    input.read(message.get_buffer(), messageTotal);
    message.add_size(messageTotal);

    // signature  assume rsa for now TODO: switch type
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, length);

    input.read(signature_, length);

    // verify signature
    byte hash[FINISHED_SZ];
    MD5  md5;
    SHA  sha;

    // md5
    md5.update(ssl.get_connection().client_random_, RAN_LEN);
    md5.update(ssl.get_connection().server_random_, RAN_LEN);
    md5.update(message.get_buffer(), message.get_size());
    md5.get_digest(hash);

    // sha
    sha.update(ssl.get_connection().client_random_, RAN_LEN);
    sha.update(ssl.get_connection().server_random_, RAN_LEN);
    sha.update(message.get_buffer(), message.get_size());
    sha.get_digest(&hash[MD5_LEN]);

    const CertManager& cert = ssl.get_certManager();
    RSA   rsa(cert.get_Key(), cert.get_KeyLength());

     rsa.verify(hash, sizeof(hash), signature_, length);

    // save input
    ssl.set_dh(new DiffieHellman(parms_.get_p(), parms_.get_pSize(),
               parms_.get_g(), parms_.get_gSize(), parms_.get_pub(),
               parms_.get_pubSize(), ssl.get_random()));
}

//#define FORCE_DIFFIE   // test diffie-hellman

SecurityParameters::SecurityParameters(ConnectionEnd ce) : entity_(ce)
{
    pending_ = true;	// suite not set yet

    int i = 0;
    // available suites, best first

    // Force Diffie test
#ifdef FORCE_DIFFIE
    suites_[i++] = 0x00;
    suites_[i++] = SSL_DHE_RSA_WITH_DES_CBC_SHA;  
    // Normal 
#else
    suites_[i++] = 0x00;
    suites_[i++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;  // TODO: add all
    suites_[i++] = 0x00;
    suites_[i++] = SSL_RSA_WITH_DES_CBC_SHA;
    suites_[i++] = 0x00;
    suites_[i++] = SSL_DHE_RSA_WITH_DES_CBC_SHA;  
    suites_[i++] = 0x00;
    suites_[i++] = SSL_DHE_DSS_WITH_DES_CBC_SHA;  
    suites_[i++] = 0x00;
    suites_[i++] = SSL_RSA_WITH_RC4_128_SHA;  
    suites_[i++] = 0x00;
    suites_[i++] = SSL_RSA_WITH_RC4_128_MD5;
#endif
   
    suites_size_ = i;
}


// input operator for RecordLayerHeader, adjust stream
input_buffer& operator>>(input_buffer& input, RecordLayerHeader& hdr)
{
    hdr.type_ = ContentType(input[AUTO]);
    hdr.version_.major_ = input[AUTO];
    hdr.version_.minor_ = input[AUTO];

    // length
    byte tmp[2];
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, hdr.length_);

    return input;
}


// output operator for RecordLayerHeader
output_buffer& operator<<(output_buffer& output, const RecordLayerHeader& hdr)
{
    output[AUTO] = hdr.type_;
    output[AUTO] = hdr.version_.major_;
    output[AUTO] = hdr.version_.minor_;
    
    // length
    byte tmp[2];
    c16toa(hdr.length_, tmp);
    output[AUTO] = tmp[0];
    output[AUTO] = tmp[1];

    return output;
}


// virtual input operator for Messages
input_buffer& operator>>(input_buffer& input, Message& msg)
{
    return msg.set(input);
}

// virtual output operator for Messages
output_buffer& operator<<(output_buffer& output, const Message& msg)
{
    return msg.get(output);
}


// input operator for HandShakeHeader
input_buffer& operator>>(input_buffer& input, HandShakeHeader& hs)
{
    hs.type_ = HandShakeType(input[AUTO]);

    hs.length_[0] = input[AUTO];
    hs.length_[1] = input[AUTO];
    hs.length_[2] = input[AUTO];
    
    return input;
}


// output operator for HandShakeHeader
output_buffer& operator<<(output_buffer& output, const HandShakeHeader& hdr)
{
    output[AUTO] = hdr.type_;
    output.write(hdr.length_, sizeof(hdr.length_));
    return output;
}


// HandShake Header Processing function
void HandShakeHeader::Process(input_buffer& input, SSL& ssl)
{
    ssl.verifyState(*this);
    const HandShakeFactory& hsf = ssl.get_factory().handShakeFactory_;
    std::auto_ptr<HandShakeBase> hs(hsf.CreateObject(type_));
    hashHandShake(ssl, input, c24to32(length_));

    input >> *hs;
    hs->Process(input, ssl);
}


// input operator for CipherSpec
input_buffer& operator>>(input_buffer& input, ChangeCipherSpec& cs)
{
    cs.type_ = CipherChoice(input[AUTO]);
    return input; 
}

// output operator for CipherSpec
output_buffer& operator<<(output_buffer& output, const ChangeCipherSpec& cs)
{
    output[AUTO] = cs.type_;
    return output;
}


// CipherSpec processing handler
void ChangeCipherSpec::Process(input_buffer& input, SSL& ssl)
{
    ssl.set_security().pending_ = false;
    if (ssl.get_security().entity_ == server_end)
        buildFinished(ssl, ssl.set_verify(), client); // build client verify
}


// input operator for Alert
input_buffer& operator>>(input_buffer& input, Alert& a)
{
    a.level_ = AlertLevel(input[AUTO]);
    a.description_ = AlertDescription(input[AUTO]);
 
    return input;
}


// output operator for Alert
output_buffer& operator<<(output_buffer& output, const Alert& a)
{
    output[AUTO] = a.level_;
    output[AUTO] = a.description_;
    return output;
}


// Alert processing handler
void Alert::Process(input_buffer& input, SSL& ssl)
{
    if (level_ == fatal) {
        ssl.set_states().recordLayer_    = recordNotReady;
        ssl.set_states().handshakeLayer_ = handShakeNotReady;
        throw Error("Fatal Alert", ErrorNumber(description_));
    }
}


// output operator for Data
output_buffer& operator<<(output_buffer& output, const Data& data)
{
    output.write(data.write_buffer_, data.length_);
    return output;
}


// Process handler for Data
void Data::Process(input_buffer& input, SSL& ssl)
{
    int msgSz = ssl.get_security().encrypt_size_;
    int pad   = 0, padByte = 0;
    if (ssl.get_security().cipher_type_ == block) {
        pad = *(input.get_buffer() + input.get_current() + msgSz - 1);
        padByte = 1;
    }
    int digestSz = ssl.get_mac().get_digestSize();
    int dataSz = msgSz - digestSz - pad - padByte;   
    opaque verify[SHA_LEN];

    // read data
    if (dataSz) {
        input_buffer* data;
        ssl.addData(data = new input_buffer(dataSz));
        input.read(data->get_buffer(), dataSz);
        data->add_size(dataSz);

        if (ssl.isTLS())
            TLS_hmac(ssl, verify, data->get_buffer(), dataSz, application_data,
                     true);
        else
            hmac(ssl, verify, data->get_buffer(), dataSz, application_data,
                 true);
    }

    // read mac and fill
    opaque mac[SHA_LEN];
    opaque fill;
    input.read(mac, digestSz);
    for (int i = 0; i < pad; i++) 
        fill = input[AUTO];
    if (padByte)
        fill = input[AUTO];    

    // verify
    if (dataSz) {
        int cmp = memcmp(mac, verify, digestSz);
        assert (cmp == 0);
    }
    else 
        ssl.get_SEQIncrement(true);  // even though no data, increment verify
}


// virtual input operator for HandShakes
input_buffer& operator>>(input_buffer& input, HandShakeBase& hs)
{
    return hs.set(input);
}


// virtual output operator for HandShakes
output_buffer& operator<<(output_buffer& output, const HandShakeBase& hs)
{
    return hs.get(output);
}


Certificate::Certificate(const x509* cert) : cert_(cert) 
{
    set_length(cert_->get_length() + 2 * CERT_HEADER); // list and cert size
}


const opaque* Certificate::get_buffer() const
{
    return cert_->get_buffer(); 
}


// output operator for Certificate
output_buffer& operator<<(output_buffer& output, const Certificate& cert)
{
    size_t sz = cert.get_length() - 2 * CERT_HEADER;
    opaque tmp[CERT_HEADER];

    c32to24(sz + CERT_HEADER, tmp);
    output.write(tmp, CERT_HEADER);
    c32to24(sz, tmp);
    output.write(tmp, CERT_HEADER);
    output.write(cert.get_buffer(), sz);

    return output;
}


// certificate processing handler
void Certificate::Process(input_buffer& input, SSL& ssl)
{
    CertManager& cm = ssl.use_certManager();
  
    uint32 list_sz;
    byte   tmp[3];

    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    tmp[2] = input[AUTO];
    c24to32(tmp, list_sz);
    
    while (list_sz) {
        // cert size
        uint32 cert_sz;
        tmp[0] = input[AUTO];
        tmp[1] = input[AUTO];
        tmp[2] = input[AUTO];
        c24to32(tmp, cert_sz);
        
        x509* myCert;
        cm.AddCert(myCert = new x509(cert_sz));
        input.read(myCert->set_buffer(), myCert->get_length());

        list_sz -= cert_sz + CERT_HEADER;
    }
    cm.SetKey();
    cm.Validate();

    if (ssl.get_security().entity_ == client_end)
        ssl.set_states().clientState_ = serverCertComplete;
    // TODO add server input certificate state and validate
}

// input operator for ServerHello
input_buffer& operator>>(input_buffer& input, ServerHello& hello)
{ 
    // Protocol
    hello.server_version_.major_ = input[AUTO];
    hello.server_version_.minor_ = input[AUTO];
   
    // Random
    input.read(hello.random_, RAN_LEN);
    
    // Session
    hello.id_len_ = input[AUTO];
    input.read(hello.session_id_, ID_LEN);
 
    // Suites
    hello.cipher_suite_[0] = input[AUTO];
    hello.cipher_suite_[1] = input[AUTO];
   
    // Compression
    hello.compression_method_ = CompressionMethod(input[AUTO]);

    return input;
}


// output operator for ServerHello
output_buffer& operator<<(output_buffer& output, const ServerHello& hello)
{
    // Protocol
    output[AUTO] = hello.server_version_.major_;
    output[AUTO] = hello.server_version_.minor_;

    // Random
    output.write(hello.random_, RAN_LEN);

    // Session
    output[AUTO] = hello.id_len_;
    output.write(hello.session_id_, ID_LEN);

    // Suites
    output[AUTO] = hello.cipher_suite_[0];
    output[AUTO] = hello.cipher_suite_[1];

    // Compression
    output[AUTO] = hello.compression_method_;

    return output;
}


// Server Hello processing handler
void ServerHello::Process(input_buffer& input, SSL& ssl)
{
    ssl.set_pending(cipher_suite_[1]);
    ssl.set_random(random_, server_end);
    ssl.set_sessionID(session_id_);

    ssl.set_states().clientState_ = serverHelloComplete;
}



// Server Hello Done processing handler
void ServerHelloDone::Process(input_buffer& input, SSL& ssl)
{
    ssl.set_states().clientState_ = serverHelloDoneComplete;
}


// input operator for Client Hello
input_buffer& operator>>(input_buffer& input, ClientHello& hello)
{
    // Protocol
    hello.client_version_.major_ = input[AUTO];
    hello.client_version_.minor_ = input[AUTO];

    // Random
    input.read(hello.random_, RAN_LEN);

    // Session
    hello.id_len_ = input[AUTO];
    if (hello.id_len_) input.read(hello.session_id_, ID_LEN);

    // Suites
    byte tmp[2];
    tmp[0] = input[AUTO];
    tmp[1] = input[AUTO];
    ato16(tmp, hello.suite_len_);
    input.read(hello.cipher_suites_, hello.suite_len_);

    // Compression
    hello.comp_len_ = input[AUTO];
    hello.compression_methods_ = CompressionMethod(input[AUTO]);

    return input;
}


// output operaotr for Client Hello
output_buffer& operator<<(output_buffer& output, const ClientHello& hello)
{ 
    // Protocol
    output[AUTO] = hello.client_version_.major_;
    output[AUTO] = hello.client_version_.minor_;

    // Random
    output.write(hello.random_, RAN_LEN);

    // Session
    output[AUTO] = hello.id_len_;
    if (hello.id_len_) output.write(hello.session_id_, ID_LEN);

    // Suites
    byte tmp[2];
    c16toa(hello.suite_len_, tmp);
    output[AUTO] = tmp[0];
    output[AUTO] = tmp[1];
    output.write(hello.cipher_suites_, hello.suite_len_);
  
    // Compression
    output[AUTO] = hello.comp_len_;
    output[AUTO] = hello.compression_methods_;

    return output;
}


// Client Hello processing handler
void ClientHello::Process(input_buffer& input, SSL& ssl)
{
    ssl.matchSuite(cipher_suites_, suite_len_);

    // store
    ssl.set_random(random_, client_end);
    ssl.set_pending(ssl.get_security().suite_[1]);

    // process
    if (ssl.get_connection().dh_init_needed_)
        ssl.init_dh();

    ssl.set_states().serverState_ = clientHelloComplete;
}


// output operator for ServerKeyExchange
output_buffer& operator<<(output_buffer& output, const ServerKeyExchange& sk)
{
    output.write(sk.getKey(), sk.getKeyLength());
    return output;
}


// Server Key Exchange processing handler
void ServerKeyExchange::Process(input_buffer& input, SSL& ssl)
{
    createKey(ssl);
    server_key_->read(ssl, input);

    ssl.set_states().clientState_ = serverKeyExchangeComplete;
}


// output operator for ClientKeyExchange
output_buffer& operator<<(output_buffer& output, const ClientKeyExchange& ck)
{
    output.write(ck.getKey(), ck.getKeyLength());
    return output;
}


// Client Key Exchange processing handler
void ClientKeyExchange::Process(input_buffer& input, SSL& ssl)
{
    createKey(ssl);
    client_key_->read(ssl, input);

    ssl.set_states().serverState_ = clientKeyExchangeComplete;
}


// input operator for Finished
input_buffer& operator>>(input_buffer& input, Finished& fin)
{
    /*  do in process
    input.read(fin.hashes_.md5_, MD5_LEN);
    input.read(fin.hashes_.sha_, SHA_LEN);
    */

    return input; 
}

// output operator for Finished
output_buffer& operator<<(output_buffer& output, const Finished& fin)
{
    if (fin.get_length() == FINISHED_SZ) {
        output.write(fin.hashes_.md5_, MD5_LEN);
        output.write(fin.hashes_.sha_, SHA_LEN);
    }
    else    // TLS_FINISHED_SZ
        output.write(fin.hashes_.md5_, TLS_FINISHED_SZ);

    return output;
}


// Finished processing handler
void Finished::Process(input_buffer& input, SSL& ssl)
{
    // verify hashes
    const  Finished& verify = ssl.get_verify();
    size_t finishedSz = ssl.isTLS() ? TLS_FINISHED_SZ : FINISHED_SZ;

    input.read(hashes_.md5_, finishedSz);

    int    cmp = memcmp(&hashes_, &verify.hashes_, finishedSz);
    assert(cmp == 0);

    // read verify mac
    opaque verifyMAC[SHA_LEN];
    size_t macSz = finishedSz + HANDSHAKE_HEADER;

    if (ssl.isTLS())
        TLS_hmac(ssl, verifyMAC, input.get_buffer() + input.get_current()
                 - macSz, macSz, handshake, true);
    else
        hmac(ssl, verifyMAC, input.get_buffer() + input.get_current() - macSz,
             macSz, handshake, true);

    // read mac and fill
    opaque mac[SHA_LEN];   // max size
    int    digestSz = ssl.get_mac().get_digestSize();
    input.read(mac, digestSz);

    opaque fill;
    int    padSz = ssl.get_security().encrypt_size_ - HANDSHAKE_HEADER -
                                                      finishedSz - digestSz;
    for (int i = 0; i < padSz; i++) 
        fill = input[AUTO];

    // verify mac
    cmp = memcmp(mac, verifyMAC, digestSz);
    assert (cmp == 0);

    // update states
    ssl.set_states().handshakeLayer_ = handshakeReady;
    if (ssl.get_security().entity_ == client_end)
        ssl.set_states().clientState_ = serverFinishedComplete;
    else
        ssl.set_states().serverState_ = clientFinishedComplete;
}


// Create functions for message factory
Message* CreateCipherSpec() { return new ChangeCipherSpec; }
Message* CreateAlert()      { return new Alert; }
Message* CreateHandShake()  { return new HandShakeHeader; }
Message* CreateData()       { return new Data; }

// Create functions for handshake factory
HandShakeBase* CreateHelloRequest()       { return new HelloRequest; }
HandShakeBase* CreateClientHello()        { return new ClientHello; }
HandShakeBase* CreateServerHello()        { return new ServerHello; }
HandShakeBase* CreateCertificate()        { return new Certificate; }
HandShakeBase* CreateServerKeyExchange()  { return new ServerKeyExchange; }
HandShakeBase* CreateCertificateRequest() { return new CertificateRequest; }
HandShakeBase* CreateServerHelloDone()    { return new ServerHelloDone; }
HandShakeBase* CreateCertificateVerify()  { return new CertificateVerify; }
HandShakeBase* CreateClientKeyExchange()  { return new ClientKeyExchange; }
HandShakeBase* CreateFinished()           { return new Finished; }

// Create functions for server key exchange factory
ServerKeyBase* CreateRSAServerKEA()       { return new RSA_Server; }
ServerKeyBase* CreateDHServerKEA()        { return new DH_Server; }
ServerKeyBase* CreateFortezzaServerKEA()  { return new Fortezza_Server; }

// Create functions for client key exchange factory
ClientKeyBase* CreateRSAClient()      { return new EncryptedPreMasterSecret; }
ClientKeyBase* CreateDHClient()       { return new ClientDiffieHellmanPublic; }
ClientKeyBase* CreateFortezzaClient() { return new FortezzaKeys; }
