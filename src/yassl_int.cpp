/* yassl_int.cpp                                
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


/* yaSSL internal source implements SSL supporting types not specified in the
 * draft along with type conversion functions.
 */


#include "yassl_int.hpp"
#include "handshake.hpp"



// convert a 32 bit integer into a 24 bit one
void c32to24(uint32 u32, uint24& u24)
{
    u24[0] = (u32 >> 16) & 0xff;
    u24[1] = (u32 >>  8) & 0xff;
    u24[2] =  u32 & 0xff;
}


// convert a 24 bit integer into a 32 bit one
void c24to32(const uint24 u24, uint32& u32)
{
    u32 = 0;
    u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}


// convert with return for ease of use
uint32 c24to32(const uint24 u24)
{
    uint32 ret;
    c24to32(u24, ret);

    return ret;
}


// using a for opaque since underlying type is unsgined char and o is not a
// good leading identifier

// convert opaque to 16 bit integer
void ato16(const opaque* c, uint16& u16)
{
    u16 = 0;
    u16 = (c[0] << 8) | (c[1]);
}


// convert (copy) opaque to 24 bit integer
void ato24(const opaque* c, uint24& u24)
{
    u24[0] = c[0];
    u24[1] = c[1];
    u24[2] = c[2];
}


// convert 16 bit integer to opaque
void c16toa(uint16 u16, opaque* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}


// convert 24 bit integer to opaque
void c24toa(const uint24 u24, opaque* c)
{
    c[0] =  u24[0]; 
    c[1] =  u24[1];
    c[2] =  u24[2];
}


// convert 32 bit integer to opaque
void c32toa(uint32 u32, opaque* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


SSL::SSL(SSL_CTX* ctx) : connection_(ctx->method_->version_),
    securityParms_(ctx->method_->side_), mac_(0), cipher_(0), dh_(0)
{
    if (securityParms_.entity_ == server_end) {
        cert_.CopyCert(ctx->getCert());    
        if (!ctx->privateKey_)
            throw Error("No Server Key File", no_key_file);
        cert_.SetPrivateKey(*ctx->privateKey_);
    }
}

void delHandShake(output_buffer* hs) { delete hs; }

SSL::~SSL() 
{ 
    delete dh_;
    delete cipher_; 
    delete mac_; 
    std::for_each(handShakeList_.begin(), handShakeList_.end(), delHandShake);
    std::for_each(dataList_.begin(), dataList_.end(), deleteData) ; 
}


// store pending security parameters from Server Hello
void SSL::set_pending(Cipher suite)
{
    // TODO: add all suites

    switch (suite) {

    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
        securityParms_.bulk_cipher_algorithm_ = triple_des;
        securityParms_.mac_algorithm_         = sha;
        securityParms_.kea_                   = rsa_kea;
        securityParms_.hash_size_ = SHA_LEN;
        securityParms_.key_size_  = DES_EDE_KEY_SZ;
        securityParms_.iv_size_   = DES_IV_SZ;
        securityParms_.cipher_type_ = block;
        mac_ = new SHA;
        cipher_ = new DES_EDE;
        strncpy(securityParms_.cipher_name_, "DES-CBC3-SHA",
                MAX_SUITE_NAME);
        break;

    case SSL_RSA_WITH_DES_CBC_SHA:
        securityParms_.bulk_cipher_algorithm_ = des;
        securityParms_.mac_algorithm_         = sha;
        securityParms_.kea_                   = rsa_kea;
        securityParms_.hash_size_ = SHA_LEN;
        securityParms_.key_size_  = DES_KEY_SZ;
        securityParms_.iv_size_   = DES_IV_SZ;
        securityParms_.cipher_type_ = block;
        mac_ = new SHA;
        cipher_ = new DES;
        strncpy(securityParms_.cipher_name_, "DES-CBC-SHA",
                MAX_SUITE_NAME);
        break;

    case SSL_RSA_WITH_RC4_128_SHA:
        securityParms_.bulk_cipher_algorithm_ = rc4;
        securityParms_.mac_algorithm_         = sha;
        securityParms_.kea_                   = rsa_kea;
        securityParms_.hash_size_ = SHA_LEN;
        securityParms_.key_size_  = RC4_KEY_SZ;
        securityParms_.iv_size_   = 0;
        securityParms_.cipher_type_ = stream;
        mac_ = new SHA;
        cipher_ = new RC4;
        strncpy(securityParms_.cipher_name_, "RC4-SHA",
                MAX_SUITE_NAME);
        break;

    case SSL_RSA_WITH_RC4_128_MD5:
        securityParms_.bulk_cipher_algorithm_ = rc4;
        securityParms_.mac_algorithm_         = md5;
        securityParms_.kea_                   = rsa_kea;
        securityParms_.hash_size_ = MD5_LEN;
        securityParms_.key_size_  = RC4_KEY_SZ;
        securityParms_.iv_size_   = 0;
        securityParms_.cipher_type_ = stream;
        mac_ = new MD5;
        cipher_ = new RC4;
        strncpy(securityParms_.cipher_name_, "RC4-MD5",
                MAX_SUITE_NAME);
        break;

    case SSL_DHE_RSA_WITH_DES_CBC_SHA:
        securityParms_.bulk_cipher_algorithm_ = des;
        securityParms_.mac_algorithm_         = sha;
        securityParms_.kea_                   = diffie_hellman_kea;
        securityParms_.hash_size_ = SHA_LEN;
        securityParms_.key_size_  = DES_KEY_SZ;
        securityParms_.iv_size_   = DES_IV_SZ;
        securityParms_.cipher_type_ = block;
        connection_.send_server_key_ = true;    // ephemeral setting
        connection_.dh_init_needed_  = true;    // read dh parms
        mac_ = new SHA;
        cipher_ = new DES;
        strncpy(securityParms_.cipher_name_, "EDH-RSA-DES-CBC-SHA",
                MAX_SUITE_NAME);
        break;

    default:
        throw Error("UnKnown CipherSuite", unknown_cipher);
    }
}


// store peer's random
void SSL::set_random(const opaque* random, ConnectionEnd sender)
{
    if (sender == client_end)
        memcpy(connection_.client_random_, random, RAN_LEN);
    else
        memcpy(connection_.server_random_, random, RAN_LEN);
}


// store client pre master secret
void SSL::set_preMaster(const opaque* pre, size_t sz)
{
    connection_.AllocSecret(sz);
    memcpy(connection_.pre_master_secret_, pre, sz);
}

// store server issued id
void SSL::set_sessionID(const opaque* sessionID)
{
    memcpy(connection_.sessionID_, sessionID, ID_LEN);
}


// store error 
void SSL::set_error(const Error& e)
{
    states_.errorNumber_ = e.get_number();
    states_.errorString_ = e.what();
}


// DeriveKeys and MasterSecret helper sets prefix letters
static void setPrefix(output_buffer& sha_input, int i)
{
    opaque buffer[8];

    switch (i) {
    case 0:
        memcpy(buffer, "A", 1);
        break;
    case 1:
        memcpy(buffer, "BB", 2);
        break;
    case 2:
        memcpy(buffer, "CCC", 3);
        break;
    case 3:
        memcpy(buffer, "DDDD", 4);
        break;
    case 4:
        memcpy(buffer, "EEEEE", 5);
        break;
    case 5:
        memcpy(buffer, "FFFFFF", 6);
        break;
    case 6:
        memcpy(buffer, "GGGGGGG", 7);
        break;
    default:
        throw Error("Bad prefix index", prefix_error);
    }  
    sha_input.write(buffer, i + 1);
}


// Create and store the master secret see page 32, 6.1
void SSL::makeMasterSecret()
{
    if (isTLS())
        makeTLSMasterSecret();
    else {
        opaque sha_output[SHA_LEN];

        size_t        secretLen = connection_.secret_len_;
        output_buffer md5_input(secretLen + SHA_LEN);
        output_buffer sha_input(PREFIX + secretLen + 2 * RAN_LEN);

        MD5 md5;
        SHA sha;

        md5_input.write(connection_.pre_master_secret_, secretLen);

        for (int i = 0; i < MASTER_ROUNDS; ++i) {
            sha_input.set_current(0);
            setPrefix(sha_input, i);
            sha_input.write(connection_.pre_master_secret_, secretLen);
            sha_input.write(connection_.client_random_, RAN_LEN);
            sha_input.write(connection_.server_random_, RAN_LEN);
            sha.get_digest(sha_output, sha_input.get_buffer(),
                           sha_input.get_size());

            md5_input.set_current(secretLen);
            md5_input.write(sha_output, SHA_LEN);
            md5.get_digest(&connection_.master_secret_[i * MD5_LEN],
                           md5_input.get_buffer(), md5_input.get_size());
        }
        deriveKeys();
    }
}


void SSL::makeTLSMasterSecret()
{
    opaque seed[SEED_LEN];
    size_t secretLen = connection_.secret_len_;
    
    memcpy(seed, connection_.client_random_, RAN_LEN);
    memcpy(&seed[RAN_LEN], connection_.server_random_, RAN_LEN);

    PRF(connection_.master_secret_, SECRET_LEN, connection_.pre_master_secret_,
        secretLen, master_label, MASTER_LABEL_SZ, seed, SEED_LEN);

    deriveTLSKeys();
}


// derive mac, write, and iv keys for server and client, see page 34, 6.2.2
void SSL::deriveKeys()
{
    int length = 2 * securityParms_.hash_size_ + 
                 2 * securityParms_.key_size_  +
                 2 * securityParms_.iv_size_;
    int rounds = length / MD5_LEN + ((length % MD5_LEN) ? 1 : 0);
    input_buffer key_data(rounds * MD5_LEN);

    opaque sha_output[SHA_LEN];

    //size_t        secretLen = connection_.secret_len_; // NEWTAO always 48
    size_t        secretLen = SECRET_LEN;
    output_buffer md5_input(secretLen + SHA_LEN);
    output_buffer sha_input(KEY_PREFIX + secretLen + 2 * RAN_LEN);
  
    MD5 md5;
    SHA sha;

    md5_input.write(connection_.master_secret_, secretLen);

    for (int i = 0; i < rounds; ++i) {
        sha_input.set_current(0);
        setPrefix(sha_input, i);
        sha_input.write(connection_.master_secret_, secretLen);
        sha_input.write(connection_.server_random_, RAN_LEN);
        sha_input.write(connection_.client_random_, RAN_LEN);
        sha.get_digest(sha_output, sha_input.get_buffer(),
                       sha_input.get_size());

        md5_input.set_current(secretLen);
        md5_input.write(sha_output, SHA_LEN);
        md5.get_digest(key_data.get_buffer() + i * MD5_LEN,
                       md5_input.get_buffer(), md5_input.get_size());
    }
    storeKeys(key_data.get_buffer());
}


void SSL::deriveTLSKeys()
{
    int length = 2 * securityParms_.hash_size_ + 
                 2 * securityParms_.key_size_  +
                 2 * securityParms_.iv_size_;
    opaque       seed[SEED_LEN];
    input_buffer key_data(length);

    memcpy(seed, connection_.server_random_, RAN_LEN);
    memcpy(&seed[RAN_LEN], connection_.client_random_, RAN_LEN);

    PRF(key_data.get_buffer(), length, connection_.master_secret_,
        SECRET_LEN, key_label, KEY_LABEL_SZ, seed, SEED_LEN);

    storeKeys(key_data.get_buffer());
}


// store mac, write, and iv keys for client and server
void SSL::storeKeys(const opaque* key_data)
{
    int sz = securityParms_.hash_size_;
    memcpy(connection_.client_write_MAC_secret_, key_data, sz);
    int i = sz;
    memcpy(connection_.server_write_MAC_secret_, &key_data[i], sz);
    i += sz;

    sz = securityParms_.key_size_;
    memcpy(connection_.client_write_key_, &key_data[i], sz);
    i += sz;
    memcpy(connection_.server_write_key_, &key_data[i], sz);
    i += sz;

    sz = securityParms_.iv_size_;
    memcpy(connection_.client_write_IV_, &key_data[i], sz);
    i += sz;
    memcpy(connection_.server_write_IV_, &key_data[i], sz);

    setKeys();
}


void SSL::setKeys()
{
    if (securityParms_.entity_ == client_end) {
        cipher_->set_encryptKey(connection_.client_write_key_, 
                                connection_.client_write_IV_);
        cipher_->set_decryptKey(connection_.server_write_key_,
                                connection_.server_write_IV_);
    }
    else {
       cipher_->set_encryptKey(connection_.server_write_key_, 
                               connection_.server_write_IV_);
       cipher_->set_decryptKey(connection_.client_write_key_,
                               connection_.client_write_IV_);
    }
}


struct SumData {
    size_t total_;
    SumData() : total_(0) {}
    void operator()(input_buffer* data) { total_ += data->get_remaining(); }
};


size_t SSL::bufferedData()
{
    return std::for_each(dataList_.begin(), dataList_.end(), SumData()).total_;
}


#ifdef min
#undef min
#endif 

template<typename T>
inline T min(T a, T b)
{
    return a < b ? a : b;
}



void SSL::fillData(Data& data)
{   
    size_t dataSz   = data.get_length();        // input, data size to fill
    size_t elements = dataList_.size();

    data.set_length(0);                         // output, actual data filled
    dataSz = min(dataSz, bufferedData());

    for (size_t i = 0; i < elements; i++) {
        input_buffer* front = dataList_.front();
        size_t frontSz = front->get_remaining();
        size_t readSz  = min(dataSz - data.get_length(), frontSz);

        front->read(data.set_buffer() + data.get_length(), readSz);
        data.set_length(data.get_length() + readSz);

        if (readSz == frontSz) {
            dataList_.pop_front();
            delete front;
        }
        if (data.get_length() == dataSz)
            break;
    }
}


struct SumBuffer {
    size_t total_;
    SumBuffer() : total_(0) {}
    void operator()(output_buffer* buffer) { total_ += buffer->get_size(); }
};


void SSL::flushBuffer()
{
    size_t sz = std::for_each(handShakeList_.begin(), handShakeList_.end(),
                              SumBuffer()).total_;
    output_buffer out(sz);
    size_t elements = handShakeList_.size();

    for (size_t i = 0; i < elements; i++) {
        output_buffer* front = handShakeList_.front();
        out.write(front->get_buffer(), front->get_size());

        handShakeList_.pop_front();
        delete front;
    }
    socket_.send(out.get_buffer(), out.get_size());
}


size_t SSL::get_SEQIncrement(bool verify) 
{ 
    if (verify)
        return connection_.peer_sequence_number_++; 
    else
        return connection_.sequence_number_++; 
}


const byte* SSL::get_macSecret(bool verify)
{
    if ( (securityParms_.entity_ == client_end && !verify) ||
         (securityParms_.entity_ == server_end &&  verify) )
        return connection_.client_write_MAC_secret_;
    else
        return connection_.server_write_MAC_secret_;
}


static const char handshake_order[] = "Out of order HandShake Message!";

static void order_error()
{
    throw Error(handshake_order, out_of_order);
}


void SSL::verifyState(const RecordLayerHeader& rlHeader)
{
    if (states_.recordLayer_ == recordNotReady || 
            (rlHeader.type_ == application_data &&        // data and handshake
             states_.handshakeLayer_ != handShakeReady) ) // isn't complete yet
              throw Error("RecordLayer read after fatal error!", record_layer);
}


void SSL::verifyState(const HandShakeHeader& hsHeader)
{
    if (states_.handshakeLayer_ == handShakeNotReady)
        throw Error("HandShake read after fatal error!", handshake_layer);

    if (securityParms_.entity_ == client_end)
        verifyClientState(hsHeader.get_handshakeType());
    else
        verifyServerState(hsHeader.get_handshakeType());
}


void SSL::verifyState(ClientState cs)
{
    if (states_.clientState_ != cs) order_error();
}


void SSL::verifyState(ServerState ss)
{
    if (states_.serverState_ != ss) order_error();
}


void SSL::verfiyHandShakeComplete()
{
    if (states_.handshakeLayer_ != handShakeReady) order_error();
}


void SSL::verifyClientState(HandShakeType hsType)
{
    switch(hsType) {
    case server_hello :
        if (states_.clientState_ != serverNull)
            order_error();
        break;
    case certificate :
        if (states_.clientState_ != serverHelloComplete)
            order_error();
        break;
    case server_key_exchange :
        if (states_.clientState_ != serverCertComplete)
            order_error();
        break;
    case server_hello_done :
        if (states_.clientState_ != serverCertComplete &&
            states_.clientState_ != serverKeyExchangeComplete)
            order_error();
        break;
    case finished :
        if (states_.clientState_ != serverHelloDoneComplete || 
            securityParms_.pending_)    // no change
                order_error();          // cipher yet
        break;
    default :
        order_error();
    };
}


void SSL::verifyServerState(HandShakeType hsType)
{
    switch(hsType) {
    case client_hello :
        if (states_.serverState_ != clientNull)
            order_error();
        break;
    case client_key_exchange :
        if (states_.serverState_ != clientHelloComplete)
            order_error();
        break;
    case finished :
        if (states_.serverState_ != clientKeyExchangeComplete || 
            securityParms_.pending_)    // no change
                order_error();          // cipher yet
        break;
    default :
        order_error();
    };
}


void SSL::matchSuite(const opaque* peer, size_t length)
{
    if (length == 0 || (length % 2) != 0)
        throw Error("Bad suite input", bad_input);

    // start with best, if a match we are good, Ciphers are at odd index
    // since all SSL and TLS ciphers have 0x00 first byte
    for (size_t i = 1; i < securityParms_.suites_size_; i += 2)
        for(size_t j = 1; j < length; j+= 2)
            if (securityParms_.suites_[i] == peer[j]) {
                securityParms_.suite_[0] = 0x00;
                securityParms_.suite_[1] = peer[j];
                return;
        }

    throw Error("No suite match", match_error);
}


