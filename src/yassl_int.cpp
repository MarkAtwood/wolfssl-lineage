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
#include "timer.hpp"


namespace yaSSL {


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


SSL::SSL(SSL_CTX* ctx) 
    : secure_(ctx->getMethod()->getVersion(), crypto_.use_random(),
              ctx->getMethod()->getSide())
{
    if (secure_.use_parms().entity_ == server_end) {
        crypto_.use_certManager().CopyCert(ctx->getCert());    
        if (!ctx->getKey())
            throw Error("No Server Key File", no_key_file);
        crypto_.use_certManager().SetPrivateKey(*ctx->getKey());
    }
}


// store pending security parameters from Server Hello
void SSL::set_pending(Cipher suite)
{
    // TODO: add all suites
    Parameters& parms = secure_.use_parms();

    switch (suite) {

    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
        parms.bulk_cipher_algorithm_ = triple_des;
        parms.mac_algorithm_         = sha;
        parms.kea_                   = rsa_kea;
        parms.hash_size_ = SHA_LEN;
        parms.key_size_  = DES_EDE_KEY_SZ;
        parms.iv_size_   = DES_IV_SZ;
        parms.cipher_type_ = block;
        crypto_.setMAC(new SHA);
        crypto_.setCipher(new DES_EDE);
        strncpy(parms.cipher_name_, "DES-CBC3-SHA",
                MAX_SUITE_NAME);
        break;

    case SSL_RSA_WITH_DES_CBC_SHA:
        parms.bulk_cipher_algorithm_ = des;
        parms.mac_algorithm_         = sha;
        parms.kea_                   = rsa_kea;
        parms.hash_size_ = SHA_LEN;
        parms.key_size_  = DES_KEY_SZ;
        parms.iv_size_   = DES_IV_SZ;
        parms.cipher_type_ = block;
        crypto_.setMAC(new SHA);
        crypto_.setCipher(new DES);
        strncpy(parms.cipher_name_, "DES-CBC-SHA",
                MAX_SUITE_NAME);
        break;

    case SSL_RSA_WITH_RC4_128_SHA:
        parms.bulk_cipher_algorithm_ = rc4;
        parms.mac_algorithm_         = sha;
        parms.kea_                   = rsa_kea;
        parms.hash_size_ = SHA_LEN;
        parms.key_size_  = RC4_KEY_SZ;
        parms.iv_size_   = 0;
        parms.cipher_type_ = stream;
        crypto_.setMAC(new SHA);
        crypto_.setCipher(new RC4);
        strncpy(parms.cipher_name_, "RC4-SHA",
                MAX_SUITE_NAME);
        break;

    case SSL_RSA_WITH_RC4_128_MD5:
        parms.bulk_cipher_algorithm_ = rc4;
        parms.mac_algorithm_         = md5;
        parms.kea_                   = rsa_kea;
        parms.hash_size_ = MD5_LEN;
        parms.key_size_  = RC4_KEY_SZ;
        parms.iv_size_   = 0;
        parms.cipher_type_ = stream;
        crypto_.setMAC(new MD5);
        crypto_.setCipher(new RC4);
        strncpy(parms.cipher_name_, "RC4-MD5",
                MAX_SUITE_NAME);
        break;

    case SSL_DHE_RSA_WITH_DES_CBC_SHA:
        parms.bulk_cipher_algorithm_ = des;
        parms.mac_algorithm_         = sha;
        parms.kea_                   = diffie_hellman_kea;
        parms.hash_size_ = SHA_LEN;
        parms.key_size_  = DES_KEY_SZ;
        parms.iv_size_   = DES_IV_SZ;
        parms.cipher_type_ = block;
        secure_.use_connection().send_server_key_ = true; // eph
        secure_.use_connection().dh_init_needed_  = true; 
        crypto_.setMAC(new SHA);
        crypto_.setCipher(new DES);
        strncpy(parms.cipher_name_, "EDH-RSA-DES-CBC-SHA",
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
        memcpy(secure_.use_connection().client_random_, random, RAN_LEN);
    else
        memcpy(secure_.use_connection().server_random_, random, RAN_LEN);
}


// store client pre master secret
void SSL::set_preMaster(const opaque* pre, uint sz)
{
    secure_.use_connection().AllocPreSecret(sz);
    memcpy(secure_.use_connection().pre_master_secret_, pre, sz);
}


// store master secret
void SSL::set_masterSecret(const opaque* sec)
{
    memcpy(secure_.use_connection().master_secret_, sec, SECRET_LEN);
}

// store server issued id
void SSL::set_sessionID(const opaque* sessionID)
{
    memcpy(secure_.use_connection().sessionID_, sessionID, ID_LEN);
}


// store error 
void SSL::set_error(const Error& e)
{
    states_.useNumber() = e.get_number();
    states_.useString() = e.what();
}


// default Diffie-Hellman init
void SSL::init_dh()
{ 
    // TODO: set input file or callback
    crypto_.setDH(new DiffieHellman("../../certs/dh1024.dat",
                                    crypto_.get_random()));
}


// locals
namespace {

// DeriveKeys and MasterSecret helper sets prefix letters
static void setPrefix(opaque* sha_input, int i)
{
    switch (i) {
    case 0:
        memcpy(sha_input, "A", 1);
        break;
    case 1:
        memcpy(sha_input, "BB", 2);
        break;
    case 2:
        memcpy(sha_input, "CCC", 3);
        break;
    case 3:
        memcpy(sha_input, "DDDD", 4);
        break;
    case 4:
        memcpy(sha_input, "EEEEE", 5);
        break;
    case 5:
        memcpy(sha_input, "FFFFFF", 6);
        break;
    case 6:
        memcpy(sha_input, "GGGGGGG", 7);
        break;
    default:
        throw Error("Bad prefix index", prefix_error);
    }   
}


const char handshake_order[] = "Out of order HandShake Message!";

void order_error()
{
    throw Error(handshake_order, out_of_order);
}

} // namespcae for locals


// Create and store the master secret see page 32, 6.1
void SSL::makeMasterSecret()
{
    if (isTLS())
        makeTLSMasterSecret();
    else {
        opaque sha_output[SHA_LEN];

        const uint& preSz = secure_.get_connection().pre_secret_len_;
        output_buffer md5_input(preSz + SHA_LEN);
        output_buffer sha_input(PREFIX + preSz + 2 * RAN_LEN);

        MD5 md5;
        SHA sha;

        md5_input.write(secure_.get_connection().pre_master_secret_, preSz);

        for (int i = 0; i < MASTER_ROUNDS; ++i) {
            opaque prefix[PREFIX];
            setPrefix(prefix, i);

            sha_input.set_current(0);
            sha_input.write(prefix, i + 1);

            sha_input.write(secure_.get_connection().pre_master_secret_,preSz);
            sha_input.write(secure_.get_connection().client_random_, RAN_LEN);
            sha_input.write(secure_.get_connection().server_random_, RAN_LEN);
            sha.get_digest(sha_output, sha_input.get_buffer(),
                           sha_input.get_size());

            md5_input.set_current(preSz);
            md5_input.write(sha_output, SHA_LEN);
            md5.get_digest(&secure_.use_connection().master_secret_[i*MD5_LEN],
                           md5_input.get_buffer(), md5_input.get_size());
        }
        deriveKeys();
    }
    secure_.use_connection().CleanPreMaster();
}


void SSL::makeTLSMasterSecret()
{
    opaque seed[SEED_LEN];
    
    memcpy(seed, secure_.get_connection().client_random_, RAN_LEN);
    memcpy(&seed[RAN_LEN], secure_.get_connection().server_random_, RAN_LEN);

    PRF(secure_.use_connection().master_secret_, SECRET_LEN,
        secure_.get_connection().pre_master_secret_,
        secure_.get_connection().pre_secret_len_,
        master_label, MASTER_LABEL_SZ, 
        seed, SEED_LEN);

    deriveTLSKeys();
}


// derive mac, write, and iv keys for server and client, see page 34, 6.2.2
void SSL::deriveKeys()
{
    int length = 2 * secure_.get_parms().hash_size_ + 
                 2 * secure_.get_parms().key_size_  +
                 2 * secure_.get_parms().iv_size_;
    int rounds = length / MD5_LEN + ((length % MD5_LEN) ? 1 : 0);
    input_buffer key_data(rounds * MD5_LEN);

    opaque sha_output[SHA_LEN];
    opaque md5_input[SECRET_LEN + SHA_LEN];
    opaque sha_input[KEY_PREFIX + SECRET_LEN + 2 * RAN_LEN];
  
    MD5 md5;
    SHA sha;

    memcpy(md5_input, secure_.get_connection().master_secret_, SECRET_LEN);

    for (int i = 0; i < rounds; ++i) {
        int j = i + 1;
        setPrefix(sha_input, i);

        memcpy(&sha_input[j], secure_.get_connection().master_secret_,
               SECRET_LEN);
        memcpy(&sha_input[j+SECRET_LEN],
               secure_.get_connection().server_random_, RAN_LEN);
        memcpy(&sha_input[j + SECRET_LEN + RAN_LEN],
               secure_.get_connection().client_random_, RAN_LEN);
        sha.get_digest(sha_output, sha_input,
                       sizeof(sha_input) - KEY_PREFIX + j);

        memcpy(&md5_input[SECRET_LEN], sha_output, SHA_LEN);
        md5.get_digest(key_data.get_buffer() + i * MD5_LEN,
                       md5_input, sizeof(md5_input));
    }
    storeKeys(key_data.get_buffer());
}


void SSL::deriveTLSKeys()
{
    int length = 2 * secure_.get_parms().hash_size_ + 
                 2 * secure_.get_parms().key_size_  +
                 2 * secure_.get_parms().iv_size_;
    opaque       seed[SEED_LEN];
    input_buffer key_data(length);

    memcpy(seed, secure_.get_connection().server_random_, RAN_LEN);
    memcpy(&seed[RAN_LEN], secure_.get_connection().client_random_, RAN_LEN);

    PRF(key_data.get_buffer(), length, secure_.get_connection().master_secret_,
        SECRET_LEN, key_label, KEY_LABEL_SZ, seed, SEED_LEN);

    storeKeys(key_data.get_buffer());
}


// store mac, write, and iv keys for client and server
void SSL::storeKeys(const opaque* key_data)
{
    int sz = secure_.get_parms().hash_size_;
    memcpy(secure_.use_connection().client_write_MAC_secret_, key_data, sz);
    int i = sz;
    memcpy(secure_.use_connection().server_write_MAC_secret_,&key_data[i], sz);
    i += sz;

    sz = secure_.get_parms().key_size_;
    memcpy(secure_.use_connection().client_write_key_, &key_data[i], sz);
    i += sz;
    memcpy(secure_.use_connection().server_write_key_, &key_data[i], sz);
    i += sz;

    sz = secure_.get_parms().iv_size_;
    memcpy(secure_.use_connection().client_write_IV_, &key_data[i], sz);
    i += sz;
    memcpy(secure_.use_connection().server_write_IV_, &key_data[i], sz);

    setKeys();
}


void SSL::setKeys()
{
    Connection& conn = secure_.use_connection();

    if (secure_.get_parms().entity_ == client_end) {
        crypto_.use_cipher().set_encryptKey(conn.client_write_key_, 
                                            conn.client_write_IV_);
        crypto_.use_cipher().set_decryptKey(conn.server_write_key_,
                                            conn.server_write_IV_);
    }
    else {
        crypto_.use_cipher().set_encryptKey(conn.server_write_key_,
                                            conn.server_write_IV_);
        crypto_.use_cipher().set_decryptKey(conn.client_write_key_,
                                            conn.client_write_IV_);
    }
}



// local functors
namespace {

struct SumData {
    uint total_;
    SumData() : total_(0) {}
    void operator()(input_buffer* data) { total_ += data->get_remaining(); }
};


struct SumBuffer {
    uint total_;
    SumBuffer() : total_(0) {}
    void operator()(output_buffer* buffer) { total_ += buffer->get_size(); }
};

} // namespace for locals


uint SSL::bufferedData()
{
    return std::for_each(buffers_.getData().begin(), buffers_.getData().end(),
                         SumData()).total_;
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
    uint dataSz   = data.get_length();        // input, data size to fill
    uint elements = buffers_.getData().size();

    data.set_length(0);                         // output, actual data filled
    dataSz = min(dataSz, bufferedData());

    for (uint i = 0; i < elements; i++) {
        input_buffer* front = buffers_.getData().front();
        uint frontSz = front->get_remaining();
        uint readSz  = min(dataSz - data.get_length(), frontSz);

        front->read(data.set_buffer() + data.get_length(), readSz);
        data.set_length(data.get_length() + readSz);

        if (readSz == frontSz) {
            buffers_.useData().pop_front();
            delete front;
        }
        if (data.get_length() == dataSz)
            break;
    }
}


void SSL::flushBuffer()
{
    uint sz = std::for_each(buffers_.getHandShake().begin(),
                              buffers_.getHandShake().end(),
                              SumBuffer()).total_;
    output_buffer out(sz);
    uint elements = buffers_.getHandShake().size();

    for (uint i = 0; i < elements; i++) {
        output_buffer* front = buffers_.getHandShake().front();
        out.write(front->get_buffer(), front->get_size());

        buffers_.useHandShake().pop_front();
        delete front;
    }
    socket_.send(out.get_buffer(), out.get_size());
}


uint SSL::get_SEQIncrement(bool verify) 
{ 
    if (verify)
        return secure_.use_connection().peer_sequence_number_++; 
    else
        return secure_.use_connection().sequence_number_++; 
}


const byte* SSL::get_macSecret(bool verify)
{
    if ( (secure_.get_parms().entity_ == client_end && !verify) ||
         (secure_.get_parms().entity_ == server_end &&  verify) )
        return secure_.get_connection().client_write_MAC_secret_;
    else
        return secure_.get_connection().server_write_MAC_secret_;
}


void SSL::verifyState(const RecordLayerHeader& rlHeader)
{
    if (states_.getRecord() == recordNotReady || 
            (rlHeader.type_ == application_data &&        // data and handshake
             states_.getHandShake() != handShakeReady) ) // isn't complete yet
              throw Error("RecordLayer read after fatal error!", record_layer);
}


void SSL::verifyState(const HandShakeHeader& hsHeader)
{
    if (states_.getHandShake() == handShakeNotReady)
        throw Error("HandShake read after fatal error!", handshake_layer);

    if (secure_.get_parms().entity_ == client_end)
        verifyClientState(hsHeader.get_handshakeType());
    else
        verifyServerState(hsHeader.get_handshakeType());
}


void SSL::verifyState(ClientState cs)
{
    if (states_.getClient() != cs) order_error();
}


void SSL::verifyState(ServerState ss)
{
    if (states_.getServer() != ss) order_error();
}


void SSL::verfiyHandShakeComplete()
{
    if (states_.getHandShake() != handShakeReady) order_error();
}


void SSL::verifyClientState(HandShakeType hsType)
{
    switch(hsType) {
    case server_hello :
        if (states_.getClient() != serverNull)
            order_error();
        break;
    case certificate :
        if (states_.getClient() != serverHelloComplete)
            order_error();
        break;
    case server_key_exchange :
        if (states_.getClient() != serverCertComplete)
            order_error();
        break;
    case server_hello_done :
        if (states_.getClient() != serverCertComplete &&
            states_.getClient() != serverKeyExchangeComplete)
            order_error();
        break;
    case finished :
        if (states_.getClient() != serverHelloDoneComplete || 
            secure_.get_parms().pending_)    // no change
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
        if (states_.getServer() != clientNull)
            order_error();
        break;
    case client_key_exchange :
        if (states_.getServer() != clientHelloComplete)
            order_error();
        break;
    case finished :
        if (states_.getServer() != clientKeyExchangeComplete || 
            secure_.get_parms().pending_)    // no change
                order_error();          // cipher yet
        break;
    default :
        order_error();
    };
}


void SSL::matchSuite(const opaque* peer, uint length)
{
    if (length == 0 || (length % 2) != 0)
        throw Error("Bad suite input", bad_input);

    // start with best, if a match we are good, Ciphers are at odd index
    // since all SSL and TLS ciphers have 0x00 first byte
    for (uint i = 1; i < secure_.get_parms().suites_size_; i += 2)
        for (uint j = 1; j < length; j+= 2)
            if (secure_.use_parms().suites_[i] == peer[j]) {
                secure_.use_parms().suite_[0] = 0x00;
                secure_.use_parms().suite_[1] = peer[j];
                return;
            }

    throw Error("No suite match", match_error);
}


void SSL::set_session(SSL_SESSION* s) 
{ 
    if (s && GetSessions().lookup(s->getID(), &secure_.use_resume()))
        secure_.set_resuming(true);
}


SSL_SESSION::SSL_SESSION(const SSL& ssl, RandomPool& ran) 
    : timeout_(DEFAULT_TIMEOUT), random_(ran)
{
    const Connection& conn = ssl.getSecurity().get_connection();

    memcpy(sessionID_, conn.sessionID_, ID_LEN);
    memcpy(master_secret_, conn.master_secret_, SECRET_LEN);
    memcpy(suite_, ssl.getSecurity().get_parms().suite_, SUITE_LEN);

    bornOn_ = lowResTimer();
}


// for resumption copy in ssl::parameters
SSL_SESSION::SSL_SESSION(RandomPool& ran) 
    : bornOn_(0), timeout_(0), random_(ran)
{
    memset(sessionID_, 0, ID_LEN);
    memset(master_secret_, 0, SECRET_LEN);
    memset(suite_, 0, SUITE_LEN);
}


SSL_SESSION& SSL_SESSION::operator=(const SSL_SESSION& that)
{
    memcpy(sessionID_, that.sessionID_, ID_LEN);
    memcpy(master_secret_, that.master_secret_, SECRET_LEN);
    memcpy(suite_, that.suite_, SUITE_LEN);
    
    bornOn_  = that.bornOn_;
    timeout_ = that.timeout_;

    return *this;
}


extern void clean(volatile opaque*, uint, RandomPool&);

SSL_SESSION::~SSL_SESSION()
{
    volatile opaque* p = master_secret_;
    clean(p, SECRET_LEN, random_);
}


Sessions& GetSessions()
{
    static Sessions instance; // simple singleton
    return instance;
}


sslFactory& GetSSL_Factory()
{   
    static sslFactory instance; // simple singleton
    return instance;
}


typedef Mutex::Lock Lock;

 
void Sessions::add(const SSL& ssl) 
{
    Lock guard(mutex_);
    list_.push_back(new SSL_SESSION(ssl, random_));
}


namespace { // locals

typedef std::list<SSL_SESSION*>::iterator iterator;

struct sess_match {
    const opaque* id_;
    explicit sess_match(const opaque* p) : id_(p) {}

    bool operator()(SSL_SESSION* sess)
    {
        if ( memcmp(sess->getID(), id_, ID_LEN) == 0)
            return true;
        return false;
    }
};


} // local namespace


SSL_SESSION* Sessions::lookup(const opaque* id, SSL_SESSION* copy)
{
    Lock guard(mutex_);
    iterator find = std::find_if(list_.begin(), list_.end(), sess_match(id));

    if (find != list_.end()) {
        uint current = lowResTimer();
        if ( ((*find)->getBornOn() + (*find)->getTimeOut()) < current) {
            del_ptr_zero()(*find);
            list_.erase(find);
            return 0;
        }
        if (copy)
            *copy = *(*find);
        return *find;
    }
    return 0;
}


void Sessions::remove(const opaque* id)
{
    Lock guard(mutex_);
    iterator find = std::find_if(list_.begin(), list_.end(), sess_match(id));

    if (find != list_.end()) {
        del_ptr_zero()(*find);
        list_.erase(find);
    }
}



} // namespace
