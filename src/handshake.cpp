/* handshake.cpp                                
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


/* The handshake source implements functions for creating and reading
 * the various handshake messages.
 */


#include "handshake.hpp"
#include "yassl_int.hpp"


namespace yaSSL {


// Build a client hello message from cipher suites and compression method
void buildClientHello(SSL& ssl, ClientHello& hello,
                      CompressionMethod compression = no_compression)
{
    ssl.getCrypto().get_random().Fill(hello.random_, RAN_LEN);
    if (ssl.getSecurity().get_resuming()) {
        hello.id_len_ = ID_LEN;
        memcpy(hello.session_id_, ssl.getSecurity().get_resume().GetID(),
               ID_LEN);
    }
    else 
        hello.id_len_ = 0;
    hello.suite_len_ = ssl.getSecurity().get_parms().suites_size_;
    memcpy(hello.cipher_suites_, ssl.getSecurity().get_parms().suites_,
           hello.suite_len_);
    hello.comp_len_ = 1;                   
    hello.compression_methods_ = compression;   

    hello.set_length(sizeof(ProtocolVersion) +
                     RAN_LEN +
                     hello.id_len_    + sizeof(hello.id_len_) +
                     hello.suite_len_ + sizeof(hello.suite_len_) +
                     hello.comp_len_  + sizeof(hello.comp_len_));
}


// Build a server hello message
void buildServerHello(SSL& ssl, ServerHello& hello)
{
    if (ssl.getSecurity().get_resuming()) {
        memcpy(hello.random_,ssl.getSecurity().get_connection().server_random_,
               RAN_LEN);
        memcpy(hello.session_id_, ssl.getSecurity().get_resume().GetID(),
               ID_LEN);
    }
    else {
        ssl.getCrypto().get_random().Fill(hello.random_, RAN_LEN);
        ssl.getCrypto().get_random().Fill(hello.session_id_, ID_LEN);
    }
    hello.id_len_ = ID_LEN;
    ssl.set_sessionID(hello.session_id_);

    hello.cipher_suite_[0] = ssl.getSecurity().get_parms().suite_[0];
    hello.cipher_suite_[1] = ssl.getSecurity().get_parms().suite_[1];
    hello.compression_method_ = no_compression;

    hello.set_length(sizeof(ProtocolVersion) + RAN_LEN + ID_LEN +
                     sizeof(hello.id_len_) + SUITE_LEN + SIZEOF_ENUM);
}


// add handshake from buffer into md5 and sha hashes, use handshake header
void hashHandShake(SSL& ssl, const input_buffer& input, uint sz)
{
    const opaque* buffer = input.get_buffer() + input.get_current() - 
                           HANDSHAKE_HEADER;
    sz += HANDSHAKE_HEADER;
    ssl.useHashes().use_MD5().update(buffer, sz);
    ssl.useHashes().use_SHA().update(buffer, sz);
}


// locals
namespace {

// Write a plaintext record to buffer
void buildOutput(output_buffer& buffer, const RecordLayerHeader& rlHdr, 
                 const Message& msg)
{
    buffer.allocate(RECORD_HEADER + rlHdr.length_);
    buffer << rlHdr << msg;
}


// Write a plaintext record to buffer
void buildOutput(output_buffer& buffer, const RecordLayerHeader& rlHdr, 
                 const HandShakeHeader& hsHdr, const HandShakeBase& shake)
{
    buffer.allocate(RECORD_HEADER + rlHdr.length_);
    buffer << rlHdr << hsHdr << shake;
}


// Build Record Layer header for Message without handshake header
void buildHeader(SSL& ssl, RecordLayerHeader& rlHeader, const Message& msg)
{
    ProtocolVersion pv = ssl.getSecurity().get_connection().version_;
    rlHeader.type_ = msg.get_type();
    rlHeader.version_.major_ = pv.major_;
    rlHeader.version_.minor_ = pv.minor_;
    rlHeader.length_ = msg.get_length();
}


// Build HandShake and RecordLayer Headers for handshake output
void buildHeaders(SSL& ssl, HandShakeHeader& hsHeader,
                  RecordLayerHeader& rlHeader, const HandShakeBase& shake)
{
    int sz = shake.get_length();

    hsHeader.set_type(shake.get_type());
    hsHeader.set_length(sz);

    ProtocolVersion pv = ssl.getSecurity().get_connection().version_;
    rlHeader.type_ = handshake;
    rlHeader.version_.major_ = pv.major_;
    rlHeader.version_.minor_ = pv.minor_;
    rlHeader.length_ = sz + HANDSHAKE_HEADER;
}


// add handshake from buffer into md5 and sha hashes, exclude record header
void hashHandShake(SSL& ssl, const output_buffer& output)
{
    uint sz = output.get_size() - RECORD_HEADER;

    const opaque* buffer = output.get_buffer() + RECORD_HEADER;

    ssl.useHashes().use_MD5().update(buffer, sz);
    ssl.useHashes().use_SHA().update(buffer, sz);
}


// calculate MD5 hash for finished
void buildMD5(SSL& ssl, Finished& fin, const opaque* sender)
{

    opaque md5_result[MD5_LEN];
    opaque md5_inner[SIZEOF_SENDER + SECRET_LEN + PAD_MD5];
    opaque md5_outer[SECRET_LEN + PAD_MD5 + MD5_LEN];

    const opaque* master_secret = 
        ssl.getSecurity().get_connection().master_secret_;

    // make md5 inner
    memcpy(md5_inner, sender, SIZEOF_SENDER);
    memcpy(&md5_inner[SIZEOF_SENDER], master_secret, SECRET_LEN);
    memcpy(&md5_inner[SIZEOF_SENDER + SECRET_LEN], PAD1, PAD_MD5);

    ssl.useHashes().use_MD5().get_digest(md5_result, md5_inner,
                                         sizeof(md5_inner));

    // make md5 outer
    memcpy(md5_outer, master_secret, SECRET_LEN);
    memcpy(&md5_outer[SECRET_LEN], PAD2, PAD_MD5);
    memcpy(&md5_outer[SECRET_LEN + PAD_MD5], md5_result, MD5_LEN);

    ssl.useHashes().use_MD5().get_digest(fin.set_md5(), md5_outer,
                                         sizeof(md5_outer));
}


// calculate SHA hash for finished
void buildSHA(SSL& ssl, Finished& fin, const opaque* sender)
{
    
    opaque sha_result[SHA_LEN];
    opaque sha_inner[SIZEOF_SENDER + SECRET_LEN + PAD_SHA];
    opaque sha_outer[SECRET_LEN + PAD_SHA + SHA_LEN];

    const opaque* master_secret = 
        ssl.getSecurity().get_connection().master_secret_;

     // make sha inner
    memcpy(sha_inner, sender, SIZEOF_SENDER);
    memcpy(&sha_inner[SIZEOF_SENDER], master_secret, SECRET_LEN);
    memcpy(&sha_inner[SIZEOF_SENDER + SECRET_LEN], PAD1, PAD_SHA);

    ssl.useHashes().use_SHA().get_digest(sha_result, sha_inner,
                                         sizeof(sha_inner));

    // make sha outer
    memcpy(sha_outer, master_secret, SECRET_LEN);
    memcpy(&sha_outer[SECRET_LEN], PAD2, PAD_SHA);
    memcpy(&sha_outer[SECRET_LEN + PAD_SHA], sha_result, SHA_LEN);

    ssl.useHashes().use_SHA().get_digest(fin.set_sha(), sha_outer,
                                         sizeof(sha_outer));
}


// decrypt input message in place, store size in case needed later
void decrypt_message(SSL& ssl, input_buffer& input, uint sz)
{
    input_buffer plain(sz);
    opaque*      cipher = input.get_buffer() + input.get_current();

    ssl.useCrypto().use_cipher().decrypt(plain.get_buffer(), cipher, sz);
    memcpy(cipher, plain.get_buffer(), sz);
    ssl.useSecurity().use_parms().encrypt_size_ = sz;
}


// write headers, handshake hash, mac, pad, and encrypt
void cipherFinished(SSL& ssl, Finished& fin, output_buffer& output)
{
    uint digestSz = ssl.getCrypto().get_digest().get_digestSize();
    uint finishedSz = ssl.isTLS() ? TLS_FINISHED_SZ : FINISHED_SZ;
    uint sz  = RECORD_HEADER + HANDSHAKE_HEADER + finishedSz + digestSz;
    uint pad = 0;
    if (ssl.getSecurity().get_parms().cipher_type_ == block) {
        sz += 1;       // pad byte
        uint blockSz = ssl.getCrypto().get_cipher().get_blockSize();
        pad = (sz - RECORD_HEADER) % blockSz;
        pad = blockSz - pad;
        sz += pad;
    }

    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    buildHeaders(ssl, hsHeader, rlHeader, fin);
    rlHeader.length_ = sz - RECORD_HEADER;   // record header includes mac
                                             // and pad, hanshake doesn't
    output.allocate(sz);
    output << rlHeader << hsHeader << fin;
    
    hashHandShake(ssl, output);
    opaque digest[SHA_LEN];                  // max size
    if (ssl.isTLS())
        TLS_hmac(ssl, digest, output.get_buffer() + RECORD_HEADER,
                 output.get_size() - RECORD_HEADER, handshake);
    else
        hmac(ssl, digest, output.get_buffer() + RECORD_HEADER,
             output.get_size() - RECORD_HEADER, handshake);
    output.write(digest, digestSz);

    if (ssl.getSecurity().get_parms().cipher_type_ == block)
        for (uint i = 0; i <= pad; i++) output[AUTO] = pad;   // pad byte gets
                                                              // pad value too
    input_buffer cipher(rlHeader.length_);
    ssl.useCrypto().use_cipher().encrypt(cipher.get_buffer(),
       output.get_buffer() + RECORD_HEADER, output.get_size() - RECORD_HEADER);
    output.set_current(RECORD_HEADER);
    output.write(cipher.get_buffer(), cipher.get_capacity());
}


// build an encrypted data or alert message for output
void buildMessage(SSL& ssl, output_buffer& output, const Message& msg)
{
    uint digestSz = ssl.getCrypto().get_digest().get_digestSize();
    uint sz  = RECORD_HEADER + msg.get_length() + digestSz;                
    uint pad = 0;
    if (ssl.getSecurity().get_parms().cipher_type_ == block) {
        sz += 1;       // pad byte
        uint blockSz = ssl.getCrypto().get_cipher().get_blockSize();
        pad = (sz - RECORD_HEADER) % blockSz;
        pad = blockSz - pad;
        sz += pad;
    }

    RecordLayerHeader rlHeader;
    buildHeader(ssl, rlHeader, msg);
    rlHeader.length_ = sz - RECORD_HEADER;   // record header includes mac
                                             // and pad, hanshake doesn't
    output.allocate(sz);
    output << rlHeader << msg;
    
    opaque digest[SHA_LEN];                  // max size
    if (ssl.isTLS())
        TLS_hmac(ssl, digest, output.get_buffer() + RECORD_HEADER,
                 output.get_size() - RECORD_HEADER, msg.get_type());
    else
        hmac(ssl, digest, output.get_buffer() + RECORD_HEADER,
             output.get_size() - RECORD_HEADER, msg.get_type());
    output.write(digest, digestSz);

    if (ssl.getSecurity().get_parms().cipher_type_ == block)
        for (uint i = 0; i <= pad; i++) output[AUTO] = pad; // pad byte gets
                                                              // pad value too
    input_buffer cipher(rlHeader.length_);
    ssl.useCrypto().use_cipher().encrypt(cipher.get_buffer(),
       output.get_buffer() + RECORD_HEADER, output.get_size() - RECORD_HEADER);
    output.set_current(RECORD_HEADER);
    output.write(cipher.get_buffer(), cipher.get_capacity());
}


// build alert message
void buildAlert(SSL& ssl, output_buffer& output, const Alert& alert)
{
    if (ssl.getSecurity().get_parms().pending_ == false) // encrypted
        buildMessage(ssl, output, alert);
    else {
        RecordLayerHeader rlHeader;
        buildHeader(ssl, rlHeader, alert);
        buildOutput(output, rlHeader, alert);
    }
}


// build TLS finished message
void buildFinishedTLS(SSL& ssl, Finished& fin, const opaque* sender) 
{
    opaque handshake_hash[FINISHED_SZ];

    ssl.useHashes().use_MD5().get_digest(handshake_hash);
    ssl.useHashes().use_SHA().get_digest(&handshake_hash[MD5_LEN]);

    const opaque* side;
    if ( strncmp((const char*)sender, (const char*)client, SIZEOF_SENDER) == 0)
        side = tls_client;
    else
        side = tls_server;

    PRF(fin.set_md5(), TLS_FINISHED_SZ, 
        ssl.getSecurity().get_connection().master_secret_, SECRET_LEN, 
        side, FINISHED_LABEL_SZ, 
        handshake_hash, FINISHED_SZ);

    fin.set_length(TLS_FINISHED_SZ);  // shorter length for TLS
}


// compute p_hash for MD5 or SHA-1 for TLSv1 PRF
void p_hash(output_buffer& result, const output_buffer& secret,
            const output_buffer& seed, MACAlgorithm hash)
{
    uint   len = hash == md5 ? MD5_LEN : SHA_LEN;
    uint   times = result.get_capacity() / len;
    uint   lastLen = result.get_capacity() % len;
    opaque previous[SHA_LEN];  // max size
    opaque current[SHA_LEN];   // max size
    std::auto_ptr<Digest> hmac;

    if (lastLen) times += 1;

    if (hash == md5) {
        std::auto_ptr<Digest> tmp(new HMAC_MD5(secret.get_buffer(),
                                               secret.get_size()));
        hmac = tmp;
    }
    else {
        std::auto_ptr<Digest> tmp(new HMAC_SHA(secret.get_buffer(),
                                               secret.get_size()));
        hmac = tmp;
    }
                                                                   // A0 = seed
    hmac->get_digest(previous, seed.get_buffer(), seed.get_size());// A1
    uint lastTime = times - 1;

    for (uint i = 0; i < times; i++) {
        hmac->update(previous, len);  
        hmac->get_digest(current, seed.get_buffer(), seed.get_size());

        if (lastLen && (i == lastTime))
            result.write(current, lastLen);
        else {
            result.write(current, len);
            //memcpy(previous, current, len);
            hmac->get_digest(previous, previous, len);
        }
    }
}


// calculate XOR for TLSv1 PRF
void get_xor(byte *digest, uint digLen, output_buffer& md5,
             output_buffer& sha)
{
    for (uint i = 0; i < digLen; i++) 
        digest[i] = md5[AUTO] ^ sha[AUTO];
}


// build MD5 part of certificate verify
void buildMD5_CertVerify(SSL& ssl, byte* digest)
{
    opaque md5_result[MD5_LEN];
    opaque md5_inner[SECRET_LEN + PAD_MD5];
    opaque md5_outer[SECRET_LEN + PAD_MD5 + MD5_LEN];

    const opaque* master_secret = 
        ssl.getSecurity().get_connection().master_secret_;

    // make md5 inner
    memcpy(md5_inner, master_secret, SECRET_LEN);
    memcpy(&md5_inner[SECRET_LEN], PAD1, PAD_MD5);

    ssl.useHashes().use_MD5().get_digest(md5_result, md5_inner,
                                         sizeof(md5_inner));

    // make md5 outer
    memcpy(md5_outer, master_secret, SECRET_LEN);
    memcpy(&md5_outer[SECRET_LEN], PAD2, PAD_MD5);
    memcpy(&md5_outer[SECRET_LEN + PAD_MD5], md5_result, MD5_LEN);

    ssl.useHashes().use_MD5().get_digest(digest, md5_outer, sizeof(md5_outer));
}


// build SHA part of certificate verify
void buildSHA_CertVerify(SSL& ssl, byte* digest)
{
    opaque sha_result[SHA_LEN];
    opaque sha_inner[SECRET_LEN + PAD_SHA];
    opaque sha_outer[SECRET_LEN + PAD_SHA + SHA_LEN];

    const opaque* master_secret = 
        ssl.getSecurity().get_connection().master_secret_;

     // make sha inner
    memcpy(sha_inner, master_secret, SECRET_LEN);
    memcpy(&sha_inner[SECRET_LEN], PAD1, PAD_SHA);

    ssl.useHashes().use_SHA().get_digest(sha_result, sha_inner,
                                         sizeof(sha_inner));

    // make sha outer
    memcpy(sha_outer, master_secret, SECRET_LEN);
    memcpy(&sha_outer[SECRET_LEN], PAD2, PAD_SHA);
    memcpy(&sha_outer[SECRET_LEN + PAD_SHA], sha_result, SHA_LEN);

    ssl.useHashes().use_SHA().get_digest(digest, sha_outer, sizeof(sha_outer));
}


} // namespace for locals


// Build a finished message, see 7.6.9
void buildFinished(SSL& ssl, Finished& fin, const opaque* sender) 
{
    // store current states, building requires get_digest which resets state
    MD5 md5(ssl.getHashes().get_MD5());
    SHA sha(ssl.getHashes().get_SHA());

    if (ssl.isTLS())
        buildFinishedTLS(ssl, fin, sender);
    else {
        buildMD5(ssl, fin, sender);
        buildSHA(ssl, fin, sender);
    }

    // restore
    ssl.useHashes().use_MD5() = md5;
    ssl.useHashes().use_SHA() = sha;
}


/* compute SSLv3 HMAC into digest see
 * buffer is of sz size and includes HandShake Header but not a Record Header
 * verify means to check peers hmac
*/
void hmac(SSL& ssl, byte* digest, const byte* buffer, uint sz,
          ContentType content, bool verify)
{
    Digest& mac = ssl.useCrypto().use_digest();
    opaque inner[SHA_LEN + PAD_MD5 + SEQ_SZ + SIZEOF_ENUM + LENGTH_SZ];
    opaque outer[SHA_LEN + PAD_MD5 + SHA_LEN]; 
    opaque result[SHA_LEN];                              // max possible sizes
    uint digestSz = mac.get_digestSize();              // actual sizes
    uint padSz    = mac.get_padSize();
    uint innerSz  = digestSz + padSz + SEQ_SZ + SIZEOF_ENUM + LENGTH_SZ;
    uint outerSz  = digestSz + padSz + digestSz;

    // data
    const opaque* mac_secret = ssl.get_macSecret(verify);
    opaque seq[SEQ_SZ] = { 0x00, 0x00, 0x00, 0x00 };
    opaque length[LENGTH_SZ];
    c16toa(sz, length);
    c32toa(ssl.get_SEQIncrement(verify), &seq[sizeof(uint32)]);

    // make inner
    memcpy(inner, mac_secret, digestSz);
    memcpy(&inner[digestSz], PAD1, padSz);
    memcpy(&inner[digestSz + padSz], seq, SEQ_SZ);
    inner[digestSz + padSz + SEQ_SZ] = content;
    memcpy(&inner[digestSz + padSz + SEQ_SZ + SIZEOF_ENUM], length, LENGTH_SZ);

    mac.update(inner, innerSz);
    mac.get_digest(result, buffer, sz);      // append content buffer

    // make outer
    memcpy(outer, mac_secret, digestSz);
    memcpy(&outer[digestSz], PAD2, padSz);
    memcpy(&outer[digestSz + padSz], result, digestSz);

    mac.get_digest(digest, outer, outerSz);
}


// TLS type HAMC
void TLS_hmac(SSL& ssl, byte* digest, const byte* buffer, uint sz,
              ContentType content, bool verify)
{
    std::auto_ptr<Digest> hmac;
    opaque seq[SEQ_SZ] = { 0x00, 0x00, 0x00, 0x00 };
    opaque length[LENGTH_SZ];
    opaque inner[SIZEOF_ENUM + VERSION_SZ + LENGTH_SZ]; // type + version + len

    c16toa(sz, length);
    c32toa(ssl.get_SEQIncrement(verify), &seq[sizeof(uint32)]);

    if (ssl.getSecurity().get_parms().mac_algorithm_ == sha) {
        std::auto_ptr<Digest> tmp(new HMAC_SHA(ssl.get_macSecret(verify),
                                  SHA_LEN));
        hmac = tmp;
    }
    else {
        std::auto_ptr<Digest> tmp(new HMAC_MD5(ssl.get_macSecret(verify),
                                  MD5_LEN));
        hmac = tmp;
    }
    hmac->update(seq, SEQ_SZ);                                       // seq_num
    inner[0] = content;                                              // type
    inner[SIZEOF_ENUM] = ssl.getSecurity().get_connection().version_.major_;  
    inner[SIZEOF_ENUM + SIZEOF_ENUM] = 
        ssl.getSecurity().get_connection().version_.minor_;          // version
    memcpy(&inner[SIZEOF_ENUM + VERSION_SZ], length, LENGTH_SZ);     // length
    hmac->update(inner, sizeof(inner));
    hmac->get_digest(digest, buffer, sz);                            // content
}


// compute TLSv1 PRF (pseudo random function using HMAC)
void PRF(byte* digest, uint digLen, const byte* secret, uint secLen,
         const byte* label, uint labLen, const byte* seed, uint seedLen)
{
    uint half = secLen / 2 + secLen % 2;

    output_buffer md5_half(half);
    output_buffer sha_half(half);
    output_buffer labelSeed(labLen + seedLen);

    md5_half.write(secret, half);
    sha_half.write(secret + half - secLen % 2, half);
    labelSeed.write(label, labLen);
    labelSeed.write(seed, seedLen);

    output_buffer md5_result(digLen);
    output_buffer sha_result(digLen);

    p_hash(md5_result, md5_half, labelSeed, md5);
    p_hash(sha_result, sha_half, labelSeed, sha);

    md5_result.set_current(0);
    sha_result.set_current(0);
    get_xor(digest, digLen, md5_result, sha_result);
}


// build certificate hashes
void build_certHashes(SSL& ssl, Hashes& hashes)
{
    // store current states, building requires get_digest which resets state
    MD5 md5(ssl.getHashes().get_MD5());
    SHA sha(ssl.getHashes().get_SHA());

    if (ssl.isTLS()) {
        ssl.useHashes().use_MD5().get_digest(hashes.md5_);
        ssl.useHashes().use_SHA().get_digest(hashes.sha_);
    }
    else {
        buildMD5_CertVerify(ssl, hashes.md5_);
        buildSHA_CertVerify(ssl, hashes.sha_);
    }

    // restore
    ssl.useHashes().use_MD5() = md5;
    ssl.useHashes().use_SHA() = sha;
}


std::auto_ptr<input_buffer> null_buffer;

// do process input requests
std::auto_ptr<input_buffer>
DoProcessReply(SSL& ssl, std::auto_ptr<input_buffer> buffered)
{
    ssl.getSocket().wait();                  // wait for input if blocking
    uint ready = ssl.getSocket().get_ready();
    if (!ready) return buffered;

    uint buffSz = buffered.get() ? buffered.get()->get_size() : 0;
    input_buffer buffer(buffSz + ready);
    if (buffSz) {
        buffer.assign(buffered.get()->get_buffer(), buffSz);
        buffered = null_buffer;
    }

    uint read  = ssl.getSocket().receive(buffer.get_buffer() + buffSz, ready);
    buffer.add_size(read);
    uint offset = 0;
    const MessageFactory& mf = ssl.getFactory().getMessage();

    while(!buffer.eof()) {
        // each record
        RecordLayerHeader hdr;
        buffer >> hdr;
        ssl.verifyState(hdr);

        // make sure we have enough input in buffer to process this record
        if (hdr.length_ > buffer.get_remaining()) { 
            uint sz = buffer.get_remaining() + RECORD_HEADER;
            std::auto_ptr<input_buffer> tmp(new input_buffer(sz,
              buffer.get_buffer() + buffer.get_current() - RECORD_HEADER, sz));
            buffered = tmp;
            break;
        }

        while (buffer.get_current() < hdr.length_ + RECORD_HEADER + offset) {
            // each message in record
            if (ssl.getSecurity().get_parms().pending_ == false) // cipher enabled
                decrypt_message(ssl, buffer, hdr.length_);
            std::auto_ptr<Message> msg(mf.CreateObject(hdr.type_));
            buffer >> *msg;
            msg->Process(buffer, ssl);
        }
        offset += hdr.length_ + RECORD_HEADER;
    }
    return buffered;  // done, don't call again
}


// process input requests
void processReply(SSL& ssl)
{   
    std::auto_ptr<input_buffer> buffered;

    while ( (buffered = DoProcessReply(ssl, buffered)).get() )
        ; // keep procssing
}


// send client_hello, no buffering
void sendClientHello(SSL& ssl)
{
    ssl.verifyState(serverNull);

    ClientHello       ch(ssl.getSecurity().get_connection().version_);
    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    output_buffer     out;

    buildClientHello(ssl, ch);
    ssl.set_random(ch.get_random(), client_end);
    buildHeaders(ssl, hsHeader, rlHeader, ch);
    buildOutput(out, rlHeader, hsHeader, ch);
    hashHandShake(ssl, out);

    ssl.getSocket().send(out.get_buffer(), out.get_size());
}


// send client key exchange
void sendClientKeyExchange(SSL& ssl, BufferOutput buffer)
{
    ssl.verifyState(serverHelloDoneComplete);

    ClientKeyExchange ck(ssl);
    ck.build(ssl);
    ssl.makeMasterSecret();

    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);
    buildHeaders(ssl, hsHeader, rlHeader, ck);
    buildOutput(*out.get(), rlHeader, hsHeader, ck);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send server key exchange
void sendServerKeyExchange(SSL& ssl, BufferOutput buffer)
{
    ServerKeyExchange sk(ssl);
    sk.build(ssl);

    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);
    buildHeaders(ssl, hsHeader, rlHeader, sk);
    buildOutput(*out.get(), rlHeader, hsHeader, sk);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send change cipher
void sendChangeCipher(SSL& ssl, BufferOutput buffer)
{
    if (ssl.getSecurity().get_parms().entity_ == server_end)
        if (ssl.getSecurity().get_resuming())
            ssl.verifyState(clientKeyExchangeComplete);
        else
            ssl.verifyState(clientFinishedComplete);

    ChangeCipherSpec ccs;
    RecordLayerHeader rlHeader;
    buildHeader(ssl, rlHeader, ccs);
    std::auto_ptr<output_buffer> out(new output_buffer);
    buildOutput(*out.get(), rlHeader, ccs);
   
    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send finished
void sendFinished(SSL& ssl, ConnectionEnd side, BufferOutput buffer)
{
    Finished fin;
    buildFinished(ssl, fin, side == client_end ? client : server);
    std::auto_ptr<output_buffer> out(new output_buffer);
    cipherFinished(ssl, fin, *out.get());                   // hashes handshake

    if (ssl.getSecurity().get_resuming()) {
        if (side == server_end)
            buildFinished(ssl, ssl.useHashes().use_verify(), client); // client
    }
    else {
        GetSessions().add(ssl);  // store session
        if (side == client_end)
            buildFinished(ssl, ssl.useHashes().use_verify(), server); // server
    }   
    ssl.useSecurity().use_connection().CleanMaster();

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send data
int sendData(SSL& ssl, const Data& data)
{
    ssl.verfiyHandShakeComplete();

    output_buffer out;
    buildMessage(ssl, out, data);
    ssl.getSocket().send(out.get_buffer(), out.get_size());
    ssl.useLog().ShowData(data.get_length(), true);

    return data.get_length();
}


// send alert
int sendAlert(SSL& ssl, const Alert& alert)
{
    output_buffer out;
    buildAlert(ssl, out, alert);
    ssl.getSocket().send(out.get_buffer(), out.get_size());

    return alert.get_length();
}


// process input data
int receiveData(SSL& ssl, Data& data)
{
    ssl.verfiyHandShakeComplete();

    if (!ssl.bufferedData())
        processReply(ssl);
    ssl.fillData(data);
    ssl.useLog().ShowData(data.get_length());

    return data.get_length(); 
}


// send server hello
void sendServerHello(SSL& ssl, BufferOutput buffer)
{
    if (ssl.getSecurity().get_resuming())
        ssl.verifyState(clientKeyExchangeComplete);
    else
        ssl.verifyState(clientHelloComplete);

    ServerHello       sh(ssl.getSecurity().get_connection().version_);
    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);

    buildServerHello(ssl, sh);
    ssl.set_random(sh.get_random(), server_end);
    buildHeaders(ssl, hsHeader, rlHeader, sh);
    buildOutput(*out.get(), rlHeader, hsHeader, sh);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send server hello done
void sendServerHelloDone(SSL& ssl, BufferOutput buffer)
{
    ServerHelloDone   shd;
    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);

    buildHeaders(ssl, hsHeader, rlHeader, shd);
    buildOutput(*out.get(), rlHeader, hsHeader, shd);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send certificate
void sendCertificate(SSL& ssl, BufferOutput buffer)
{
    Certificate       cert(ssl.getCrypto().get_certManager().get_cert());
    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);

    buildHeaders(ssl, hsHeader, rlHeader, cert);
    buildOutput(*out.get(), rlHeader, hsHeader, cert);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send certificate request
void sendCertificateRequest(SSL& ssl, BufferOutput buffer)
{
    CertificateRequest request;
    request.Build();
    RecordLayerHeader  rlHeader;
    HandShakeHeader    hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);

    buildHeaders(ssl, hsHeader, rlHeader, request);
    buildOutput(*out.get(), rlHeader, hsHeader, request);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


// send certificate verify
void sendCertificateVerify(SSL& ssl, BufferOutput buffer)
{
    CertificateVerify  verify;
    verify.Build(ssl);
    RecordLayerHeader  rlHeader;
    HandShakeHeader    hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);

    buildHeaders(ssl, hsHeader, rlHeader, verify);
    buildOutput(*out.get(), rlHeader, hsHeader, verify);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.getSocket().send(out->get_buffer(), out->get_size());
}


} // namespace
