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
    ProtocolVersion pv = ssl.get_connection().version_;
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

    ProtocolVersion pv = ssl.get_connection().version_;
    rlHeader.type_ = handshake;
    rlHeader.version_.major_ = pv.major_;
    rlHeader.version_.minor_ = pv.minor_;
    rlHeader.length_ = sz + HANDSHAKE_HEADER;
}



// Build a client hello message from cipher suites and compression method
void buildClientHello(SSL& ssl, ClientHello& hello,
                      CompressionMethod compression)
{
    ssl.get_random().Fill(hello.random_, RAN_LEN);
    hello.id_len_ = 0;
    hello.suite_len_ = ssl.get_security().suites_size_;
    memcpy(hello.cipher_suites_, ssl.get_security().suites_, hello.suite_len_);
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
    ssl.get_random().Fill(hello.random_, RAN_LEN);
    hello.id_len_ = ID_LEN;
    ssl.get_random().Fill(hello.session_id_, ID_LEN);

    hello.cipher_suite_[0] = ssl.get_security().suite_[0];
    hello.cipher_suite_[1] = ssl.get_security().suite_[1];
    hello.compression_method_ = no_compression;

    hello.set_length(sizeof(ProtocolVersion) + RAN_LEN + ID_LEN +
                     sizeof(hello.id_len_) + SUITE_LEN + SIZEOF_ENUM);
}


// add handshake from buffer into md5 and sha hashes, exclude record header
void hashHandShake(SSL& ssl, const output_buffer& output)
{
    MD5& md5 = ssl.use_MD5();
    SHA& sha = ssl.use_SHA();
    int  hdrSz = RECORD_HEADER;
    int  sz = output.get_size() - hdrSz;
    const opaque* buffer = output.get_buffer() + hdrSz;

    md5.update(buffer, sz);
    sha.update(buffer, sz);
}


// add handshake from buffer into md5 and sha hashes, use handshake header
void hashHandShake(SSL& ssl, const input_buffer& input, unsigned int sz)
{
    MD5& md5 = ssl.use_MD5();
    SHA& sha = ssl.use_SHA();
    int  hdrSz = HANDSHAKE_HEADER;
    sz += hdrSz;
    const opaque* buffer = input.get_buffer() + input.get_current() - hdrSz;

    md5.update(buffer, sz);
    sha.update(buffer, sz);
}



// calculate MD5 hash for finished
static void buildMD5(SSL& ssl, Finished& fin, const opaque* sender)
{
    //size_t secretLen = ssl.get_connection().secret_len_; // NEWTAO master alway 48
    size_t secretLen = SECRET_LEN;
    MD5&   md5 = ssl.use_MD5();
    opaque md5_result[MD5_LEN];

    output_buffer md5_inner(SIZEOF_SENDER + secretLen + PAD_MD5);
    output_buffer md5_outer(secretLen + PAD_MD5 + MD5_LEN);


    const opaque* master_secret = ssl.get_connection().master_secret_;

    // make md5 inner
    md5_inner.write(sender, SIZEOF_SENDER);
    md5_inner.write(master_secret, secretLen);
    md5_inner.write(PAD1, PAD_MD5);

    md5.get_digest(md5_result, md5_inner.get_buffer(), md5_inner.get_size());

    // make md5 outer
    md5_outer.write(master_secret, secretLen);
    md5_outer.write(PAD2, PAD_MD5);
    md5_outer.write(md5_result, MD5_LEN);

    md5.get_digest(fin.set_md5(), md5_outer.get_buffer(),md5_outer.get_size());
}


// calculate SHA hash for finished
static void buildSHA(SSL& ssl, Finished& fin, const opaque* sender)
{
    //size_t secretLen = ssl.get_connection().secret_len_; // NEWTAO master always 48
    size_t secretLen = SECRET_LEN;
    SHA&   sha = ssl.use_SHA();
    opaque sha_result[SHA_LEN];

    output_buffer sha_inner(SIZEOF_SENDER + secretLen + PAD_SHA);
    output_buffer sha_outer(secretLen + PAD_SHA + SHA_LEN);

    const opaque* master_secret = ssl.get_connection().master_secret_;

    // make sha inner
    sha_inner.write(sender, SIZEOF_SENDER);
    sha_inner.write(master_secret, secretLen);
    sha_inner.write(PAD1, PAD_SHA);

    sha.get_digest(sha_result, sha_inner.get_buffer(), sha_inner.get_size());

    // make sha outer
    sha_outer.write(master_secret, secretLen);
    sha_outer.write(PAD2, PAD_SHA);
    sha_outer.write(sha_result, SHA_LEN);

    sha.get_digest(fin.set_sha(), sha_outer.get_buffer(), sha_outer.get_size());
}


void buildFinishedTLS(SSL& ssl, Finished& fin, const opaque* sender) 
{
    opaque handshake_hash[FINISHED_SZ];
    MD5&   md5 = ssl.use_MD5();
    SHA&   sha = ssl.use_SHA();
    //size_t secretLen = ssl.get_connection().secret_len_; // NEWTAO master always 48
    size_t secretLen = SECRET_LEN;

    md5.get_digest(handshake_hash);
    sha.get_digest(&handshake_hash[MD5_LEN]);

    const opaque* side;
    if ( strncmp((const char*)sender, (const char*)client, SIZEOF_SENDER) == 0)
        side = tls_client;
    else
        side = tls_server;

    PRF(fin.set_md5(), TLS_FINISHED_SZ, ssl.get_connection().master_secret_,
        secretLen, side, FINISHED_LABEL_SZ, handshake_hash, FINISHED_SZ);

    fin.set_length(TLS_FINISHED_SZ);  // shorter length for TLS
}


// Build a finished message, see 7.6.9
void buildFinished(SSL& ssl, Finished& fin, const opaque* sender) 
{
    // store current states, building requires get_digest which resets state
    MD5 md5(ssl.get_MD5());
    SHA sha(ssl.get_SHA());

    if (ssl.isTLS())
        buildFinishedTLS(ssl, fin, sender);
    else {
        buildMD5(ssl, fin, sender);
        buildSHA(ssl, fin, sender);
    }

    ssl.restoreHashes(md5, sha);
}


/* compute SSLv3 HMAC into digest see
 * buffer is of sz size and includes HandShake Header but not a Record Header
 * verify means to check peers hmac
*/
void hmac(SSL& ssl, byte* digest, const byte* buffer, size_t sz,
          ContentType content, bool verify)
{
    MAC& mac = ssl.use_mac();
    opaque inner[SHA_LEN + PAD_MD5 + SEQ_SZ + SIZEOF_ENUM + LENGTH_SZ];
    opaque outer[SHA_LEN + PAD_MD5 + SHA_LEN]; 
    opaque result[SHA_LEN];                              // max possible sizes
    size_t digestSz = mac.get_digestSize();              // actual sizes
    size_t padSz    = mac.get_padSize();
    size_t innerSz  = digestSz + padSz + SEQ_SZ + SIZEOF_ENUM + LENGTH_SZ;
    size_t outerSz  = digestSz + padSz + digestSz;

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


void TLS_hmac(SSL& ssl, byte* digest, const byte* buffer, size_t sz,
              ContentType content, bool verify)
{
    std::auto_ptr<MAC> hmac;
    opaque seq[SEQ_SZ] = { 0x00, 0x00, 0x00, 0x00 };
    opaque length[LENGTH_SZ];
    opaque inner[SIZEOF_ENUM + VERSION_SZ + LENGTH_SZ]; // type + version + len

    c16toa(sz, length);
    c32toa(ssl.get_SEQIncrement(verify), &seq[sizeof(uint32)]);

    if (ssl.get_security().mac_algorithm_ == sha)
        hmac = std::auto_ptr<MAC>(new HMAC_SHA(ssl.get_macSecret(verify),
                                  SHA_LEN));
    else
        hmac = std::auto_ptr<MAC>(new HMAC_MD5(ssl.get_macSecret(verify),
                                  MD5_LEN));
    hmac->update(seq, SEQ_SZ);                                       // seq_num
    inner[0] = content;                                              // type
    inner[SIZEOF_ENUM] = ssl.get_connection().version_.major_;       // version
    inner[SIZEOF_ENUM + SIZEOF_ENUM] = ssl.get_connection().version_.minor_;
    memcpy(&inner[SIZEOF_ENUM + VERSION_SZ], length, LENGTH_SZ);     // length
    hmac->update(inner, sizeof(inner));
    hmac->get_digest(digest, buffer, sz);                            // content
}


// write headers, handshake hash, mac, pad, and encrypt
void cipherFinished(SSL& ssl, Finished& fin, output_buffer& output)
{
    size_t digestSz = ssl.get_mac().get_digestSize();
    size_t finishedSz = ssl.isTLS() ? TLS_FINISHED_SZ : FINISHED_SZ;
    size_t sz  = RECORD_HEADER + HANDSHAKE_HEADER + finishedSz + digestSz;
    size_t pad = 0;
    if (ssl.get_security().cipher_type_ == block) {
        sz += 1;       // pad byte
        size_t blockSz = ssl.get_cipher().get_blockSize();
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

    if (ssl.get_security().cipher_type_ == block)
        for (size_t i = 0; i <= pad; i++) output[AUTO] = pad; // pad byte gets
                                                              // pad value too
    input_buffer cipher(rlHeader.length_);
    ssl.use_cipher().encrypt(cipher.get_buffer(), output.get_buffer() + 
                             RECORD_HEADER, output.get_size() - RECORD_HEADER);
    output.set_current(RECORD_HEADER);
    output.write(cipher.get_buffer(), cipher.get_capacity());
}


// build a data layer message for output
void buildData(SSL& ssl, output_buffer& output, const Data& data)
{
    size_t digestSz = ssl.get_mac().get_digestSize();
    size_t sz  = RECORD_HEADER + data.get_length() + digestSz;                
    size_t pad = 0;
    if (ssl.get_security().cipher_type_ == block) {
        sz += 1;       // pad byte
        size_t blockSz = ssl.get_cipher().get_blockSize();
        pad = (sz - RECORD_HEADER) % blockSz;
        pad = blockSz - pad;
        sz += pad;
    }

    RecordLayerHeader rlHeader;
    buildHeader(ssl, rlHeader, data);
    rlHeader.length_ = sz - RECORD_HEADER;   // record header includes mac
                                             // and pad, hanshake doesn't
    output.allocate(sz);
    output << rlHeader << data;
    
    opaque digest[SHA_LEN];                  // max size
    if (ssl.isTLS())
        TLS_hmac(ssl, digest, output.get_buffer() + RECORD_HEADER,
                 output.get_size() - RECORD_HEADER, application_data);
    else
        hmac(ssl, digest, output.get_buffer() + RECORD_HEADER,
             output.get_size() - RECORD_HEADER, application_data);
    output.write(digest, digestSz);

    if (ssl.get_security().cipher_type_ == block)
        for (size_t i = 0; i <= pad; i++) output[AUTO] = pad; // pad byte gets
                                                              // pad value too
    input_buffer cipher(rlHeader.length_);
    ssl.use_cipher().encrypt(cipher.get_buffer(), output.get_buffer() + 
                             RECORD_HEADER, output.get_size() - RECORD_HEADER);
    output.set_current(RECORD_HEADER);
    output.write(cipher.get_buffer(), cipher.get_capacity());
}


// compute p_hash for MD5 or SHA-1 for TLSv1 PRF
void p_hash(output_buffer& result, const output_buffer& secret,
            const output_buffer& seed, MACAlgorithm hash)
{
    size_t   len = hash == md5 ? MD5_LEN : SHA_LEN;
    size_t   times = result.get_capacity() / len;
    size_t   lastLen = result.get_capacity() % len;
    opaque   previous[SHA_LEN];  // max size
    opaque   current[SHA_LEN];   // max size
    std::auto_ptr<MAC> hmac;

    if (lastLen) times += 1;

    if (hash == md5)
        hmac = std::auto_ptr<MAC>(new HMAC_MD5(secret.get_buffer(),
                                               secret.get_size()));
    else
        hmac = std::auto_ptr<MAC>(new HMAC_SHA(secret.get_buffer(),
                                               secret.get_size()));
                                                                   // A0 = seed
    hmac->get_digest(previous, seed.get_buffer(), seed.get_size());// A1
    size_t lastTime = times - 1;

    for (size_t i = 0; i < times; i++) {
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
void get_xor(byte *digest, size_t digLen, output_buffer& md5,
             output_buffer& sha)
{
    for (size_t i = 0; i < digLen; i++) 
        digest[i] = md5[AUTO] ^ sha[AUTO];
}


// compute TLSv1 PRF (pseudo random function using HMAC)
void PRF(byte* digest, size_t digLen, const byte* secret, size_t secLen,
         const byte* label, size_t labLen, const byte* seed, size_t seedLen)
{
    size_t half = secLen / 2 + secLen % 2;

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


// Process incoming cipherd data into plain
void processData(SSL& ssl, input_buffer& cipher, unsigned int cipherSz, 
                 input_buffer& plain)
{
    size_t curr = cipher.get_current();
    ssl.use_cipher().decrypt(plain.get_buffer(), cipher.get_buffer() + curr,
                             cipherSz);
    cipher.set_current(curr + cipherSz);
}


void sendClientHello(SSL& ssl)
{
    ClientHello       ch(ssl.get_connection().version_);
    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    output_buffer     out;

    buildClientHello(ssl, ch);
    ssl.set_random(ch.get_random(), client_end);
    buildHeaders(ssl, hsHeader, rlHeader, ch);
    buildOutput(out, rlHeader, hsHeader, ch);
    hashHandShake(ssl, out);

    ssl.get_socket().send(out.get_buffer(), out.get_size());
}


static void decrypt_message(SSL& ssl, input_buffer& input, size_t sz)
{
    input_buffer plain(sz);
    opaque*      cipher = input.get_buffer() + input.get_current();

    ssl.use_cipher().decrypt(plain.get_buffer(), cipher, sz);
    memcpy(cipher, plain.get_buffer(), sz);
    ssl.set_security().encrypt_size_ = sz;
}


void processReply(SSL& ssl)
{
    ssl.get_socket().receive(NULL, 0);		   // wait if no input and blocking
    size_t ready = ssl.get_socket().get_ready();
    if (!ready) return;
    input_buffer buffer(ready);
    size_t read  = ssl.get_socket().receive(buffer.get_buffer(),
                                            buffer.get_capacity());
    buffer.add_size(read);
    size_t offset = 0;
    const  MessageFactory& mf = ssl.get_factory().messageFactory_;

    while(!buffer.eof()) {
        // each record
        RecordLayerHeader hdr;
        buffer >> hdr;
        ssl.verifyState(hdr);

        while (buffer.get_current() < hdr.length_ + RECORD_HEADER + offset) {
            // each message in record
            if (ssl.is_encrypted())             // cipher enabled
                decrypt_message(ssl, buffer, hdr.length_);
            std::auto_ptr<Message> msg(mf.CreateObject(hdr.type_));
            buffer >> *msg;
            msg->Process(buffer, ssl);
        }
        offset += hdr.length_ + RECORD_HEADER;
    }
}


void sendClientKeyExchange(SSL& ssl, BufferOutput buffer)
{
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
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}


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
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}


void sendChangeCipher(SSL& ssl, BufferOutput buffer)
{
    ChangeCipherSpec ccs;
    RecordLayerHeader rlHeader;
    buildHeader(ssl, rlHeader, ccs);
    std::auto_ptr<output_buffer> out(new output_buffer);
    buildOutput(*out.get(), rlHeader, ccs);
   
    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}


void sendFinished(SSL& ssl, ConnectionEnd side, BufferOutput buffer)
{
    Finished fin;
    buildFinished(ssl, fin, side == client_end ? client : server);
    std::auto_ptr<output_buffer> out(new output_buffer);
    cipherFinished(ssl, fin, *out.get());               // hashes handshake
    if (side == client_end)
        buildFinished(ssl, ssl.set_verify(), server);   // server's verify

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}


int sendData(SSL& ssl, const Data& data)
{
    output_buffer out;
    buildData(ssl, out, data);
    ssl.get_socket().send(out.get_buffer(), out.get_size());

    return data.get_length();
}


int receiveData(SSL& ssl, Data& data)
{
    if (ssl.bufferedData() < data.get_length())
        processReply(ssl);
    ssl.fillData(data);

    return data.get_length(); 
}


void sendServerHello(SSL& ssl, BufferOutput buffer)
{
    ServerHello       sh(ssl.get_connection().version_);
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
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}


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
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}


void sendCertificate(SSL& ssl, BufferOutput buffer)
{
    Certificate       cert(ssl.get_certManager().get_cert());
    RecordLayerHeader rlHeader;
    HandShakeHeader   hsHeader;
    std::auto_ptr<output_buffer> out(new output_buffer);

    buildHeaders(ssl, hsHeader, rlHeader, cert);
    buildOutput(*out.get(), rlHeader, hsHeader, cert);
    hashHandShake(ssl, *out.get());

    if (buffer == buffered)
        ssl.addBuffer(out.release());
    else
        ssl.get_socket().send(out->get_buffer(), out->get_size());
}
