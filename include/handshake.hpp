/* handshake.hpp                               
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

/* The handshake header declares function prototypes for creating and reading
 * the various handshake messages.
 */



#ifndef __yaSSL_handshake_hpp__
#define __yaSSL_handshake_hpp__

#include "yassl_imp.hpp"
#include "yassl_int.hpp"
#include "buffer.hpp"

enum BufferOutput { buffered, unbuffered };

void buildClientHello(SSL&, ClientHello&, CompressionMethod = no_compression);
void buildHeader(SSL&, RecordLayerHeader&, const Message&);
void buildHeaders(SSL&, HandShakeHeader&, RecordLayerHeader&,
                  const HandShakeBase&);
void buildOutput(output_buffer&, const RecordLayerHeader&, const Message&);
void buildOutput(output_buffer&, const RecordLayerHeader&, 
                const HandShakeHeader&, const HandShakeBase&);
void buildFinished(SSL&, Finished&, const opaque*);

void hashHandShake(SSL&, const output_buffer&);
void hashHandShake(SSL&, const input_buffer&, unsigned int);

void cipherFinished(SSL&, Finished&, output_buffer&);
void verifyFinished(SSL&, input_buffer&, unsigned int);

void buildData(SSL&, output_buffer&, const Data&);
void processData(SSL&, input_buffer&, unsigned int, input_buffer&);

void sendClientHello(SSL&);
void sendServerHello(SSL&, BufferOutput = buffered);
void sendServerHelloDone(SSL&, BufferOutput = buffered);
void sendClientKeyExchange(SSL&, BufferOutput = buffered);
void sendChangeCipher(SSL&, BufferOutput = buffered);
void sendFinished(SSL&, ConnectionEnd, BufferOutput = buffered);
void sendCertificate(SSL&, BufferOutput = buffered);
int  sendData(SSL&, const Data&);

int  receiveData(SSL&, Data&);
void processReply(SSL&);

void hmac(SSL&, byte*, const byte*, size_t, ContentType, bool verify = false);
void TLS_hmac(SSL&, byte*, const byte*, size_t, ContentType,
              bool verify = false);
void PRF(byte* digest, size_t digLen, const byte* secret, size_t secLen,
         const byte* label, size_t labLen, const byte* seed, size_t seedLen);


#endif // __yaSSL_handshake_hpp__
