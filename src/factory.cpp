/* factory.cpp
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

/*  The factory source implements an Object Factory for the SSL message and
 *  handshake types.
 *
 *  See Desgin Pattern in GoF and Alexandrescu's chapter in Modern C++ Design.
 */


#include "yassl_imp.hpp"
#include "factory.hpp"



// Constructor calls this to Register compile time callbacks
void InitMessageFactory(MessageFactory& mf)
{
    mf.Register(alert, CreateAlert);
    mf.Register(change_cipher_spec, CreateCipherSpec);
    mf.Register(handshake, CreateHandShake);
    mf.Register(application_data, CreateData);
}


// Constructor calls this to Register compile time callbacks
void InitHandShakeFactory(HandShakeFactory& hsf)
{
    hsf.Register(hello_request, CreateHelloRequest);
    hsf.Register(client_hello, CreateClientHello);
    hsf.Register(server_hello, CreateServerHello);
    hsf.Register(certificate, CreateCertificate);
    hsf.Register(server_key_exchange, CreateServerKeyExchange);
    hsf.Register(certificate_request, CreateCertificateRequest);
    hsf.Register(server_hello_done, CreateServerHelloDone);
    hsf.Register(certificate_verify, CreateCertificateVerify);
    hsf.Register(client_key_exchange, CreateClientKeyExchange);
    hsf.Register(finished, CreateFinished);
}


// Constructor calls this to Register compile time callbacks
void InitServerKeyFactory(ServerKeyFactory& skf)
{
    skf.Register(rsa_kea, CreateRSAServerKEA);
    skf.Register(diffie_hellman_kea, CreateDHServerKEA);
    skf.Register(fortezza_kea, CreateFortezzaServerKEA);
}


// Constructor calls this to Register compile time callbacks
void InitClientKeyFactory(ClientKeyFactory& ckf)
{
    ckf.Register(rsa_kea, CreateRSAClient);
    ckf.Register(diffie_hellman_kea, CreateDHClient);
    ckf.Register(fortezza_kea, CreateFortezzaClient);
}
