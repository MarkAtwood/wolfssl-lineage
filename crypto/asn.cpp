// asn.cpp

#include "asn.hpp"
#include "file.hpp"
#include "integer.hpp"
#include "rsa.hpp"


namespace TaoCrypt {


Integer& BER_Decoder::GetInteger(Integer& integer)
{
    integer.Decode(sink_);
    return integer;
}

void RSA_Private_Decoder::Decode(RSA_PrivateKey& key)
{
    ReadHeader();

    // public
    key.SetModulus(GetInteger(Integer().Ref()));
    key.SetPublicExponent(GetInteger(Integer().Ref()));

    // private
    key.SetPrivateExponent(GetInteger(Integer().Ref()));
    key.SetPrime1(GetInteger(Integer().Ref()));
    key.SetPrime2(GetInteger(Integer().Ref()));
    key.SetModPrime1PrivateExponent(GetInteger(Integer().Ref()));
    key.SetModPrime2PrivateExponent(GetInteger(Integer().Ref()));
    key.SetMultiplicativeInverseOfPrime2ModPrime1(GetInteger(Integer().Ref()));
}


class BadHeader {};

void RSA_Private_Decoder::ReadHeader()
{
    byte b = sink_.next();
    if (b != (SEQUENCE | CONSTRUCTED)) throw BadHeader();  // sequence

    b = sink_.next();
    if (b >= LONG_LENGTH) {        // total length
        b = b >> 6;

        for (int i = 0; i < b; i++)
            sink_.next();
    }
    else
        sink_.next();

    b = sink_.next();
    if (b != INTEGER) throw BadHeader();  // version

    b = sink_.next();
    if (b != 0x01) throw BadHeader();  // length not 1

    b = sink_.next();
    if (b != 0x00 && b != 0x01) throw BadHeader(); // version incorrect
}


void RSA_Public_Decoder::Decode(RSA_PublicKey& key)
{
    ReadHeader();

    // public
    key.SetModulus(GetInteger(Integer().Ref()));
    key.SetPublicExponent(GetInteger(Integer().Ref()));
}


void RSA_Public_Decoder::ReadHeader()
{
    byte b = sink_.next();
    if (b != (SEQUENCE | CONSTRUCTED)) throw BadHeader();  // sequence

    b = sink_.next();
    if (b >= LONG_LENGTH) {        // total length
        b = b >> 6;

        for (int i = 0; i < b; i++)
            sink_.next();
    }
    else
        sink_.next();

    b = sink_.next();
    if (b != INTEGER) throw BadHeader();  // version

    b = sink_.next();
    if (b != 0x01) throw BadHeader();  // length not 1

    b = sink_.next();
    if (b != 0x00 && b != 0x01) throw BadHeader(); // version incorrect
}



} // namespace
