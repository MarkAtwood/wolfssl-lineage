// asn.hpp

#ifndef TAO_CRYPT_ASN_HPP__
#define TAO_CRYPT_ASN_HPP__


#include "misc.hpp"
#include "block.hpp"



namespace TaoCrypt {

// these tags and flags are not complete
enum ASNTag
{
    BOOLEAN 			= 0x01,
    INTEGER 			= 0x02,
    BIT_STRING			= 0x03,
    OCTET_STRING		= 0x04,
    TAG_NULL			= 0x05,
    OBJECT_IDENTIFIER	= 0x06,
    OBJECT_DESCRIPTOR	= 0x07,
    EXTERNAL			= 0x08,
    REAL				= 0x09,
    ENUMERATED			= 0x0a,
    UTF8_STRING			= 0x0c,
    SEQUENCE			= 0x10,
    SET 				= 0x11,
    NUMERIC_STRING		= 0x12,
    PRINTABLE_STRING 	= 0x13,
    T61_STRING			= 0x14,
    VIDEOTEXT_STRING 	= 0x15,
    IA5_STRING			= 0x16,
    UTC_TIME 			= 0x17,
    GENERALIZED_TIME 	= 0x18,
    GRAPHIC_STRING		= 0x19,
    VISIBLE_STRING		= 0x1a,
    GENERAL_STRING		= 0x1b,
    LONG_LENGTH         = 0x80
};

enum ASNIdFlag
{
    UNIVERSAL			= 0x00,
    DATA				= 0x01,
    HEADER				= 0x02,
    CONSTRUCTED 		= 0x20,
    APPLICATION 		= 0x40,
    CONTEXT_SPECIFIC	= 0x80,
    PRIVATE 			= 0xc0
};


class Sink;
class RSA_PublicKey;
class RSA_PrivateKey;
class Integer;


class BER_Decoder {
protected:
    Sink& sink_;
public:
    explicit BER_Decoder(Sink& s) : sink_(s) {}

    virtual void     ReadHeader() = 0;
            Integer& GetInteger(Integer&);
};

class RSA_Private_Decoder : public BER_Decoder {
public:
    explicit RSA_Private_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(RSA_PrivateKey&);
private:
    void ReadHeader();
};


class RSA_Public_Decoder : public BER_Decoder {
public:
    explicit RSA_Public_Decoder(Sink& s) : BER_Decoder(s) {}
    void Decode(RSA_PublicKey&);
private:
    void ReadHeader();
};



} // namespace


#endif // TAO_CRYPT_ASN_HPP__
