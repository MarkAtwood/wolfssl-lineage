// aes.hpp

#ifndef TAO_CRYPT_AES_HPP__
#define TAO_CRYPT_AES_HPP__

#include <string.h>
#include "misc.hpp"
#include "modes.hpp"
#include "block.hpp"

namespace TaoCrypt {

enum { AES_BLOCK_SIZE = 16 };

class AES : public Mode_BASE<AES_BLOCK_SIZE> {
public:
    enum { BLOCK_SIZE = AES_BLOCK_SIZE };

    AES(CipherDir DIR, Mode MODE) : dir_(DIR), mode_(MODE) {}
    virtual ~AES() {}

    void Process(byte*, const byte*, size_t);
    void SetKey(const byte* iv, size_t sz, CipherDir fake = ENCRYPTION);

    void ProcessAndXorBlock(const byte*, const byte*, byte*) const;
private:
    CipherDir dir_;
    Mode      mode_;

	static const uint32 Te0[256];
	static const uint32 Te1[256];
	static const uint32 Te2[256];
	static const uint32 Te3[256];
	static const uint32 Te4[256];

	static const uint32 Td0[256];
	static const uint32 Td1[256];
	static const uint32 Td2[256];
	static const uint32 Td3[256];
	static const uint32 Td4[256];

	static const uint32 rcon_[];

	size_t    rounds_;
	WordBlock key_;

    void encrypt(const byte*, const byte*, byte*) const;
    void decrypt(const byte*, const byte*, byte*) const;
};


typedef BlockCipher<ENCRYPTION, AES, ECB> AES_ECB_Encryption;
typedef BlockCipher<DECRYPTION, AES, ECB> AES_ECB_Decryption;

typedef BlockCipher<ENCRYPTION, AES, CBC> AES_CBC_Encryption;
typedef BlockCipher<DECRYPTION, AES, CBC> AES_CBC_Decryption;



} // naemspace

#endif // TAO_CRYPT_AES_HPP__
