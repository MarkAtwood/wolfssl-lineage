#ifndef CRYPTOPP_RIJNDAEL_H
#define CRYPTOPP_RIJNDAEL_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class Rijndael : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength <= 16 ? 16 : (keylength <= 24 ? 24 : 32);}

protected:
	Rijndael(const byte *userKey, unsigned int keylength);

	static const word32 Te0[256];
	static const word32 Te1[256];
	static const word32 Te2[256];
	static const word32 Te3[256];
	static const word32 Te4[256];

	static const word32 Td0[256];
	static const word32 Td1[256];
	static const word32 Td2[256];
	static const word32 Td3[256];
	static const word32 Td4[256];

	static const word32 rcon[];

	unsigned int m_rounds;
	SecBlock<word32> m_key;
};

class RijndaelEncryption : public Rijndael
{
public:
	RijndaelEncryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Rijndael(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{RijndaelEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class RijndaelDecryption : public Rijndael
{
public:
	RijndaelDecryption(const byte *userKey, unsigned int keylength=KEYLENGTH);

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{RijndaelDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
