#ifndef CRYPTOPP_TWOFISH_H
#define CRYPTOPP_TWOFISH_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class Twofish : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return STDMIN(keylength, 32U);}

protected:
	Twofish(const byte *userKey, unsigned int keylength);
	static word32 h0(word32 x, const word32 *key, unsigned int kLen);
	static word32 h(word32 x, const word32 *key, unsigned int kLen);

	static const byte q[2][256];
	static const word32 mds[4][256];

	SecBlock<word32> m_k;
	SecBlock<word32[256]> m_s;
};

class TwofishEncryption : public Twofish
{
public:
	TwofishEncryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Twofish(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{TwofishEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class TwofishDecryption : public Twofish
{
public:
	TwofishDecryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Twofish(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{TwofishDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
