// adler32.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "adler32.h"

NAMESPACE_BEGIN(CryptoPP)

void Adler32::Update(const byte *input, unsigned int length)
{
	const unsigned long BASE = 65521;

	unsigned long s1 = m_s1;
	unsigned long s2 = m_s2;

	while (length--)
	{
		s1 += *input++;
		if (s1 >= BASE)
			s1 -= BASE;
		s2 += s1;
		if (length & 0xffff == 0)
			s2 %= BASE;
	}

	m_s1 = (word16)s1;
	m_s2 = (word16)s2;
}

void Adler32::Final(byte *hash)
{
	hash[0] = byte(m_s2 >> 8);
	hash[1] = byte(m_s2);
	hash[2] = byte(m_s1 >> 8);
	hash[3] = byte(m_s1);

	Reset();
}

NAMESPACE_END
