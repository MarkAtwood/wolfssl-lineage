// misc.cpp


#include "misc.hpp"

namespace TaoCrypt {

inline void XorWords(word* r, const word* a, unsigned int n)
{
	for (unsigned int i=0; i<n; i++)
		r[i] ^= a[i];
}


void xorbuf(byte* buf, const byte* mask, unsigned int count)
{
	if (((unsigned int)buf | (unsigned int)mask | count) % WORD_SIZE == 0)
		XorWords((word *)buf, (const word *)mask, count/WORD_SIZE);
	else
	{
		for (unsigned int i=0; i<count; i++)
			buf[i] ^= mask[i];
	}
}


unsigned int BytePrecision(unsigned long value)
{
	unsigned int i;
	for (i=sizeof(value); i; --i)
		if (value >> (i-1)*8)
			break;

	return i;
}


unsigned int BitPrecision(unsigned long value)
{
	if (!value)
		return 0;

	unsigned int l = 0,
                 h = 8 * sizeof(value);

	while (h-l > 1)
	{
		unsigned int t = (l+h)/2;
		if (value >> t)
			l = t;
		else
			h = t;
	}

	return h;
}


unsigned long Crop(unsigned long value, unsigned int size)
{
	if (size < 8*sizeof(value))
    	return (value & ((1L << size) - 1));
	else
		return value;
}




}  // namespace

