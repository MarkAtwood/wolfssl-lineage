// misc.hpp

#ifndef TAO_CRYPT_MISC_HPP__
#define TAO_CRYPT_MISC_HPP__

#include <stdlib.h>
#include <assert.h>

namespace TaoCrypt {

typedef unsigned short uint16;
typedef unsigned long  uint32;
typedef unsigned char  byte;

// tao TODO: fix these
typedef unsigned __int32 word;
typedef unsigned __int64 dword;
const size_t WORD_SIZE = sizeof(word);
const size_t WORD_BITS = WORD_SIZE * 8;


#define LOW_WORD(x) (word)(x)

union dword_union
{
	dword_union (const dword &dw) : dw(dw) {}
	dword dw;
	word w[2];
};

#ifndef BIG_ENDIAN
#	define HIGH_WORD(x) (dword_union(x).w[1])
#else
#	define HIGH_WORD(x) (dword_union(x).w[0])
#endif

#define MAKE_DWORD(lowWord, hiWord) ((dword(hiWord)<<WORD_BITS) | (lowWord))


inline unsigned int BitsToBytes(unsigned int bitCount)
{
	return ((bitCount+7)/(8));
}

inline unsigned int BytesToWords(unsigned int byteCount)
{
	return ((byteCount+WORD_SIZE-1)/WORD_SIZE);
}

inline unsigned int BitsToWords(unsigned int bitCount)
{
	return ((bitCount+WORD_BITS-1)/(WORD_BITS));
}

inline void CopyWords(word* r, const word* a, size_t n)
{
	for (size_t i = 0; i < n; i++)
		r[i] = a[i];
}

inline unsigned int CountWords(const word* X, unsigned int N)
{
	while (N && X[N-1]==0)
		N--;
	return N;
}

inline void SetWords(word* r, word a, unsigned int n)
{
	for (unsigned int i=0; i<n; i++)
		r[i] = a;
}

enum ByteOrder { LittleEndianOrder = 0, BigEndianOrder = 1 };
enum CipherDir {ENCRYPTION,	DECRYPTION};

inline CipherDir ReverseDir(CipherDir dir)
{
	return (dir == ENCRYPTION) ? DECRYPTION : ENCRYPTION;
}

template <typename ENUM_TYPE, int VALUE>
struct EnumToType
{
    static ENUM_TYPE ToEnum() { return (ENUM_TYPE)VALUE; }
};

typedef EnumToType<ByteOrder, LittleEndianOrder> LittleEndian;
typedef EnumToType<ByteOrder, BigEndianOrder>    BigEndian;


#ifndef BIG_ENDIAN
	typedef LittleEndian HostByteOrder;
#else
	typedef BigEndian    HostByteOrder;
#endif

inline ByteOrder GetHostByteOrder()
{
	return HostByteOrder::ToEnum();
}

inline bool HostByteOrderIs(ByteOrder order)
{
	return order == GetHostByteOrder();
}


void xorbuf(byte*, const byte*, unsigned int);


template <class T>
inline bool IsPowerOf2(T n)
{
	return n > 0 && (n & (n-1)) == 0;
}

template <class T1, class T2>
inline T2 ModPowerOf2(T1 a, T2 b)
{
	assert(IsPowerOf2(b));
	return T2(a) & (b-1);
}

template <class T>
inline T RoundDownToMultipleOf(T n, T m)
{
	return n - (IsPowerOf2(m) ? ModPowerOf2(n, m) : (n%m));
}

template <class T>
inline T RoundUpToMultipleOf(T n, T m)
{
	return RoundDownToMultipleOf(n+m-1, m);
}

template <class T>
inline unsigned int GetAlignment(T *dummy=NULL)	// VC60 workaround
{
#if (_MSC_VER >= 1300)
	return __alignof(T);
#elif defined(__GNUC__)
	return __alignof__(T);
#else
	return sizeof(T);
#endif
}

inline bool IsAlignedOn(const void *p, unsigned int alignment)
{
	return IsPowerOf2(alignment) ? ModPowerOf2((unsigned int)p, alignment) == 0
        : (unsigned int)p % alignment == 0;
}

template <class T>
inline bool IsAligned(const void *p, T *dummy=NULL)	// VC60 workaround
{
	return IsAlignedOn(p, GetAlignment<T>());
}



inline uint32 rotlFixed(uint32 x, size_t y)
{
    assert(y < 32);
    return y ? _lrotl(x, y) : x;
}

inline uint32 rotrFixed(uint32 x, size_t y)
{
    assert(y < 32);
    return y ? _lrotr(x, y) : x;
}

#ifdef min
#undef min
#endif 

inline uint32 min(uint32 a, uint32 b)
{
    return a < b ? a : b;
}


inline uint32 ByteReverse(uint32 value)
{
    return (rotrFixed(value, 8U) & 0xff00ff00) | 
           (rotlFixed(value, 8U) & 0x00ff00ff);
}


inline void ByteReverse(uint32* out, const uint32* in, size_t byteCount)
{
    assert(byteCount % sizeof(uint32) == 0);
    size_t count = byteCount/sizeof(uint32);
    for (size_t i=0; i<count; i++)
        out[i] = ByteReverse(in[i]);
}


inline void ByteReverse(byte* out, const byte* in, size_t byteCount)
{
    uint32* o       = reinterpret_cast<uint32*>(out);
    const uint32* i = reinterpret_cast<const uint32*>(in);
    ByteReverse(o, i, byteCount);
}


template <class T>
inline T ByteReverseIf(T value, ByteOrder order)
{
	return HostByteOrderIs(order) ? value : ByteReverse(value);
}


template <typename T>
inline void ByteReverseIf(T* out, const T* in, size_t bc, ByteOrder order)
{
    if (!HostByteOrderIs(order)) 
        ByteReverse(out, in, bc);
    else if (out != in)
        memcpy(out, in, bc);
}


#ifdef _MSC_VER
    // disable conversion warning
    #pragma warning(disable:4244)
#endif


// convert 32 bit integer to byte
inline void write32(uint32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}

// convert 64 bit integer to High byte  TODO: make 64
inline void write64(uint32 u32, byte* c)
{
    c[0] = 0;
    c[1] = 0;
    c[2] = 0;
    c[3] = 0;
    c[4] =  u32 & 0xff;
    c[5] = (u32 >>  8)  & 0xff;
    c[6] = (u32 >>  16) & 0xff;
    c[7] = (u32 >>  24) & 0xff; 
}

// convert 64 bit integer to Low byte  TODO: make 64
inline void write64L(uint32 u32, byte* c)
{
    c[0] =  u32 & 0xff;
    c[1] = (u32 >>  8)  & 0xff;
    c[2] = (u32 >>  16) & 0xff;
    c[3] = (u32 >>  24) & 0xff; 
    c[4] = 0;
    c[5] = 0;
    c[6] = 0;
    c[7] = 0;
}

inline void write64Order(uint32 u32, byte* c, ByteOrder order)
{
    if (order == LittleEndianOrder)
        write64L(u32, c);
    else
        write64(u32, c);
}



inline byte UnalignedGetWordNonTemplate(ByteOrder order, const byte *block,
                                        byte*)
{
	return block[0];
}

inline uint16 UnalignedGetWordNonTemplate(ByteOrder order, const byte* block,
                                          uint16*)
{
	return (order == BigEndianOrder)
		? block[1] | (block[0] << 8)
		: block[0] | (block[1] << 8);
}

inline uint32 UnalignedGetWordNonTemplate(ByteOrder order, const byte* block,
                                          uint32*)
{
	return (order == BigEndianOrder)
		? uint32(block[3]) | (uint32(block[2]) << 8) | (uint32(block[1]) << 16)
            | (uint32(block[0]) << 24)
		: uint32(block[0]) | (uint32(block[1]) << 8) | (uint32(block[2]) << 16)
            | (uint32(block[3]) << 24);
}

template <class T>
inline T UnalignedGetWord(ByteOrder order, const byte *block, T*dummy=NULL)
{
	return UnalignedGetWordNonTemplate(order, block, dummy);
}

inline void UnalignedPutWord(ByteOrder order, byte *block, byte value,
                             const byte *xorBlock = NULL)
{
	block[0] = xorBlock ? (value ^ xorBlock[0]) : value;
}

#define GETBYTE(x, y) (unsigned int)byte((x)>>(8*(y)))

inline void UnalignedPutWord(ByteOrder order, byte *block, uint16 value,
                             const byte *xorBlock = NULL)
{
	if (order == BigEndianOrder)
	{
		block[0] = GETBYTE(value, 1);
		block[1] = GETBYTE(value, 0);
	}
	else
	{
		block[0] = GETBYTE(value, 0);
		block[1] = GETBYTE(value, 1);
	}

	if (xorBlock)
	{
		block[0] ^= xorBlock[0];
		block[1] ^= xorBlock[1];
	}
}

inline void UnalignedPutWord(ByteOrder order, byte* block, uint32 value,
                             const byte* xorBlock = NULL)
{
	if (order == BigEndianOrder)
	{
		block[0] = GETBYTE(value, 3);
		block[1] = GETBYTE(value, 2);
		block[2] = GETBYTE(value, 1);
		block[3] = GETBYTE(value, 0);
	}
	else
	{
		block[0] = GETBYTE(value, 0);
		block[1] = GETBYTE(value, 1);
		block[2] = GETBYTE(value, 2);
		block[3] = GETBYTE(value, 3);
	}

	if (xorBlock)
	{
		block[0] ^= xorBlock[0];
		block[1] ^= xorBlock[1];
		block[2] ^= xorBlock[2];
		block[3] ^= xorBlock[3];
	}
}


template <class T>
inline T GetWord(bool assumeAligned, ByteOrder order, const byte *block)
{
	if (assumeAligned)
	{
		assert(IsAligned<T>(block));
		return ByteReverseIf(*reinterpret_cast<const T *>(block), order);
	}
	else
		return UnalignedGetWord<T>(order, block);
}

template <class T>
inline void GetWord(bool assumeAligned, ByteOrder order, T &result,
                    const byte *block)
{
	result = GetWord<T>(assumeAligned, order, block);
}

template <class T>
inline void PutWord(bool assumeAligned, ByteOrder order, byte* block, T value,
                    const byte *xorBlock = NULL)
{
	if (assumeAligned)
	{
		assert(IsAligned<T>(block));
		if (xorBlock)
			*reinterpret_cast<T *>(block) = ByteReverseIf(value, order) 
                ^ *reinterpret_cast<const T *>(xorBlock);
		else
			*reinterpret_cast<T *>(block) = ByteReverseIf(value, order);
	}
	else
		UnalignedPutWord(order, block, value, xorBlock);
}

template <class T, class B, bool A=true>
class GetBlock
{
public:
	GetBlock(const void *block)
		: m_block((const byte *)block) {}

	template <class U>
	inline GetBlock<T, B, A> & operator()(U &x)
	{
		//CRYPTOPP_COMPILE_ASSERT(sizeof(U) >= sizeof(T));
		x = GetWord<T>(A, B::ToEnum(), m_block);
		m_block += sizeof(T);
		return *this;
	}

private:
	const byte *m_block;
};

template <class T, class B, bool A = true>
class PutBlock
{
public:
	PutBlock(const void *xorBlock, void *block)
		: m_xorBlock((const byte *)xorBlock), m_block((byte *)block) {}

	template <class U>
	inline PutBlock<T, B, A> & operator()(U x)
	{
		PutWord(A, B::ToEnum(), m_block, (T)x, m_xorBlock);
		m_block += sizeof(T);
		if (m_xorBlock)
			m_xorBlock += sizeof(T);
		return *this;
	}

private:
	const byte *m_xorBlock;
	byte *m_block;
};

template <class T, class B, bool A=true>
struct BlockGetAndPut
{
	// function needed because of C++ grammatical ambiguity between
    // expression-statements and declarations
	static inline GetBlock<T, B, A> Get(const void *block) 
        {return GetBlock<T, B, A>(block);}
	typedef PutBlock<T, B, A> Put;
};



template <bool overflow> struct SafeShifter;

template<> struct SafeShifter<true>
{
	template <class T>
	static inline T RightShift(T value, unsigned int bits)
	{
		return 0;
	}

	template <class T>
	static inline T LeftShift(T value, unsigned int bits)
	{
		return 0;
	}
};

template<> struct SafeShifter<false>
{
	template <class T>
	static inline T RightShift(T value, unsigned int bits)
	{
		return value >> bits;
	}

	template <class T>
	static inline T LeftShift(T value, unsigned int bits)
	{
		return value << bits;
	}
};

template <unsigned int bits, class T>
inline T SafeRightShift(T value)
{
	return SafeShifter<(bits>=(8*sizeof(T)))>::RightShift(value, bits);
}

template <unsigned int bits, class T>
inline T SafeLeftShift(T value)
{
	return SafeShifter<(bits>=(8*sizeof(T)))>::LeftShift(value, bits);
}


inline word ShiftWordsLeftByBits(word *r, unsigned int n, unsigned int shiftBits)
{
	assert (shiftBits<WORD_BITS);
	word u, carry=0;
	if (shiftBits)
		for (unsigned int i=0; i<n; i++)
		{
			u = r[i];
			r[i] = (u << shiftBits) | carry;
			carry = u >> (WORD_BITS-shiftBits);
		}
	return carry;
}

inline word ShiftWordsRightByBits(word *r, unsigned int n, unsigned int shiftBits)
{
	assert (shiftBits<WORD_BITS);
	word u, carry=0;
	if (shiftBits)
		for (int i=n-1; i>=0; i--)
		{
			u = r[i];
			r[i] = (u >> shiftBits) | carry;
			carry = u << (WORD_BITS-shiftBits);
		}
	return carry;
}

inline void ShiftWordsLeftByWords(word *r, unsigned int n, unsigned int shiftWords)
{
	shiftWords = min(shiftWords, n);
	if (shiftWords)
	{
		for (unsigned int i=n-1; i>=shiftWords; i--)
			r[i] = r[i-shiftWords];
		SetWords(r, 0, shiftWords);
	}
}

inline void ShiftWordsRightByWords(word *r, unsigned int n, unsigned int shiftWords)
{
	shiftWords = min(shiftWords, n);
	if (shiftWords)
	{
		for (unsigned int i=0; i+shiftWords<n; i++)
			r[i] = r[i+shiftWords];
		SetWords(r+n-shiftWords, 0, shiftWords);
	}
}


// declares
unsigned int BytePrecision(unsigned long value);
unsigned int BitPrecision(unsigned long);


} // namespace

#endif //
