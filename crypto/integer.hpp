// integer.hpp

#ifndef TAO_CRYPT_INTEGER_HPP__
#define TAO_CRYPT_INTEGER_HPP__

#include "misc.hpp"
#include <cstring>
#include <algorithm>

namespace TaoCrypt {

template<typename T> inline
const T& min(const T& a, const T& b)
{
    return a < b ? a : b;
}

template<typename T> inline
const T& max(const T& a, const T& b)
{
    return a > b ? a : b;
}

word* reallocate(word* p, size_t oldSize, size_t newSize, bool preserve);


class WordBlock {
public:
    explicit WordBlock(size_t s = 0) : sz_(s), buffer_(new word[sz_]) {}

    WordBlock(const word* buff, size_t s) : sz_(s), buffer_(new word[sz_])
        { memcpy(buffer_, buff, sz_ * WORD_SIZE); }

    WordBlock(const WordBlock& other) : sz_(other.sz_), buffer_(new word[sz_])
        { memcpy(buffer_, other.buffer_, sz_ * WORD_SIZE); }

    WordBlock& operator=(const WordBlock& that) {
        WordBlock tmp(that);
        swap(tmp);
        return *this;
    }

    word& operator[] (size_t i) { assert(i < sz_); return buffer_[i]; }
    const word& operator[] (size_t i) const 
        { assert(i < sz_); return buffer_[i]; }

    word* operator+ (size_t i) { return buffer_ + i; }
    const word* operator+ (size_t i) const { return buffer_ + i; }

    size_t size() const { return sz_; }

    word* get_buffer() const { return buffer_; }
    word* begin()      const { return get_buffer(); }

	void CleanGrow(size_t newSize)
	{
		if (newSize > sz_)
		{
			buffer_ = reallocate(buffer_, sz_, newSize, true);
			memset(buffer_ + sz_, 0, (newSize - sz_) * WORD_SIZE);
			sz_ = newSize;
		}
	}

	void CleanNew(unsigned int newSize)
	{
	    New(newSize);
		memset(buffer_, 0, sz_ * WORD_SIZE);
	}

	void New(unsigned int newSize)
	{
    	buffer_ = reallocate(buffer_, sz_, newSize, false);
        sz_ = newSize;
	}

	void resize(unsigned int newSize)
	{
    	buffer_ = reallocate(buffer_, sz_, newSize, true);
        sz_ = newSize;
	}

    void swap(WordBlock& other) {
        std::swap(sz_, other.sz_);
        std::swap(buffer_, other.buffer_);
    }

    ~WordBlock() { delete[] buffer_; }
private:
    size_t sz_;     // size in words
    word*  buffer_;
};


class Integer {
public:
        enum Sign {POSITIVE = 0, NEGATIVE = 1 };
        enum Signedness { UNSIGNED, SIGNED };
        enum RandomNumberType { ANY, PRIME };

        class DivideByZero {};
	
		Integer();
		Integer(const Integer& t);
		Integer(signed long value);
		Integer(Sign s, word highWord, word lowWord);

        explicit Integer(const char* str);
        explicit Integer(const wchar_t* str);
	
        //Integer(const byte* encodedInteger, unsigned int byteCount,
        //        Signedness s = UNSIGNED);
		//Integer(BufferedTransformation &bt, unsigned int byteCount, Signedness s=UNSIGNED);
		//explicit Integer(BufferedTransformation &bt);
		//Integer(RandomNumberGenerator &rng, unsigned int bitcount);
      
        static const Integer &Zero();
        static const Integer &One();
        static const Integer &Two();

        //Integer(RandomNumberGenerator &rng, const Integer &min, const Integer &max, RandomNumberType rnType=ANY, const Integer &equiv=Zero(), const Integer &mod=One());

		static Integer Power2(unsigned int e);

        unsigned int MinEncodedSize(Signedness = UNSIGNED) const;
        //unsigned int Encode(byte* output, unsigned int outputLen,
        //                    Signedness = UNSIGNED) const;

        //unsigned int Encode(BufferedTransformation &bt, unsigned int outputLen, Signedness=UNSIGNED) const;
        //void DEREncode(BufferedTransformation &bt) const;
        //void DEREncodeAsOctetString(BufferedTransformation &bt, unsigned int length) const;

        //unsigned int OpenPGPEncode(byte *output, unsigned int bufferSize) const;
        //unsigned int OpenPGPEncode(BufferedTransformation &bt) const;

        //void Decode(const byte* input, unsigned int inputLen,
        //            Signedness = UNSIGNED);
        //void Decode(BufferedTransformation &bt, unsigned int inputLen, Signedness=UNSIGNED);

        //void BERDecode(const byte* input, unsigned int inputLen);
        //void BERDecode(BufferedTransformation &bt);

        //void BERDecodeAsOctetString(BufferedTransformation &bt, unsigned int length);

        //void OpenPGPDecode(const byte *input, unsigned int inputLen);
	
        //void OpenPGPDecode(BufferedTransformation &bt);

        bool  IsConvertableToLong() const;
        signed long ConvertToLong() const;

        unsigned int BitCount() const;
        unsigned int ByteCount() const;
        unsigned int WordCount() const;

        bool GetBit(unsigned int i) const;
        byte GetByte(unsigned int i) const;
        unsigned long GetBits(unsigned int i, unsigned int n) const;

        bool IsZero()      const { return !*this; }
        bool NotZero()     const { return !IsZero(); }
        bool IsNegative()  const { return sign_ == NEGATIVE; }
        bool NotNegative() const { return !IsNegative(); }
        bool IsPositive()  const { return NotNegative() && NotZero(); }
        bool NotPositive() const { return !IsPositive(); }
        bool IsEven()      const { return GetBit(0) == 0; }
        bool IsOdd()       const { return GetBit(0) == 1; }

        Integer&  operator=(const Integer& t);
        Integer&  operator+=(const Integer& t);
        Integer&  operator-=(const Integer& t);
        Integer&  operator*=(const Integer& t)	{ return *this = Times(t); }
        Integer&  operator/=(const Integer& t)	{ return *this = DividedBy(t);}
        Integer&  operator%=(const Integer& t)	{ return *this = Modulo(t); }
        Integer&  operator/=(word t)  { return *this = DividedBy(t); }
        Integer&  operator%=(word t)  { return *this = Modulo(t); }
        Integer&  operator<<=(unsigned int);
        Integer&  operator>>=(unsigned int);

        /*
        void Randomize(RandomNumberGenerator &rng, unsigned int bitcount);
        void Randomize(RandomNumberGenerator &rng, const Integer &min, const Integer &max);
        bool Randomize(RandomNumberGenerator &rng, const Integer &min, const Integer &max, RandomNumberType rnType, const Integer &equiv=Zero(), const Integer &mod=One());

        bool GenerateRandomNoThrow(RandomNumberGenerator &rng, const NameValuePairs &params = g_nullNameValuePairs);
        void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params = g_nullNameValuePairs)
        {
            if (!GenerateRandomNoThrow(rng, params))
                throw RandomNumberNotFound();
        }
        */

        void SetBit(unsigned int n, bool value = 1);
        void SetByte(unsigned int n, byte value);

        void Negate();		
        void SetPositive() { sign_ = POSITIVE; }
        void SetNegative() { if (!!(*this)) sign_ = NEGATIVE; }
        void swap(Integer& a);

        bool	    operator!() const;
        Integer     operator+() const {return *this;}
        Integer     operator-() const;
        Integer&    operator++();
        Integer&    operator--();
        Integer     operator++(int) 
            { Integer temp = *this; ++*this; return temp; }
        Integer     operator--(int) 
            { Integer temp = *this; --*this; return temp; }

        int Compare(const Integer& a) const;

        Integer Plus(const Integer &b) const;
        Integer Minus(const Integer &b) const;
        Integer Times(const Integer &b) const;
        Integer DividedBy(const Integer &b) const;
        Integer Modulo(const Integer &b) const;
        Integer DividedBy(word b) const;
        word    Modulo(word b) const;

        Integer operator>>(unsigned int n) const { return Integer(*this)>>=n; }
        Integer operator<<(unsigned int n) const { return Integer(*this)<<=n; }

        Integer AbsoluteValue() const;
        Integer Doubled() const { return Plus(*this); }
        Integer Squared() const { return Times(*this); }
        Integer SquareRoot() const;

        bool    IsSquare() const;
		bool    IsUnit() const;

        Integer MultiplicativeInverse() const;

        friend Integer a_times_b_mod_c(const Integer& x, const Integer& y,
                                       const Integer& m);
        friend Integer a_exp_b_mod_c(const Integer& x, const Integer& e,
                                     const Integer& m);

        static void Divide(Integer& r, Integer& q, const Integer& a,
                           const Integer& d);
        static void Divide(word& r, Integer& q, const Integer& a, word d);
        static void DivideByPowerOf2(Integer& r, Integer& q, const Integer& a,
                                     unsigned int n);
        static Integer Gcd(const Integer& a, const Integer& n);

        Integer InverseMod(const Integer& n) const;
        word InverseMod(word n) const;

	    //friend std::istream& operator>>(std::istream& in, Integer &a);
        //friend std::ostream& operator<<(std::ostream& out, const Integer &a);
private:
	friend class ModularArithmetic;
	friend class MontgomeryRepresentation;
	friend class HalfMontgomeryRepresentation;

	Integer(word value, unsigned int length);

	int PositiveCompare(const Integer& t) const;
	friend void PositiveAdd(Integer& sum, const Integer& a, const Integer& b);
	friend void PositiveSubtract(Integer& diff, const Integer& a, const Integer& b);
	friend void PositiveMultiply(Integer& product, const Integer& a,
                                 const Integer& b);
	friend void PositiveDivide(Integer& remainder, Integer& quotient, const
                               Integer& dividend, const Integer& divisor);
	WordBlock reg_;
	Sign      sign_;
};

inline bool operator==(const Integer& a, const Integer& b) {return a.Compare(b)==0;}
inline bool operator!=(const Integer& a, const Integer& b) {return a.Compare(b)!=0;}
inline bool operator> (const Integer& a, const Integer& b) {return a.Compare(b)> 0;}
inline bool operator>=(const Integer& a, const Integer& b) {return a.Compare(b)>=0;}
inline bool operator< (const Integer& a, const Integer& b) {return a.Compare(b)< 0;}
inline bool operator<=(const Integer& a, const Integer& b) {return a.Compare(b)<=0;}

inline Integer operator+(const Integer &a, const Integer &b) {return a.Plus(b);}
inline Integer operator-(const Integer &a, const Integer &b) {return a.Minus(b);}
inline Integer operator*(const Integer &a, const Integer &b) {return a.Times(b);}
inline Integer operator/(const Integer &a, const Integer &b) {return a.DividedBy(b);}
inline Integer operator%(const Integer &a, const Integer &b) {return a.Modulo(b);}
inline Integer operator/(const Integer &a, word b) {return a.DividedBy(b);}
inline word    operator%(const Integer &a, word b) {return a.Modulo(b);}

inline void swap(Integer &a, Integer &b)
{
	a.swap(b);
}



}   // namespace

#endif // TAO_CRYPT_INTEGER_HPP__
