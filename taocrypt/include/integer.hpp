/* integer.hpp                                
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


#ifndef TAO_CRYPT_INTEGER_HPP
#define TAO_CRYPT_INTEGER_HPP

#include "misc.hpp"
#include "block.hpp"
#include "random.hpp"
#include "file.hpp"
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

        // BER Decode Sink
        explicit Integer(Sink&);

        Integer(const byte* encodedInteger, unsigned int byteCount,
                Signedness s = UNSIGNED);

        ~Integer() {}
      
        static const Integer &Zero();
        static const Integer &One();
        static const Integer &Two();

        Integer& Ref() { return *this; }

        Integer(RandomNumberGenerator& rng, const Integer& min,
                const Integer& max);

        static Integer Power2(unsigned int e);

        unsigned int MinEncodedSize(Signedness = UNSIGNED) const;
        unsigned int Encode(byte* output, unsigned int outputLen,
                            Signedness = UNSIGNED) const;

        void Decode(const byte* input, unsigned int inputLen,
                    Signedness = UNSIGNED);
        void Decode(Sink&);

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
        Integer&  operator/=(const Integer& t)	
                        { return *this = DividedBy(t);}
        Integer&  operator%=(const Integer& t)	{ return *this = Modulo(t); }
        Integer&  operator/=(word t)  { return *this = DividedBy(t); }
        Integer&  operator%=(word t)  { return *this = Modulo(t); }
        Integer&  operator<<=(unsigned int);
        Integer&  operator>>=(unsigned int);

     
        void Randomize(RandomNumberGenerator &rng, unsigned int bitcount);
        void Randomize(RandomNumberGenerator &rng, const Integer &min,
                       const Integer &max);

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

private:
    friend class ModularArithmetic;
    friend class MontgomeryRepresentation;
    friend class HalfMontgomeryRepresentation;

    Integer(word value, unsigned int length);

    int PositiveCompare(const Integer& t) const;
    friend void PositiveAdd(Integer& sum, const Integer& a, const Integer& b);
    friend void PositiveSubtract(Integer& diff, const Integer& a,
                                 const Integer& b);
    friend void PositiveMultiply(Integer& product, const Integer& a,
                                 const Integer& b);
    friend void PositiveDivide(Integer& remainder, Integer& quotient, const
                               Integer& dividend, const Integer& divisor);
    WordBlock reg_;
    Sign      sign_;
};

inline bool operator==(const Integer& a, const Integer& b) 
                        {return a.Compare(b)==0;}
inline bool operator!=(const Integer& a, const Integer& b) 
                        {return a.Compare(b)!=0;}
inline bool operator> (const Integer& a, const Integer& b) 
                        {return a.Compare(b)> 0;}
inline bool operator>=(const Integer& a, const Integer& b) 
                        {return a.Compare(b)>=0;}
inline bool operator< (const Integer& a, const Integer& b) 
                        {return a.Compare(b)< 0;}
inline bool operator<=(const Integer& a, const Integer& b) 
                        {return a.Compare(b)<=0;}

inline Integer operator+(const Integer &a, const Integer &b) 
                        {return a.Plus(b);}
inline Integer operator-(const Integer &a, const Integer &b) 
                        {return a.Minus(b);}
inline Integer operator*(const Integer &a, const Integer &b) 
                        {return a.Times(b);}
inline Integer operator/(const Integer &a, const Integer &b) 
                        {return a.DividedBy(b);}
inline Integer operator%(const Integer &a, const Integer &b) 
                        {return a.Modulo(b);}
inline Integer operator/(const Integer &a, word b) {return a.DividedBy(b);}
inline word    operator%(const Integer &a, word b) {return a.Modulo(b);}

inline void swap(Integer &a, Integer &b)
{
    a.swap(b);
}


Integer CRT(const Integer& xp, const Integer& p, const Integer& xq,
            const Integer& q,  const Integer& u);
inline Integer ModularExponentiation(const Integer& a, const Integer& e,
                                     const Integer& m)
{
    return a_exp_b_mod_c(a, e, m);
}

Integer ModularRoot(const Integer& a, const Integer& dp, const Integer& dq,
                    const Integer& p, const Integer& q,  const Integer& u);



}   // namespace

#endif // TAO_CRYPT_INTEGER_HPP
