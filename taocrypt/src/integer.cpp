/* integer.cpp                                
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



/* based on Wei Dai's integer.cpp from CryptoPP */

#ifdef _MSC_VER
    // 4250: dominance
    // 4660: explicitly instantiating a class already implicitly instantiated
    // 4661: no suitable definition provided for explicit template request
    // 4786: identifer was truncated in debug information
    // 4355: 'this' : used in base member initializer list
#   pragma warning(disable: 4250 4660 4661 4786 4355)
#endif

#include "integer.hpp"
#include "algebra.cpp"
#include "modarith.hpp"
#include "asn.hpp"
#include <stdexcept>


namespace TaoCrypt {


// ********  start of integer needs


static const unsigned int RoundupSizeTable[] = {2, 2, 2, 4, 4, 8, 8, 8, 8};

static inline unsigned int RoundupSize(unsigned int n)
{
    if (n<=8)
        return RoundupSizeTable[n];
    else if (n<=16)
        return 16;
    else if (n<=32)
        return 32;
    else if (n<=64)
        return 64;
    else return 1U << BitPrecision(n-1);
}


template <class T>
static Integer StringToInteger(const T *str)
{
    word radix;
#if (defined(__GNUC__) && __GNUC__ <= 3)        // GCC workaround
    // std::char_traits doesn't exist in GCC 2.x
    // std::char_traits<wchar_t>::length() not defined in GCC 3.2
    unsigned int length;
    for (length = 0; str[length] != 0; length++) {}
#else
    unsigned int length = std::char_traits<T>::length(str);
#endif

    Integer v;

    if (length == 0)
        return v;

    switch (str[length-1])
    {
    case 'h':
    case 'H':
        radix=16;
        break;
    case 'o':
    case 'O':
        radix=8;
        break;
    case 'b':
    case 'B':
        radix=2;
        break;
    default:
        radix=10;
    }

    if (length > 2 && str[0] == '0' && str[1] == 'x')
        radix = 16;

    for (unsigned i=0; i<length; i++)
    {
        word digit;

        if (str[i] >= '0' && str[i] <= '9')
            digit = str[i] - '0';
        else if (str[i] >= 'A' && str[i] <= 'F')
            digit = str[i] - 'A' + 10;
        else if (str[i] >= 'a' && str[i] <= 'f')
            digit = str[i] - 'a' + 10;
        else
            digit = radix;

        if (digit < radix)
        {
            v *= radix;
            v += digit;
        }
    }

    if (str[0] == '-')
        v.Negate();

    return v;
}

static int Compare(const word *A, const word *B, unsigned int N)
{
    while (N--)
        if (A[N] > B[N])
            return 1;
        else if (A[N] < B[N])
            return -1;

    return 0;
}

static word Increment(word *A, unsigned int N, word B=1)
{
    assert(N);
    word t = A[0];
    A[0] = t+B;
    if (A[0] >= t)
        return 0;
    for (unsigned i=1; i<N; i++)
        if (++A[i])
            return 0;
    return 1;
}

static word Decrement(word *A, unsigned int N, word B=1)
{
    assert(N);
    word t = A[0];
    A[0] = t-B;
    if (A[0] <= t)
        return 0;
    for (unsigned i=1; i<N; i++)
        if (A[i]--)
            return 0;
    return 1;
}

static void TwosComplement(word *A, unsigned int N)
{
    Decrement(A, N);
    for (unsigned i=0; i<N; i++)
        A[i] = ~A[i];
}


static word LinearMultiply(word *C, const word *A, word B, unsigned int N)
{
    word carry=0;
    for(unsigned i=0; i<N; i++)
    {
        dword p = (dword)A[i] * B + carry;
        C[i] = LOW_WORD(p);
        carry = HIGH_WORD(p);
    }
    return carry;
}

static void AtomicInverseModPower2(word *C, word A0, word A1)
{
    assert(A0%2==1);

    dword A=MAKE_DWORD(A0, A1), R=A0%8;

    for (unsigned i=3; i<2*WORD_BITS; i*=2)
        R = R*(2-R*A);

    assert(R*A==1);

    C[0] = LOW_WORD(R);
    C[1] = HIGH_WORD(R);
}



// ********************************************************

class Portable
{
public:
    static word Add(word *C, const word *A, const word *B, unsigned int N);
    static word Subtract(word *C, const word *A, const word*B, unsigned int N);

    static inline void Multiply2(word *C, const word *A, const word *B);
    static inline word Multiply2Add(word *C, const word *A, const word *B);
    static void Multiply4(word *C, const word *A, const word *B);
    static void Multiply8(word *C, const word *A, const word *B);
    static inline unsigned int MultiplyRecursionLimit() {return 8;}

    static inline void Multiply2Bottom(word *C, const word *A, const word *B);
    static void Multiply4Bottom(word *C, const word *A, const word *B);
    static void Multiply8Bottom(word *C, const word *A, const word *B);
    static inline unsigned int MultiplyBottomRecursionLimit() {return 8;}

    static void Square2(word *R, const word *A);
    static void Square4(word *R, const word *A);
    static void Square8(word *R, const word *A) {assert(false);}
    static inline unsigned int SquareRecursionLimit() {return 4;}
};

word Portable::Add(word *C, const word *A, const word *B, unsigned int N)
{
    assert (N%2 == 0);

#ifndef BIG_ENDIAN_ORDER
    if (sizeof(dword) == sizeof(size_t))    // dword is only register size
    {
        dword carry = 0;
        N >>= 1;
        for (unsigned int i = 0; i < N; i++)
        {
            dword a = ((const dword *)A)[i] + carry;
            dword c = a + ((const dword *)B)[i];
            ((dword *)C)[i] = c;
            carry = (a < carry) | (c < a);
        }
        return (word)carry;
    }
    else
#endif
    {
        word carry = 0;
        for (unsigned int i = 0; i < N; i+=2)
        {
            dword u = (dword) carry + A[i] + B[i];
            C[i] = LOW_WORD(u);
            u = (dword) HIGH_WORD(u) + A[i+1] + B[i+1];
            C[i+1] = LOW_WORD(u);
            carry = HIGH_WORD(u);
        }
        return carry;
    }
}

word Portable::Subtract(word *C, const word *A, const word *B, unsigned int N)
{
    assert (N%2 == 0);

#ifndef BIG_ENDIAN_ORDER
    if (sizeof(dword) == sizeof(size_t))    // dword is only register size
    {
        dword borrow = 0;
        N >>= 1;
        for (unsigned int i = 0; i < N; i++)
        {
            dword a = ((const dword *)A)[i];
            dword b = a - borrow;
            dword c = b - ((const dword *)B)[i];
            ((dword *)C)[i] = c;
            borrow = (b > a) | (c > b);
        }
        return (word)borrow;
    }
    else
#endif
    {
        word borrow=0;
        for (unsigned i = 0; i < N; i+=2)
        {
            dword u = (dword) A[i] - B[i] - borrow;
            C[i] = LOW_WORD(u);
            u = (dword) A[i+1] - B[i+1] - (word)(0-HIGH_WORD(u));
            C[i+1] = LOW_WORD(u);
            borrow = 0-HIGH_WORD(u);
        }
        return borrow;
    }
}

void Portable::Multiply2(word *C, const word *A, const word *B)
{
/*
    word s;
    dword d;

    if (A1 >= A0)
        if (B0 >= B1)
        {
            s = 0;
            d = (dword)(A1-A0)*(B0-B1);
        }
        else
        {
            s = (A1-A0);
            d = (dword)s*(word)(B0-B1);
        }
    else
        if (B0 > B1)
        {
            s = (B0-B1);
            d = (word)(A1-A0)*(dword)s;
        }
        else
        {
            s = 0;
            d = (dword)(A0-A1)*(B1-B0);
        }
*/
    // this segment is the branchless equivalent of above
    word D[4] = {A[1]-A[0], A[0]-A[1], B[0]-B[1], B[1]-B[0]};
    unsigned int ai = A[1] < A[0];
    unsigned int bi = B[0] < B[1];
    unsigned int di = ai & bi;
    dword d = (dword)D[di]*D[di+2];
    D[1] = D[3] = 0;
    unsigned int si = ai + !bi;
    word s = D[si];

    dword A0B0 = (dword)A[0]*B[0];
    C[0] = LOW_WORD(A0B0);

    dword A1B1 = (dword)A[1]*B[1];
    dword t = (dword) HIGH_WORD(A0B0) + LOW_WORD(A0B0) + LOW_WORD(d) + 
                LOW_WORD(A1B1);
    C[1] = LOW_WORD(t);

    t = A1B1 + HIGH_WORD(t) + HIGH_WORD(A0B0) + HIGH_WORD(d) + HIGH_WORD(A1B1)
         - s;
    C[2] = LOW_WORD(t);
    C[3] = HIGH_WORD(t);
}

inline void Portable::Multiply2Bottom(word *C, const word *A, const word *B)
{
#ifndef BIG_ENDIAN_ORDER
    if (sizeof(dword) == sizeof(size_t))
    {
        dword a = *(const dword *)A, b = *(const dword *)B;
        ((dword *)C)[0] = a*b;
    }
    else
#endif
    {
        dword t = (dword)A[0]*B[0];
        C[0] = LOW_WORD(t);
        C[1] = HIGH_WORD(t) + A[0]*B[1] + A[1]*B[0];
    }
}

word Portable::Multiply2Add(word *C, const word *A, const word *B)
{
    word D[4] = {A[1]-A[0], A[0]-A[1], B[0]-B[1], B[1]-B[0]};
    unsigned int ai = A[1] < A[0];
    unsigned int bi = B[0] < B[1];
    unsigned int di = ai & bi;
    dword d = (dword)D[di]*D[di+2];
    D[1] = D[3] = 0;
    unsigned int si = ai + !bi;
    word s = D[si];

    dword A0B0 = (dword)A[0]*B[0];
    dword t = A0B0 + C[0];
    C[0] = LOW_WORD(t);

    dword A1B1 = (dword)A[1]*B[1];
    t = (dword) HIGH_WORD(t) + LOW_WORD(A0B0) + LOW_WORD(d) + LOW_WORD(A1B1)
         + C[1];
    C[1] = LOW_WORD(t);

    t = (dword) HIGH_WORD(t) + LOW_WORD(A1B1) + HIGH_WORD(A0B0) + 
         HIGH_WORD(d) + HIGH_WORD(A1B1) - s + C[2];
    C[2] = LOW_WORD(t);

    t = (dword) HIGH_WORD(t) + HIGH_WORD(A1B1) + C[3];
    C[3] = LOW_WORD(t);
    return HIGH_WORD(t);
}

#define MulAcc(x, y)                                \
    p = (dword)A[x] * B[y] + c;                     \
    c = LOW_WORD(p);                                \
    p = (dword)d + HIGH_WORD(p);                    \
    d = LOW_WORD(p);                                \
    e += HIGH_WORD(p);

#define SaveMulAcc(s, x, y)                         \
    R[s] = c;                                       \
    p = (dword)A[x] * B[y] + d;                     \
    c = LOW_WORD(p);                                \
    p = (dword)e + HIGH_WORD(p);                    \
    d = LOW_WORD(p);                                \
    e = HIGH_WORD(p);

#define SquAcc(x, y)                                \
    q = (dword)A[x] * A[y];                         \
    p = q + c;                                      \
    c = LOW_WORD(p);                                \
    p = (dword)d + HIGH_WORD(p);                    \
    d = LOW_WORD(p);                                \
    e += HIGH_WORD(p);                              \
    p = q + c;                                      \
    c = LOW_WORD(p);                                \
    p = (dword)d + HIGH_WORD(p);                    \
    d = LOW_WORD(p);                                \
    e += HIGH_WORD(p);

#define SaveSquAcc(s, x, y)                         \
    R[s] = c;                                       \
    q = (dword)A[x] * A[y];                         \
    p = q + d;                                      \
    c = LOW_WORD(p);                                \
    p = (dword)e + HIGH_WORD(p);                    \
    d = LOW_WORD(p);                                \
    e = HIGH_WORD(p);                               \
    p = q + c;                                      \
    c = LOW_WORD(p);                                \
    p = (dword)d + HIGH_WORD(p);                    \
    d = LOW_WORD(p);                                \
    e += HIGH_WORD(p);

void Portable::Multiply4(word *R, const word *A, const word *B)
{
    dword p;
    word c, d, e;

    p = (dword)A[0] * B[0];
    R[0] = LOW_WORD(p);
    c = HIGH_WORD(p);
    d = e = 0;

    MulAcc(0, 1);
    MulAcc(1, 0);

    SaveMulAcc(1, 2, 0);
    MulAcc(1, 1);
    MulAcc(0, 2);

    SaveMulAcc(2, 0, 3);
    MulAcc(1, 2);
    MulAcc(2, 1);
    MulAcc(3, 0);

    SaveMulAcc(3, 3, 1);
    MulAcc(2, 2);
    MulAcc(1, 3);

    SaveMulAcc(4, 2, 3);
    MulAcc(3, 2);

    R[5] = c;
    p = (dword)A[3] * B[3] + d;
    R[6] = LOW_WORD(p);
    R[7] = e + HIGH_WORD(p);
}

void Portable::Square2(word *R, const word *A)
{
    dword p, q;
    word c, d, e;

    p = (dword)A[0] * A[0];
    R[0] = LOW_WORD(p);
    c = HIGH_WORD(p);
    d = e = 0;

    SquAcc(0, 1);

    R[1] = c;
    p = (dword)A[1] * A[1] + d;
    R[2] = LOW_WORD(p);
    R[3] = e + HIGH_WORD(p);
}

void Portable::Square4(word *R, const word *A)
{
    const word *B = A;
    dword p, q;
    word c, d, e;

    p = (dword)A[0] * A[0];
    R[0] = LOW_WORD(p);
    c = HIGH_WORD(p);
    d = e = 0;

    SquAcc(0, 1);

    SaveSquAcc(1, 2, 0);
    MulAcc(1, 1);

    SaveSquAcc(2, 0, 3);
    SquAcc(1, 2);

    SaveSquAcc(3, 3, 1);
    MulAcc(2, 2);

    SaveSquAcc(4, 2, 3);

    R[5] = c;
    p = (dword)A[3] * A[3] + d;
    R[6] = LOW_WORD(p);
    R[7] = e + HIGH_WORD(p);
}

void Portable::Multiply8(word *R, const word *A, const word *B)
{
    dword p;
    word c, d, e;

    p = (dword)A[0] * B[0];
    R[0] = LOW_WORD(p);
    c = HIGH_WORD(p);
    d = e = 0;

    MulAcc(0, 1);
    MulAcc(1, 0);

    SaveMulAcc(1, 2, 0);
    MulAcc(1, 1);
    MulAcc(0, 2);

    SaveMulAcc(2, 0, 3);
    MulAcc(1, 2);
    MulAcc(2, 1);
    MulAcc(3, 0);

    SaveMulAcc(3, 0, 4);
    MulAcc(1, 3);
    MulAcc(2, 2);
    MulAcc(3, 1);
    MulAcc(4, 0);

    SaveMulAcc(4, 0, 5);
    MulAcc(1, 4);
    MulAcc(2, 3);
    MulAcc(3, 2);
    MulAcc(4, 1);
    MulAcc(5, 0);

    SaveMulAcc(5, 0, 6);
    MulAcc(1, 5);
    MulAcc(2, 4);
    MulAcc(3, 3);
    MulAcc(4, 2);
    MulAcc(5, 1);
    MulAcc(6, 0);

    SaveMulAcc(6, 0, 7);
    MulAcc(1, 6);
    MulAcc(2, 5);
    MulAcc(3, 4);
    MulAcc(4, 3);
    MulAcc(5, 2);
    MulAcc(6, 1);
    MulAcc(7, 0);

    SaveMulAcc(7, 1, 7);
    MulAcc(2, 6);
    MulAcc(3, 5);
    MulAcc(4, 4);
    MulAcc(5, 3);
    MulAcc(6, 2);
    MulAcc(7, 1);

    SaveMulAcc(8, 2, 7);
    MulAcc(3, 6);
    MulAcc(4, 5);
    MulAcc(5, 4);
    MulAcc(6, 3);
    MulAcc(7, 2);

    SaveMulAcc(9, 3, 7);
    MulAcc(4, 6);
    MulAcc(5, 5);
    MulAcc(6, 4);
    MulAcc(7, 3);

    SaveMulAcc(10, 4, 7);
    MulAcc(5, 6);
    MulAcc(6, 5);
    MulAcc(7, 4);

    SaveMulAcc(11, 5, 7);
    MulAcc(6, 6);
    MulAcc(7, 5);

    SaveMulAcc(12, 6, 7);
    MulAcc(7, 6);

    R[13] = c;
    p = (dword)A[7] * B[7] + d;
    R[14] = LOW_WORD(p);
    R[15] = e + HIGH_WORD(p);
}

void Portable::Multiply4Bottom(word *R, const word *A, const word *B)
{
    dword p;
    word c, d, e;

    p = (dword)A[0] * B[0];
    R[0] = LOW_WORD(p);
    c = HIGH_WORD(p);
    d = e = 0;

    MulAcc(0, 1);
    MulAcc(1, 0);

    SaveMulAcc(1, 2, 0);
    MulAcc(1, 1);
    MulAcc(0, 2);

    R[2] = c;
    R[3] = d + A[0] * B[3] + A[1] * B[2] + A[2] * B[1] + A[3] * B[0];
}

void Portable::Multiply8Bottom(word *R, const word *A, const word *B)
{
    dword p;
    word c, d, e;

    p = (dword)A[0] * B[0];
    R[0] = LOW_WORD(p);
    c = HIGH_WORD(p);
    d = e = 0;

    MulAcc(0, 1);
    MulAcc(1, 0);

    SaveMulAcc(1, 2, 0);
    MulAcc(1, 1);
    MulAcc(0, 2);

    SaveMulAcc(2, 0, 3);
    MulAcc(1, 2);
    MulAcc(2, 1);
    MulAcc(3, 0);

    SaveMulAcc(3, 0, 4);
    MulAcc(1, 3);
    MulAcc(2, 2);
    MulAcc(3, 1);
    MulAcc(4, 0);

    SaveMulAcc(4, 0, 5);
    MulAcc(1, 4);
    MulAcc(2, 3);
    MulAcc(3, 2);
    MulAcc(4, 1);
    MulAcc(5, 0);

    SaveMulAcc(5, 0, 6);
    MulAcc(1, 5);
    MulAcc(2, 4);
    MulAcc(3, 3);
    MulAcc(4, 2);
    MulAcc(5, 1);
    MulAcc(6, 0);

    R[6] = c;
    R[7] = d + A[0] * B[7] + A[1] * B[6] + A[2] * B[5] + A[3] * B[4] +
                A[4] * B[3] + A[5] * B[2] + A[6] * B[1] + A[7] * B[0];
}


#undef MulAcc
#undef SaveMulAcc
#undef SquAcc
#undef SaveSquAcc

// CodeWarrior defines _MSC_VER
#if defined(_MSC_VER) && !defined(__MWERKS__) && defined(_M_IX86) && \
(_M_IX86<=700)

class PentiumOptimized : public Portable
{
public:
    static word __fastcall Add(word *C, const word *A, const word *B,
                               unsigned int N);
    static word __fastcall Subtract(word *C, const word *A, const word *B,
                                    unsigned int N);
    static inline void Square4(word *R, const word *A)
    {
        // VC60 workaround: MSVC 6.0 has an optimization bug that makes
        // (dword)A*B where either A or B has been cast to a dword before
        // very expensive. Revisit this function when this
        // bug is fixed.
        Multiply4(R, A, A);
    }
};

typedef PentiumOptimized LowLevel;

__declspec(naked) word __fastcall PentiumOptimized::Add(word *C, const word *A,
                                                 const word *B, unsigned int N)
{
    __asm
    {
        push ebp
        push ebx
        push esi
        push edi

        mov esi, [esp+24]	; N
        mov ebx, [esp+20]	; B

        // now: ebx = B, ecx = C, edx = A, esi = N

        sub ecx, edx    // hold the distance between C & A 
        xor eax, eax    // clear eax

        sub eax, esi    // eax is a negative index from end of B
        lea ebx, [ebx+4*esi]    // ebx is end of B

        sar eax, 1      // unit of eax is now dwords; and clears the carry flag
        jz	loopend     // if no dwords then nothing to do

loopstart:
        mov    esi,[edx]            // load lower word of A
        mov    ebp,[edx+4]          // load higher word of A

        mov    edi,[ebx+8*eax]      // load lower word of B
        lea    edx,[edx+8]          // advance A and C

        adc    esi,edi              // add lower words
        mov    edi,[ebx+8*eax+4]    // load higher word of B

        adc    ebp,edi              // add higher words
        inc    eax                  // advance B

        mov    [edx+ecx-8],esi      // store lower word result
        mov    [edx+ecx-4],ebp      // store higher word result

        jnz    loopstart            // loop until eax overflows, becomes zero

loopend:
        adc eax, 0      // store carry into eax (return result register)
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret 8
    }
}

__declspec(naked) word __fastcall PentiumOptimized::Subtract(word *C,
                                  const word *A, const word *B, unsigned int N)
{
    __asm
    {
        push ebp
        push ebx
        push esi
        push edi

        mov esi, [esp+24]   ; N
        mov ebx, [esp+20]   ; B

        sub ecx, edx
        xor eax, eax

        sub eax, esi
        lea ebx, [ebx+4*esi]

        sar eax, 1
        jz  loopend

loopstart:
        mov    esi,[edx]
        mov    ebp,[edx+4]

        mov    edi,[ebx+8*eax]
        lea    edx,[edx+8]

        sbb    esi,edi
        mov    edi,[ebx+8*eax+4]

        sbb    ebp,edi
        inc    eax

        mov    [edx+ecx-8],esi
        mov    [edx+ecx-4],ebp

        jnz    loopstart

loopend:
        adc eax, 0
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret 8
    }
}

#ifdef SSE2_INTRINSICS_AVAILABLE

static bool GetSSE2Capability()
{
    word32 b;

    __asm
    {
        mov     eax, 1
        cpuid
        mov     b, edx
    }

    return (b & (1 << 26)) != 0;
}

bool g_sse2DetectionDone = false, g_sse2Detected, g_sse2Enabled = true;

static inline bool HasSSE2()
{
    if (g_sse2Enabled && !g_sse2DetectionDone)
    {
        g_sse2Detected = GetSSE2Capability();
        g_sse2DetectionDone = true;
    }
    return g_sse2Enabled && g_sse2Detected;
}

class P4Optimized : public PentiumOptimized
{
public:
    static word __fastcall Add(word *C, const word *A, const word *B,
                               unsigned int N);
    static word __fastcall Subtract(word *C, const word *A, const word *B,
                                    unsigned int N);
    static void Multiply4(word *C, const word *A, const word *B);
    static void Multiply8(word *C, const word *A, const word *B);
    static inline void Square4(word *R, const word *A)
    {
        Multiply4(R, A, A);
    }
    static void Multiply8Bottom(word *C, const word *A, const word *B);
};

static void __fastcall P4_Mul(__m128i *C, const __m128i *A, const __m128i *B)
{
    __m128i a3210 = _mm_load_si128(A);
    __m128i b3210 = _mm_load_si128(B);

    __m128i sum;

    __m128i z = _mm_setzero_si128();
    __m128i a2b2_a0b0 = _mm_mul_epu32(a3210, b3210);
    C[0] = a2b2_a0b0;

    __m128i a3120 = _mm_shuffle_epi32(a3210, _MM_SHUFFLE(3, 1, 2, 0));
    __m128i b3021 = _mm_shuffle_epi32(b3210, _MM_SHUFFLE(3, 0, 2, 1));
    __m128i a1b0_a0b1 = _mm_mul_epu32(a3120, b3021);
    __m128i a1b0 = _mm_unpackhi_epi32(a1b0_a0b1, z);
    __m128i a0b1 = _mm_unpacklo_epi32(a1b0_a0b1, z);
    C[1] = _mm_add_epi64(a1b0, a0b1);

    __m128i a31 = _mm_srli_epi64(a3210, 32);
    __m128i b31 = _mm_srli_epi64(b3210, 32);
    __m128i a3b3_a1b1 = _mm_mul_epu32(a31, b31);
    C[6] = a3b3_a1b1;

    __m128i a1b1 = _mm_unpacklo_epi32(a3b3_a1b1, z);
    __m128i b3012 = _mm_shuffle_epi32(b3210, _MM_SHUFFLE(3, 0, 1, 2));
    __m128i a2b0_a0b2 = _mm_mul_epu32(a3210, b3012);
    __m128i a0b2 = _mm_unpacklo_epi32(a2b0_a0b2, z);
    __m128i a2b0 = _mm_unpackhi_epi32(a2b0_a0b2, z);
    sum = _mm_add_epi64(a1b1, a0b2);
    C[2] = _mm_add_epi64(sum, a2b0);

    __m128i a2301 = _mm_shuffle_epi32(a3210, _MM_SHUFFLE(2, 3, 0, 1));
    __m128i b2103 = _mm_shuffle_epi32(b3210, _MM_SHUFFLE(2, 1, 0, 3));
    __m128i a3b0_a1b2 = _mm_mul_epu32(a2301, b3012);
    __m128i a2b1_a0b3 = _mm_mul_epu32(a3210, b2103);
    __m128i a3b0 = _mm_unpackhi_epi32(a3b0_a1b2, z);
    __m128i a1b2 = _mm_unpacklo_epi32(a3b0_a1b2, z);
    __m128i a2b1 = _mm_unpackhi_epi32(a2b1_a0b3, z);
    __m128i a0b3 = _mm_unpacklo_epi32(a2b1_a0b3, z);
    __m128i sum1 = _mm_add_epi64(a3b0, a1b2);
    sum = _mm_add_epi64(a2b1, a0b3);
    C[3] = _mm_add_epi64(sum, sum1);

    __m128i	a3b1_a1b3 = _mm_mul_epu32(a2301, b2103);
    __m128i a2b2 = _mm_unpackhi_epi32(a2b2_a0b0, z);
    __m128i a3b1 = _mm_unpackhi_epi32(a3b1_a1b3, z);
    __m128i a1b3 = _mm_unpacklo_epi32(a3b1_a1b3, z);
    sum = _mm_add_epi64(a2b2, a3b1);
    C[4] = _mm_add_epi64(sum, a1b3);

    __m128i a1302 = _mm_shuffle_epi32(a3210, _MM_SHUFFLE(1, 3, 0, 2));
    __m128i b1203 = _mm_shuffle_epi32(b3210, _MM_SHUFFLE(1, 2, 0, 3));
    __m128i a3b2_a2b3 = _mm_mul_epu32(a1302, b1203);
    __m128i a3b2 = _mm_unpackhi_epi32(a3b2_a2b3, z);
    __m128i a2b3 = _mm_unpacklo_epi32(a3b2_a2b3, z);
    C[5] = _mm_add_epi64(a3b2, a2b3);
}

void P4Optimized::Multiply4(word *C, const word *A, const word *B)
{
    __m128i temp[7];
    const word *w = (word *)temp;
    const __m64 *mw = (__m64 *)w;

    P4_Mul(temp, (__m128i *)A, (__m128i *)B);

    C[0] = w[0];

    __m64 s1, s2;

    __m64 w1 = _m_from_int(w[1]);
    __m64 w4 = mw[2];
    __m64 w6 = mw[3];
    __m64 w8 = mw[4];
    __m64 w10 = mw[5];
    __m64 w12 = mw[6];
    __m64 w14 = mw[7];
    __m64 w16 = mw[8];
    __m64 w18 = mw[9];
    __m64 w20 = mw[10];
    __m64 w22 = mw[11];
    __m64 w26 = _m_from_int(w[26]);

    s1 = _mm_add_si64(w1, w4);
    C[1] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w6, w8);
    s1 = _mm_add_si64(s1, s2);
    C[2] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w10, w12);
    s1 = _mm_add_si64(s1, s2);
    C[3] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w14, w16);
    s1 = _mm_add_si64(s1, s2);
    C[4] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w18, w20);
    s1 = _mm_add_si64(s1, s2);
    C[5] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w22, w26);
    s1 = _mm_add_si64(s1, s2);
    C[6] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    C[7] = _m_to_int(s1) + w[27];
    _mm_empty();
}

void P4Optimized::Multiply8(word *C, const word *A, const word *B)
{
    __m128i temp[28];
    const word *w = (word *)temp;
    const __m64 *mw = (__m64 *)w;
    const word *x = (word *)temp+7*4;
    const __m64 *mx = (__m64 *)x;
    const word *y = (word *)temp+7*4*2;
    const __m64 *my = (__m64 *)y;
    const word *z = (word *)temp+7*4*3;
    const __m64 *mz = (__m64 *)z;

    P4_Mul(temp, (__m128i *)A, (__m128i *)B);

    P4_Mul(temp+7, (__m128i *)A+1, (__m128i *)B);

    P4_Mul(temp+14, (__m128i *)A, (__m128i *)B+1);

    P4_Mul(temp+21, (__m128i *)A+1, (__m128i *)B+1);

    C[0] = w[0];

    __m64 s1, s2, s3, s4;

    __m64 w1 = _m_from_int(w[1]);
    __m64 w4 = mw[2];
    __m64 w6 = mw[3];
    __m64 w8 = mw[4];
    __m64 w10 = mw[5];
    __m64 w12 = mw[6];
    __m64 w14 = mw[7];
    __m64 w16 = mw[8];
    __m64 w18 = mw[9];
    __m64 w20 = mw[10];
    __m64 w22 = mw[11];
    __m64 w26 = _m_from_int(w[26]);
    __m64 w27 = _m_from_int(w[27]);

    __m64 x0 = _m_from_int(x[0]);
    __m64 x1 = _m_from_int(x[1]);
    __m64 x4 = mx[2];
    __m64 x6 = mx[3];
    __m64 x8 = mx[4];
    __m64 x10 = mx[5];
    __m64 x12 = mx[6];
    __m64 x14 = mx[7];
    __m64 x16 = mx[8];
    __m64 x18 = mx[9];
    __m64 x20 = mx[10];
    __m64 x22 = mx[11];
    __m64 x26 = _m_from_int(x[26]);
    __m64 x27 = _m_from_int(x[27]);

    __m64 y0 = _m_from_int(y[0]);
    __m64 y1 = _m_from_int(y[1]);
    __m64 y4 = my[2];
    __m64 y6 = my[3];
    __m64 y8 = my[4];
    __m64 y10 = my[5];
    __m64 y12 = my[6];
    __m64 y14 = my[7];
    __m64 y16 = my[8];
    __m64 y18 = my[9];
    __m64 y20 = my[10];
    __m64 y22 = my[11];
    __m64 y26 = _m_from_int(y[26]);
    __m64 y27 = _m_from_int(y[27]);

    __m64 z0 = _m_from_int(z[0]);
    __m64 z1 = _m_from_int(z[1]);
    __m64 z4 = mz[2];
    __m64 z6 = mz[3];
    __m64 z8 = mz[4];
    __m64 z10 = mz[5];
    __m64 z12 = mz[6];
    __m64 z14 = mz[7];
    __m64 z16 = mz[8];
    __m64 z18 = mz[9];
    __m64 z20 = mz[10];
    __m64 z22 = mz[11];
    __m64 z26 = _m_from_int(z[26]);

    s1 = _mm_add_si64(w1, w4);
    C[1] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w6, w8);
    s1 = _mm_add_si64(s1, s2);
    C[2] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w10, w12);
    s1 = _mm_add_si64(s1, s2);
    C[3] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x0, y0);
    s2 = _mm_add_si64(w14, w16);
    s1 = _mm_add_si64(s1, s3);
    s1 = _mm_add_si64(s1, s2);
    C[4] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x1, y1);
    s4 = _mm_add_si64(x4, y4);
    s1 = _mm_add_si64(s1, w18);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, w20);
    s1 = _mm_add_si64(s1, s3);
    C[5] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x6, y6);
    s4 = _mm_add_si64(x8, y8);
    s1 = _mm_add_si64(s1, w22);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, w26);
    s1 = _mm_add_si64(s1, s3);
    C[6] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x10, y10);
    s4 = _mm_add_si64(x12, y12);
    s1 = _mm_add_si64(s1, w27);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, s3);
    C[7] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x14, y14);
    s4 = _mm_add_si64(x16, y16);
    s1 = _mm_add_si64(s1, z0);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, s3);
    C[8] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x18, y18);
    s4 = _mm_add_si64(x20, y20);
    s1 = _mm_add_si64(s1, z1);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, z4);
    s1 = _mm_add_si64(s1, s3);
    C[9] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x22, y22);
    s4 = _mm_add_si64(x26, y26);
    s1 = _mm_add_si64(s1, z6);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, z8);
    s1 = _mm_add_si64(s1, s3);
    C[10] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x27, y27);
    s1 = _mm_add_si64(s1, z10);
    s1 = _mm_add_si64(s1, z12);
    s1 = _mm_add_si64(s1, s3);
    C[11] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(z14, z16);
    s1 = _mm_add_si64(s1, s3);
    C[12] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(z18, z20);
    s1 = _mm_add_si64(s1, s3);
    C[13] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(z22, z26);
    s1 = _mm_add_si64(s1, s3);
    C[14] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    C[15] = z[27] + _m_to_int(s1);
    _mm_empty();
}

void P4Optimized::Multiply8Bottom(word *C, const word *A, const word *B)
{
    __m128i temp[21];
    const word *w = (word *)temp;
    const __m64 *mw = (__m64 *)w;
    const word *x = (word *)temp+7*4;
    const __m64 *mx = (__m64 *)x;
    const word *y = (word *)temp+7*4*2;
    const __m64 *my = (__m64 *)y;

    P4_Mul(temp, (__m128i *)A, (__m128i *)B);

    P4_Mul(temp+7, (__m128i *)A+1, (__m128i *)B);

    P4_Mul(temp+14, (__m128i *)A, (__m128i *)B+1);

    C[0] = w[0];

    __m64 s1, s2, s3, s4;

    __m64 w1 = _m_from_int(w[1]);
    __m64 w4 = mw[2];
    __m64 w6 = mw[3];
    __m64 w8 = mw[4];
    __m64 w10 = mw[5];
    __m64 w12 = mw[6];
    __m64 w14 = mw[7];
    __m64 w16 = mw[8];
    __m64 w18 = mw[9];
    __m64 w20 = mw[10];
    __m64 w22 = mw[11];
    __m64 w26 = _m_from_int(w[26]);

    __m64 x0 = _m_from_int(x[0]);
    __m64 x1 = _m_from_int(x[1]);
    __m64 x4 = mx[2];
    __m64 x6 = mx[3];
    __m64 x8 = mx[4];

    __m64 y0 = _m_from_int(y[0]);
    __m64 y1 = _m_from_int(y[1]);
    __m64 y4 = my[2];
    __m64 y6 = my[3];
    __m64 y8 = my[4];

    s1 = _mm_add_si64(w1, w4);
    C[1] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w6, w8);
    s1 = _mm_add_si64(s1, s2);
    C[2] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s2 = _mm_add_si64(w10, w12);
    s1 = _mm_add_si64(s1, s2);
    C[3] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x0, y0);
    s2 = _mm_add_si64(w14, w16);
    s1 = _mm_add_si64(s1, s3);
    s1 = _mm_add_si64(s1, s2);
    C[4] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x1, y1);
    s4 = _mm_add_si64(x4, y4);
    s1 = _mm_add_si64(s1, w18);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, w20);
    s1 = _mm_add_si64(s1, s3);
    C[5] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    s3 = _mm_add_si64(x6, y6);
    s4 = _mm_add_si64(x8, y8);
    s1 = _mm_add_si64(s1, w22);
    s3 = _mm_add_si64(s3, s4);
    s1 = _mm_add_si64(s1, w26);
    s1 = _mm_add_si64(s1, s3);
    C[6] = _m_to_int(s1);
    s1 = _m_psrlqi(s1, 32);

    C[7] = _m_to_int(s1) + w[27] + x[10] + y[10] + x[12] + y[12];
    _mm_empty();
}

__declspec(naked) word __fastcall P4Optimized::Add(word *C, const word *A,
                                                 const word *B, unsigned int N)
{
    __asm
    {
        sub     esp, 16
        xor     eax, eax
        mov     [esp], edi
        mov     [esp+4], esi
        mov     [esp+8], ebx
        mov     [esp+12], ebp

        mov     ebx, [esp+20]	// B
        mov     esi, [esp+24]	// N

        // now: ebx = B, ecx = C, edx = A, esi = N

        neg     esi
        jz      loopend     // if no dwords then nothing to do

        mov     edi, [edx]
        mov     ebp, [ebx]

loopstart:
        add     edi, eax
        jc      carry1

        xor     eax, eax

carry1continue:
        add     edi, ebp
        mov     ebp, 1
        mov     [ecx], edi
        mov     edi, [edx+4]
        cmovc   eax, ebp
        mov     ebp, [ebx+4]
        lea     ebx, [ebx+8]
        add     edi, eax
        jc      carry2

        xor     eax, eax

carry2continue:
        add     edi, ebp
        mov     ebp, 1
        cmovc   eax, ebp
        mov     [ecx+4], edi
        add     ecx, 8
        mov     edi, [edx+8]
        add     edx, 8
        add     esi, 2
        mov     ebp, [ebx]
        jnz     loopstart

loopend:
        mov     edi, [esp]
        mov     esi, [esp+4]
        mov     ebx, [esp+8]
        mov     ebp, [esp+12]
        add     esp, 16
        ret     8

carry1:
        mov     eax, 1
        jmp     carry1continue

carry2:
        mov     eax, 1
        jmp     carry2continue
    }
}

__declspec(naked) word __fastcall P4Optimized::Subtract(word *C, const word *A,
                                                const word *B, unsigned int N)
{
    __asm
    {
        sub     esp, 16
        xor     eax, eax
        mov     [esp], edi
        mov     [esp+4], esi
        mov     [esp+8], ebx
        mov     [esp+12], ebp

        mov     ebx, [esp+20]	// B
        mov     esi, [esp+24]	// N

        // now: ebx = B, ecx = C, edx = A, esi = N

        neg     esi
        jz      loopend     // if no dwords then nothing to do

        mov     edi, [edx]
        mov     ebp, [ebx]

loopstart:
        sub     edi, eax
        jc      carry1

        xor     eax, eax

carry1continue:
        sub     edi, ebp
        mov     ebp, 1
        mov     [ecx], edi
        mov     edi, [edx+4]
        cmovc   eax, ebp
        mov     ebp, [ebx+4]
        lea     ebx, [ebx+8]
        sub     edi, eax
        jc      carry2

        xor     eax, eax

carry2continue:
        sub     edi, ebp
        mov     ebp, 1
        cmovc   eax, ebp
        mov     [ecx+4], edi
        add     ecx, 8
        mov     edi, [edx+8]
        add     edx, 8
        add     esi, 2
        mov     ebp, [ebx]
        jnz     loopstart

loopend:
        mov     edi, [esp]
        mov     esi, [esp+4]
        mov     ebx, [esp+8]
        mov     ebp, [esp+12]
        add     esp, 16
        ret     8

carry1:
        mov     eax, 1
        jmp     carry1continue

carry2:
        mov     eax, 1
        jmp     carry2continue
    }
}

#endif	// #ifdef SSE2_INTRINSICS_AVAILABLE

#elif defined(__GNUC__) && defined(__i386__)

class PentiumOptimized : public Portable
{
public:
#ifndef __pic__     // -fpic uses up a register, leaving too few for asm code
    static word Add(word *C, const word *A, const word *B, unsigned int N);
    static word Subtract(word *C, const word *A, const word*B, unsigned int N);
#endif
    static void Square4(word *R, const word *A);
    static void Multiply4(word *C, const word *A, const word *B);
    static void Multiply8(word *C, const word *A, const word *B);
};

typedef PentiumOptimized LowLevel;

// Add and Subtract assembly code originally contributed by Alister Lee

#ifndef __pic__
__attribute__((regparm(3))) word PentiumOptimized::Add(word *C, const word *A,
                                                 const word *B, unsigned int N)
{
    assert (N%2 == 0);

    register word carry, temp;

    __asm__ __volatile__(
            "push %%ebp;"
            "sub %3, %2;"
            "xor %0, %0;"
            "sub %4, %0;"
            "lea (%1,%4,4), %1;"
            "sar $1, %0;"
            "jz 1f;"

        "0:;"
            "mov 0(%3), %4;"
            "mov 4(%3), %%ebp;"
            "mov (%1,%0,8), %5;"
            "lea 8(%3), %3;"
            "adc %5, %4;"
            "mov 4(%1,%0,8), %5;"
            "adc %5, %%ebp;"
            "inc %0;"
            "mov %4, -8(%3, %2);"
            "mov %%ebp, -4(%3, %2);"
            "jnz 0b;"

        "1:;"
            "adc $0, %0;"
            "pop %%ebp;"

        : "=aSD" (carry), "+r" (B), "+r" (C), "+r" (A), "+r" (N), "=r" (temp)
        : : "cc", "memory");

    return carry;
}

__attribute__((regparm(3))) word PentiumOptimized::Subtract(word *C,
                                  const word *A, const word *B, unsigned int N)
{
    assert (N%2 == 0);

    register word carry, temp;

    __asm__ __volatile__(
            "push %%ebp;"
            "sub %3, %2;"
            "xor %0, %0;"
            "sub %4, %0;"
            "lea (%1,%4,4), %1;"
            "sar $1, %0;"
            "jz 1f;"

        "0:;"
            "mov 0(%3), %4;"
            "mov 4(%3), %%ebp;"
            "mov (%1,%0,8), %5;"
            "lea 8(%3), %3;"
            "sbb %5, %4;"
            "mov 4(%1,%0,8), %5;"
            "sbb %5, %%ebp;"
            "inc %0;"
            "mov %4, -8(%3, %2);"
            "mov %%ebp, -4(%3, %2);"
            "jnz 0b;"

        "1:;"
            "adc $0, %0;"
            "pop %%ebp;"

        : "=aSD" (carry), "+r" (B), "+r" (C), "+r" (A), "+r" (N), "=r" (temp)
        : : "cc", "memory");

    return carry;
}
#endif	// __pic__

// Comba square and multiply assembly code contributed by Leonard Janke

#define SqrStartup \
  "push %%ebp\n\t" \
  "push %%esi\n\t" \
  "push %%ebx\n\t" \
  "xor %%ebp, %%ebp\n\t" \
  "xor %%ebx, %%ebx\n\t" \
  "xor %%ecx, %%ecx\n\t" 

#define SqrShiftCarry \
  "mov %%ebx, %%ebp\n\t" \
  "mov %%ecx, %%ebx\n\t" \
  "xor %%ecx, %%ecx\n\t"

#define SqrAccumulate(i,j) \
  "mov 4*"#j"(%%esi), %%eax\n\t" \
  "mull 4*"#i"(%%esi)\n\t" \
  "add %%eax, %%ebp\n\t" \
  "adc %%edx, %%ebx\n\t" \
  "adc %%ch, %%cl\n\t" \
  "add %%eax, %%ebp\n\t" \
  "adc %%edx, %%ebx\n\t" \
  "adc %%ch, %%cl\n\t"

#define SqrAccumulateCentre(i) \
  "mov 4*"#i"(%%esi), %%eax\n\t" \
  "mull 4*"#i"(%%esi)\n\t" \
  "add %%eax, %%ebp\n\t" \
  "adc %%edx, %%ebx\n\t" \
  "adc %%ch, %%cl\n\t" 

#define SqrStoreDigit(X)  \
  "mov %%ebp, 4*"#X"(%%edi)\n\t" \

#define SqrLastDiagonal(digits) \
  "mov 4*("#digits"-1)(%%esi), %%eax\n\t" \
  "mull 4*("#digits"-1)(%%esi)\n\t" \
  "add %%eax, %%ebp\n\t" \
  "adc %%edx, %%ebx\n\t" \
  "mov %%ebp, 4*(2*"#digits"-2)(%%edi)\n\t" \
  "mov %%ebx, 4*(2*"#digits"-1)(%%edi)\n\t" 

#define SqrCleanup \
  "pop %%ebx\n\t" \
  "pop %%esi\n\t" \
  "pop %%ebp\n\t" 

void PentiumOptimized::Square4(word* Y, const word* X)
{
    __asm__ __volatile__(
        SqrStartup

        SqrAccumulateCentre(0)
        SqrStoreDigit(0)
        SqrShiftCarry

        SqrAccumulate(1,0)
        SqrStoreDigit(1)
        SqrShiftCarry

        SqrAccumulate(2,0)
        SqrAccumulateCentre(1)
        SqrStoreDigit(2)
        SqrShiftCarry

        SqrAccumulate(3,0)
        SqrAccumulate(2,1)
        SqrStoreDigit(3)
        SqrShiftCarry

        SqrAccumulate(3,1)
        SqrAccumulateCentre(2)
        SqrStoreDigit(4)
        SqrShiftCarry

        SqrAccumulate(3,2)
        SqrStoreDigit(5)
        SqrShiftCarry

        SqrLastDiagonal(4)

        SqrCleanup

        :
        : "D" (Y), "S" (X)
        : "eax",  "ecx", "edx", "ebp",   "memory"
    );
}

#define MulStartup \
  "push %%ebp\n\t" \
  "push %%esi\n\t" \
  "push %%ebx\n\t" \
  "push %%edi\n\t" \
  "mov %%eax, %%ebx \n\t" \
  "xor %%ebp, %%ebp\n\t" \
  "xor %%edi, %%edi\n\t" \
  "xor %%ecx, %%ecx\n\t" 

#define MulShiftCarry \
  "mov %%edx, %%ebp\n\t" \
  "mov %%ecx, %%edi\n\t" \
  "xor %%ecx, %%ecx\n\t"

#define MulAccumulate(i,j) \
  "mov 4*"#j"(%%ebx), %%eax\n\t" \
  "mull 4*"#i"(%%esi)\n\t" \
  "add %%eax, %%ebp\n\t" \
  "adc %%edx, %%edi\n\t" \
  "adc %%ch, %%cl\n\t"

#define MulStoreDigit(X)  \
  "mov %%edi, %%edx \n\t" \
  "mov (%%esp), %%edi \n\t" \
  "mov %%ebp, 4*"#X"(%%edi)\n\t" \
  "mov %%edi, (%%esp)\n\t" 

#define MulLastDiagonal(digits) \
  "mov 4*("#digits"-1)(%%ebx), %%eax\n\t" \
  "mull 4*("#digits"-1)(%%esi)\n\t" \
  "add %%eax, %%ebp\n\t" \
  "adc %%edi, %%edx\n\t" \
  "mov (%%esp), %%edi\n\t" \
  "mov %%ebp, 4*(2*"#digits"-2)(%%edi)\n\t" \
  "mov %%edx, 4*(2*"#digits"-1)(%%edi)\n\t" 

#define MulCleanup \
  "pop %%edi\n\t" \
  "pop %%ebx\n\t" \
  "pop %%esi\n\t" \
  "pop %%ebp\n\t" 

void PentiumOptimized::Multiply4(word* Z, const word* X, const word* Y)
{
    __asm__ __volatile__(
        MulStartup
        MulAccumulate(0,0)
        MulStoreDigit(0)
        MulShiftCarry

        MulAccumulate(1,0)
        MulAccumulate(0,1)
        MulStoreDigit(1)
        MulShiftCarry

        MulAccumulate(2,0)
        MulAccumulate(1,1)
        MulAccumulate(0,2)
        MulStoreDigit(2)
        MulShiftCarry

        MulAccumulate(3,0)
        MulAccumulate(2,1)
        MulAccumulate(1,2)
        MulAccumulate(0,3)
        MulStoreDigit(3)
        MulShiftCarry

        MulAccumulate(3,1)
        MulAccumulate(2,2)
        MulAccumulate(1,3)
        MulStoreDigit(4)
        MulShiftCarry

        MulAccumulate(3,2)
        MulAccumulate(2,3)
        MulStoreDigit(5)
        MulShiftCarry

        MulLastDiagonal(4)

        MulCleanup

        : 
        : "D" (Z), "S" (X), "a" (Y)
        : "%ecx", "%edx",  "memory"
    );
}

void PentiumOptimized::Multiply8(word* Z, const word* X, const word* Y)
{
    __asm__ __volatile__(
        MulStartup
        MulAccumulate(0,0)
        MulStoreDigit(0)
        MulShiftCarry

        MulAccumulate(1,0)
        MulAccumulate(0,1)
        MulStoreDigit(1)
        MulShiftCarry

        MulAccumulate(2,0)
        MulAccumulate(1,1)
        MulAccumulate(0,2)
        MulStoreDigit(2)
        MulShiftCarry

        MulAccumulate(3,0)
        MulAccumulate(2,1)
        MulAccumulate(1,2)
        MulAccumulate(0,3)
        MulStoreDigit(3)
        MulShiftCarry

        MulAccumulate(4,0)
        MulAccumulate(3,1)
        MulAccumulate(2,2)
        MulAccumulate(1,3)
        MulAccumulate(0,4)
        MulStoreDigit(4)
        MulShiftCarry

        MulAccumulate(5,0)
        MulAccumulate(4,1)
        MulAccumulate(3,2)
        MulAccumulate(2,3)
        MulAccumulate(1,4)
        MulAccumulate(0,5)
        MulStoreDigit(5)
        MulShiftCarry

        MulAccumulate(6,0)
        MulAccumulate(5,1)
        MulAccumulate(4,2)
        MulAccumulate(3,3)
        MulAccumulate(2,4)
        MulAccumulate(1,5)
        MulAccumulate(0,6)
        MulStoreDigit(6)
        MulShiftCarry

        MulAccumulate(7,0)
        MulAccumulate(6,1)
        MulAccumulate(5,2)
        MulAccumulate(4,3)
        MulAccumulate(3,4)
        MulAccumulate(2,5)
        MulAccumulate(1,6)
        MulAccumulate(0,7)
        MulStoreDigit(7)
        MulShiftCarry

        MulAccumulate(7,1)
        MulAccumulate(6,2)
        MulAccumulate(5,3)
        MulAccumulate(4,4)
        MulAccumulate(3,5)
        MulAccumulate(2,6)
        MulAccumulate(1,7)
        MulStoreDigit(8)
        MulShiftCarry

        MulAccumulate(7,2)
        MulAccumulate(6,3)
        MulAccumulate(5,4)
        MulAccumulate(4,5)
        MulAccumulate(3,6)
        MulAccumulate(2,7)
        MulStoreDigit(9)
        MulShiftCarry

        MulAccumulate(7,3)
        MulAccumulate(6,4)
        MulAccumulate(5,5)
        MulAccumulate(4,6)
        MulAccumulate(3,7)
        MulStoreDigit(10)
        MulShiftCarry

        MulAccumulate(7,4)
        MulAccumulate(6,5)
        MulAccumulate(5,6)
        MulAccumulate(4,7)
        MulStoreDigit(11)
        MulShiftCarry

        MulAccumulate(7,5)
        MulAccumulate(6,6)
        MulAccumulate(5,7)
        MulStoreDigit(12)
        MulShiftCarry

        MulAccumulate(7,6)
        MulAccumulate(6,7)
        MulStoreDigit(13)
        MulShiftCarry

        MulLastDiagonal(8)

        MulCleanup

        : 
        : "D" (Z), "S" (X), "a" (Y)
        : "%ecx", "%edx",  "memory"
    );
}

#elif defined(__GNUC__) && defined(__alpha__)

class AlphaOptimized : public Portable
{
public:
    static inline void Multiply2(word *C, const word *A, const word *B);
    static inline word Multiply2Add(word *C, const word *A, const word *B);
    static inline void Multiply4(word *C, const word *A, const word *B);
    static inline unsigned int MultiplyRecursionLimit() {return 4;}

    static inline void Multiply4Bottom(word *C, const word *A, const word *B);
    static inline unsigned int MultiplyBottomRecursionLimit() {return 4;}

    static inline void Square4(word *R, const word *A)
    {
        Multiply4(R, A, A);
    }
};

typedef AlphaOptimized LowLevel;

inline void AlphaOptimized::Multiply2(word *C, const word *A, const word *B)
{
    register dword c, a = *(const dword *)A, b = *(const dword *)B;
    ((dword *)C)[0] = a*b;
    __asm__("umulh %1,%2,%0" : "=r" (c) : "r" (a), "r" (b));
    ((dword *)C)[1] = c;
}

inline word AlphaOptimized::Multiply2Add(word *C, const word *A, const word *B)
{
    register dword c, d, e, a = *(const dword *)A, b = *(const dword *)B;
    c = ((dword *)C)[0];
    d = a*b + c;
    __asm__("umulh %1,%2,%0" : "=r" (e) : "r" (a), "r" (b));
    ((dword *)C)[0] = d;
    d = (d < c);
    c = ((dword *)C)[1] + d;
    d = (c < d);
    c += e;
    ((dword *)C)[1] = c;
    d |= (c < e);
    return d;
}

inline void AlphaOptimized::Multiply4(word *R, const word *A, const word *B)
{
    Multiply2(R, A, B);
    Multiply2(R+4, A+2, B+2);
    word carry = Multiply2Add(R+2, A+0, B+2);
    carry += Multiply2Add(R+2, A+2, B+0);
    Increment(R+6, 2, carry);
}

static inline void Multiply2BottomAdd(word *C, const word *A, const word *B)
{
    register dword a = *(const dword *)A, b = *(const dword *)B;
    ((dword *)C)[0] = a*b + ((dword *)C)[0];
}

inline void AlphaOptimized::Multiply4Bottom(word *R, const word *A,
                                            const word *B)
{
    Multiply2(R, A, B);
    Multiply2BottomAdd(R+2, A+0, B+2);
    Multiply2BottomAdd(R+2, A+2, B+0);
}

#else   // no processor specific code available

typedef Portable LowLevel;

#endif

// ********************************************************

#define A0      A
#define A1      (A+N2)
#define B0      B
#define B1      (B+N2)

#define T0      T
#define T1      (T+N2)
#define T2      (T+N)
#define T3      (T+N+N2)

#define R0      R
#define R1      (R+N2)
#define R2      (R+N)
#define R3      (R+N+N2)

//VC60 workaround: compiler bug triggered without the extra dummy parameters

// R[2*N] - result = A*B
// T[2*N] - temporary work space
// A[N] --- multiplier
// B[N] --- multiplicant

template <class P>
void DoRecursiveMultiply(word *R, word *T, const word *A, const word *B,
                         unsigned int N, const P *dummy=NULL);

template <class P>
inline void RecursiveMultiply(word *R, word *T, const word *A, const word *B,
                              unsigned int N, const P *dummy=NULL)
{
    assert(N>=2 && N%2==0);

    if (P::MultiplyRecursionLimit() >= 8 && N==8)
        P::Multiply8(R, A, B);
    else if (P::MultiplyRecursionLimit() >= 4 && N==4)
        P::Multiply4(R, A, B);
    else if (N==2)
        P::Multiply2(R, A, B);
    else
        DoRecursiveMultiply<P>(R, T, A, B, N, NULL);    
        // VC60 workaround: needs this NULL
}

template <class P>
void DoRecursiveMultiply(word *R, word *T, const word *A, const word *B,
                         unsigned int N, const P *dummy)
{
    const unsigned int N2 = N/2;
    int carry;

    int aComp = Compare(A0, A1, N2);
    int bComp = Compare(B0, B1, N2);

    switch (2*aComp + aComp + bComp)
    {
    case -4:
        P::Subtract(R0, A1, A0, N2);
        P::Subtract(R1, B0, B1, N2);
        RecursiveMultiply<P>(T0, T2, R0, R1, N2);
        P::Subtract(T1, T1, R0, N2);
        carry = -1;
        break;
    case -2:
        P::Subtract(R0, A1, A0, N2);
        P::Subtract(R1, B0, B1, N2);
        RecursiveMultiply<P>(T0, T2, R0, R1, N2);
        carry = 0;
        break;
    case 2:
        P::Subtract(R0, A0, A1, N2);
        P::Subtract(R1, B1, B0, N2);
        RecursiveMultiply<P>(T0, T2, R0, R1, N2);
        carry = 0;
        break;
    case 4:
        P::Subtract(R0, A1, A0, N2);
        P::Subtract(R1, B0, B1, N2);
        RecursiveMultiply<P>(T0, T2, R0, R1, N2);
        P::Subtract(T1, T1, R1, N2);
        carry = -1;
        break;
    default:
        SetWords(T0, 0, N);
        carry = 0;
    }

    RecursiveMultiply<P>(R0, T2, A0, B0, N2);
    RecursiveMultiply<P>(R2, T2, A1, B1, N2);

    // now T[01] holds (A1-A0)*(B0-B1), R[01] holds A0*B0, R[23] holds A1*B1

    carry += P::Add(T0, T0, R0, N);
    carry += P::Add(T0, T0, R2, N);
    carry += P::Add(R1, R1, T0, N);

    assert (carry >= 0 && carry <= 2);
    Increment(R3, N2, carry);
}

// R[2*N] - result = A*A
// T[2*N] - temporary work space
// A[N] --- number to be squared

template <class P>
void DoRecursiveSquare(word *R, word *T, const word *A, unsigned int N,
                       const P *dummy=NULL);

template <class P>
inline void RecursiveSquare(word *R, word *T, const word *A, unsigned int N,
                            const P *dummy=NULL)
{
    assert(N && N%2==0);
    if (P::SquareRecursionLimit() >= 8 && N==8)
        P::Square8(R, A);
    if (P::SquareRecursionLimit() >= 4 && N==4)
        P::Square4(R, A);
    else if (N==2)
        P::Square2(R, A);
    else
        DoRecursiveSquare<P>(R, T, A, N, NULL);	
        // VC60 workaround: needs this NULL
}

template <class P>
void DoRecursiveSquare(word *R, word *T, const word *A, unsigned int N,
                       const P *dummy)
{
    const unsigned int N2 = N/2;

    RecursiveSquare<P>(R0, T2, A0, N2);
    RecursiveSquare<P>(R2, T2, A1, N2);
    RecursiveMultiply<P>(T0, T2, A0, A1, N2);

    word carry = P::Add(R1, R1, T0, N);
    carry += P::Add(R1, R1, T0, N);
    Increment(R3, N2, carry);
}

// R[N] - bottom half of A*B
// T[N] - temporary work space
// A[N] - multiplier
// B[N] - multiplicant

template <class P>
void DoRecursiveMultiplyBottom(word *R, word *T, const word *A, const word *B,
                               unsigned int N, const P *dummy=NULL);

template <class P>
inline void RecursiveMultiplyBottom(word *R, word *T, const word *A,
                            const word *B, unsigned int N, const P *dummy=NULL)
{
    assert(N>=2 && N%2==0);
    if (P::MultiplyBottomRecursionLimit() >= 8 && N==8)
        P::Multiply8Bottom(R, A, B);
    else if (P::MultiplyBottomRecursionLimit() >= 4 && N==4)
        P::Multiply4Bottom(R, A, B);
    else if (N==2)
        P::Multiply2Bottom(R, A, B);
    else
        DoRecursiveMultiplyBottom<P>(R, T, A, B, N, NULL);
}

template <class P>
void DoRecursiveMultiplyBottom(word *R, word *T, const word *A, const word *B,
                               unsigned int N, const P *dummy)
{
    const unsigned int N2 = N/2;

    RecursiveMultiply<P>(R, T, A0, B0, N2);
    RecursiveMultiplyBottom<P>(T0, T1, A1, B0, N2);
    P::Add(R1, R1, T0, N2);
    RecursiveMultiplyBottom<P>(T0, T1, A0, B1, N2);
    P::Add(R1, R1, T0, N2);
}

// R[N] --- upper half of A*B
// T[2*N] - temporary work space
// L[N] --- lower half of A*B
// A[N] --- multiplier
// B[N] --- multiplicant

template <class P>
void RecursiveMultiplyTop(word *R, word *T, const word *L, const word *A,
                          const word *B, unsigned int N, const P *dummy=NULL)
{
    assert(N>=2 && N%2==0);

    if (N==4)
    {
        P::Multiply4(T, A, B);
        ((dword *)R)[0] = ((dword *)T)[2];
        ((dword *)R)[1] = ((dword *)T)[3];
    }
    else if (N==2)
    {
        P::Multiply2(T, A, B);
        ((dword *)R)[0] = ((dword *)T)[1];
    }
    else
    {
        const unsigned int N2 = N/2;
        int carry;

        int aComp = Compare(A0, A1, N2);
        int bComp = Compare(B0, B1, N2);

        switch (2*aComp + aComp + bComp)
        {
        case -4:
            P::Subtract(R0, A1, A0, N2);
            P::Subtract(R1, B0, B1, N2);
            RecursiveMultiply<P>(T0, T2, R0, R1, N2);
            P::Subtract(T1, T1, R0, N2);
            carry = -1;
            break;
        case -2:
            P::Subtract(R0, A1, A0, N2);
            P::Subtract(R1, B0, B1, N2);
            RecursiveMultiply<P>(T0, T2, R0, R1, N2);
            carry = 0;
            break;
        case 2:
            P::Subtract(R0, A0, A1, N2);
            P::Subtract(R1, B1, B0, N2);
            RecursiveMultiply<P>(T0, T2, R0, R1, N2);
            carry = 0;
            break;
        case 4:
            P::Subtract(R0, A1, A0, N2);
            P::Subtract(R1, B0, B1, N2);
            RecursiveMultiply<P>(T0, T2, R0, R1, N2);
            P::Subtract(T1, T1, R1, N2);
            carry = -1;
            break;
        default:
            SetWords(T0, 0, N);
            carry = 0;
        }

        RecursiveMultiply<P>(T2, R0, A1, B1, N2);

        // now T[01] holds (A1-A0)*(B0-B1), T[23] holds A1*B1

        word c2 = P::Subtract(R0, L+N2, L, N2);
        c2 += P::Subtract(R0, R0, T0, N2);
        word t = (Compare(R0, T2, N2) == -1);

        carry += t;
        carry += Increment(R0, N2, c2+t);
        carry += P::Add(R0, R0, T1, N2);
        carry += P::Add(R0, R0, T3, N2);
        assert (carry >= 0 && carry <= 2);

        CopyWords(R1, T3, N2);
        Increment(R1, N2, carry);
    }
}

inline word Add(word *C, const word *A, const word *B, unsigned int N)
{
    return LowLevel::Add(C, A, B, N);
}

inline word Subtract(word *C, const word *A, const word *B, unsigned int N)
{
    return LowLevel::Subtract(C, A, B, N);
}

inline void Multiply(word *R, word *T, const word *A, const word *B,
                     unsigned int N)
{
#ifdef SSE2_INTRINSICS_AVAILABLE
    if (HasSSE2())
        RecursiveMultiply<P4Optimized>(R, T, A, B, N);
    else
#endif
        RecursiveMultiply<LowLevel>(R, T, A, B, N);
}

inline void Square(word *R, word *T, const word *A, unsigned int N)
{
#ifdef SSE2_INTRINSICS_AVAILABLE
    if (HasSSE2())
        RecursiveSquare<P4Optimized>(R, T, A, N);
    else
#endif
        RecursiveSquare<LowLevel>(R, T, A, N);
}


void AsymmetricMultiply(word *R, word *T, const word *A, unsigned int NA,
                        const word *B, unsigned int NB)
{
    if (NA == NB)
    {
        if (A == B)
            Square(R, T, A, NA);
        else
            Multiply(R, T, A, B, NA);

        return;
    }

    if (NA > NB)
    {
        std::swap(A, B);
        std::swap(NA, NB);
    }

    assert(NB % NA == 0);
    assert((NB/NA)%2 == 0); 	// NB is an even multiple of NA

    if (NA==2 && !A[1])
    {
        switch (A[0])
        {
        case 0:
            SetWords(R, 0, NB+2);
            return;
        case 1:
            CopyWords(R, B, NB);
            R[NB] = R[NB+1] = 0;
            return;
        default:
            R[NB] = LinearMultiply(R, B, A[0], NB);
            R[NB+1] = 0;
            return;
        }
    }

    Multiply(R, T, A, B, NA);
    CopyWords(T+2*NA, R+NA, NA);

    unsigned i;

    for (i=2*NA; i<NB; i+=2*NA)
        Multiply(T+NA+i, T, A, B+i, NA);
    for (i=NA; i<NB; i+=2*NA)
        Multiply(R+i, T, A, B+i, NA);

    if (Add(R+NA, R+NA, T+2*NA, NB-NA))
        Increment(R+NB, NA);
}


void PositiveMultiply(Integer& product, const Integer& a, const Integer& b)
{
    unsigned int aSize = RoundupSize(a.WordCount());
    unsigned int bSize = RoundupSize(b.WordCount());

    product.reg_.CleanNew(RoundupSize(aSize + bSize));
    product.sign_ = Integer::POSITIVE;

    WordBlock workspace(aSize + bSize);
    AsymmetricMultiply(product.reg_.get_buffer(), workspace.get_buffer(),
                       a.reg_.get_buffer(), aSize, b.reg_.get_buffer(), bSize);
}

void Multiply(Integer &product, const Integer &a, const Integer &b)
{
    PositiveMultiply(product, a, b);

    if (a.NotNegative() != b.NotNegative())
        product.Negate();
}


static inline unsigned int EvenWordCount(const word *X, unsigned int N)
{
    while (N && X[N-2]==0 && X[N-1]==0)
        N-=2;
    return N;
}


unsigned int AlmostInverse(word *R, word *T, const word *A, unsigned int NA,
                           const word *M, unsigned int N)
{
    assert(NA<=N && N && N%2==0);

    word *b = T;
    word *c = T+N;
    word *f = T+2*N;
    word *g = T+3*N;
    unsigned int bcLen=2, fgLen=EvenWordCount(M, N);
    unsigned int k=0, s=0;

    SetWords(T, 0, 3*N);
    b[0]=1;
    CopyWords(f, A, NA);
    CopyWords(g, M, N);

    while (1)
    {
        word t=f[0];
        while (!t)
        {
            if (EvenWordCount(f, fgLen)==0)
            {
                SetWords(R, 0, N);
                return 0;
            }

            ShiftWordsRightByWords(f, fgLen, 1);
            if (c[bcLen-1]) bcLen+=2;
            assert(bcLen <= N);
            ShiftWordsLeftByWords(c, bcLen, 1);
            k+=WORD_BITS;
            t=f[0];
        }

        unsigned int i=0;
        while (t%2 == 0)
        {
            t>>=1;
            i++;
        }
        k+=i;

        if (t==1 && f[1]==0 && EvenWordCount(f, fgLen)==2)
        {
            if (s%2==0)
                CopyWords(R, b, N);
            else
                Subtract(R, M, b, N);
            return k;
        }

        ShiftWordsRightByBits(f, fgLen, i);
        t=ShiftWordsLeftByBits(c, bcLen, i);
        if (t)
        {
            c[bcLen] = t;
            bcLen+=2;
            assert(bcLen <= N);
        }

        if (f[fgLen-2]==0 && g[fgLen-2]==0 && f[fgLen-1]==0 && g[fgLen-1]==0)
            fgLen-=2;

        if (Compare(f, g, fgLen)==-1)
        {
            std::swap(f, g);
            std::swap(b, c);
            s++;
        }

        Subtract(f, f, g, fgLen);

        if (Add(b, b, c, bcLen))
        {
            b[bcLen] = 1;
            bcLen+=2;
            assert(bcLen <= N);
        }
    }
}

// R[N] - result = A/(2^k) mod M
// A[N] - input
// M[N] - modulus

void DivideByPower2Mod(word *R, const word *A, unsigned int k, const word *M,
                       unsigned int N)
{
    CopyWords(R, A, N);

    while (k--)
    {
        if (R[0]%2==0)
            ShiftWordsRightByBits(R, N, 1);
        else
        {
            word carry = Add(R, R, M, N);
            ShiftWordsRightByBits(R, N, 1);
            R[N-1] += carry<<(WORD_BITS-1);
        }
    }
}

// R[N] - result = A*(2^k) mod M
// A[N] - input
// M[N] - modulus

void MultiplyByPower2Mod(word *R, const word *A, unsigned int k, const word *M,
                         unsigned int N)
{
    CopyWords(R, A, N);

    while (k--)
        if (ShiftWordsLeftByBits(R, N, 1) || Compare(R, M, N)>=0)
            Subtract(R, R, M, N);
}


// ********** end of integer needs


Integer::Integer()
    : reg_(2), sign_(POSITIVE)
{
    reg_[0] = reg_[1] = 0;
}


Integer::Integer(const Integer& t)
    : reg_(RoundupSize(t.WordCount())), sign_(t.sign_)
{
    CopyWords(reg_.get_buffer(), t.reg_.get_buffer(), reg_.size());
}


Integer::Integer(signed long value)
    : reg_(2)
{
    if (value >= 0)
        sign_ = POSITIVE;
    else
    {
        sign_ = NEGATIVE;
        value = -value;
    }
    reg_[0] = word(value);
    reg_[1] = word(SafeRightShift<WORD_BITS, unsigned long>(value));
}


Integer::Integer(Sign s, word high, word low)
    : reg_(2), sign_(s)
{
    reg_[0] = low;
    reg_[1] = high;
}


Integer::Integer(word value, unsigned int length)
    : reg_(RoundupSize(length)), sign_(POSITIVE)
{
    reg_[0] = value;
    SetWords(reg_ + 1, 0, reg_.size() - 1);
}


Integer::Integer(const char *str)
    : reg_(2), sign_(POSITIVE)
{
    *this = StringToInteger(str);
}


Integer::Integer(const wchar_t *str)
    : reg_(2), sign_(POSITIVE)
{
    *this = StringToInteger(str);
}


Integer::Integer(const byte *encodedInteger, unsigned int byteCount,
                 Signedness s)
{
    Decode(encodedInteger, byteCount, s);
}

class BadBER {};

// BER Decode Sink
Integer::Integer(Sink& sink)
    : reg_(2), sign_(POSITIVE)
{
    Decode(sink);
}

void Integer::Decode(Sink& sink)
{
    byte b = sink.next();
    if (b != INTEGER)  
        throw BadBER();

    unsigned int length(0);
    b = sink.next();

    if (b >= LONG_LENGTH) {        
        unsigned int bytes = b & 0x7F;

        while (bytes--) {
            b = sink.next();
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    if ( (b = sink.next()) == 0x00)
        length--;
    else
        sink.prev();
 
    unsigned int words = (length + WORD_SIZE - 1) / WORD_SIZE;
    words = RoundupSize(words);
    if (words > reg_.size()) reg_.CleanNew(words);

    for (int j = length; j > 0; j--) {
        b = sink.next();
        reg_ [(j-1) / WORD_SIZE] |= b << ((j-1) % WORD_SIZE) * 8;
    }
}


void Integer::Decode(const byte* input, unsigned int inputLen, Signedness s)
{
    unsigned int idx(0);
    byte b = input[idx++];
    sign_  = ((s==SIGNED) && (b & 0x80)) ? NEGATIVE : POSITIVE;

    while (inputLen>0 && (sign_==POSITIVE ? b==0 : b==0xff))
    {
        inputLen--;
        b = input[idx++];
    }

    reg_.CleanNew(RoundupSize(BytesToWords(inputLen)));

    --idx;
    for (unsigned int i=inputLen; i > 0; i--)
    {
        b = input[idx++];
        reg_[(i-1)/WORD_SIZE] |= b << ((i-1)%WORD_SIZE)*8;
    }

    if (sign_ == NEGATIVE)
    {
        for (unsigned i=inputLen; i<reg_.size()*WORD_SIZE; i++)
            reg_[i/WORD_SIZE] |= 0xff << (i%WORD_SIZE)*8;
        TwosComplement(reg_.get_buffer(), reg_.size());
    }
}


unsigned int Integer::Encode(byte* output, unsigned int outputLen,
                       Signedness signedness) const
{
    unsigned int idx(0);
    if (signedness == UNSIGNED || NotNegative())
    {
        for (unsigned int i=outputLen; i > 0; i--)
            output[idx++] = GetByte(i-1);
    }
    else
    {
        // take two's complement of *this
        Integer temp = Integer::Power2(8*max(ByteCount(), outputLen)) + *this;
        for (unsigned i=0; i<outputLen; i++)
            output[idx++] = temp.GetByte(outputLen-i-1);
    }
    return outputLen;
}


const Integer &Integer::Zero()
{
    static const Integer zero;
    return zero;
}


const Integer &Integer::One()
{
    static const Integer one(1,2);
    return one;
}


const Integer &Integer::Two()
{
    static const Integer two(2,2);
    return two;
}


Integer::Integer(RandomNumberGenerator& rng, const Integer& min,
                 const Integer& max)
{
    Randomize(rng, min, max);
}


void Integer::Randomize(RandomNumberGenerator& rng, unsigned int nbits)
{
    const unsigned int nbytes = nbits/8 + 1;
    ByteBlock buf(nbytes);
    rng.GenerateBlock(buf.get_buffer(), nbytes);
    if (nbytes)
        buf[0] = (byte)Crop(buf[0], nbits % 8);
    Decode(buf.get_buffer(), nbytes, UNSIGNED);
}

void Integer::Randomize(RandomNumberGenerator& rng, const Integer& min,
                        const Integer& max)
{
    if (min > max)
        throw std::runtime_error("Integer: Min must be no greater than Max");

    Integer range = max - min;
    const unsigned int nbits = range.BitCount();

    do
    {
        Randomize(rng, nbits);
    }
    while (*this > range);

    *this += min;
}


Integer Integer::Power2(unsigned int e)
{
    Integer r((word)0, BitsToWords(e + 1));
    r.SetBit(e);
    return r;
}


void Integer::SetBit(unsigned int n, bool value)
{
    if (value)
    {
        reg_.CleanGrow(RoundupSize(BitsToWords(n + 1)));
        reg_[n / WORD_BITS] |= (word(1) << (n % WORD_BITS));
    }
    else
    {
        if (n / WORD_BITS < reg_.size())
            reg_[n / WORD_BITS] &= ~(word(1) << (n % WORD_BITS));
    }
}


void Integer::SetByte(unsigned int n, byte value)
{
    reg_.CleanGrow(RoundupSize(BytesToWords(n+1)));
    reg_[n/WORD_SIZE] &= ~(word(0xff) << 8*(n%WORD_SIZE));
    reg_[n/WORD_SIZE] |= (word(value) << 8*(n%WORD_SIZE));
}


void Integer::Negate()
{
    if (!!(*this))	// don't flip sign if *this==0
        sign_ = Sign(1 - sign_);
}


bool Integer::operator!() const
{
    return IsNegative() ? false : (reg_[0]==0 && WordCount()==0);
}


Integer& Integer::operator=(const Integer& t)
{
    if (this != &t)
    {
        reg_.New(RoundupSize(t.WordCount()));
        CopyWords(reg_.get_buffer(), t.reg_.get_buffer(), reg_.size());
        sign_ = t.sign_;
    }
    return *this;
}


Integer& Integer::operator+=(const Integer& t)
{
    reg_.CleanGrow(t.reg_.size());
    if (NotNegative())
    {
        if (t.NotNegative())
            PositiveAdd(*this, *this, t);
        else
            PositiveSubtract(*this, *this, t);
    }
    else
    {
        if (t.NotNegative())
            PositiveSubtract(*this, t, *this);
        else
        {
            PositiveAdd(*this, *this, t);
            sign_ = Integer::NEGATIVE;
        }
    }
    return *this;
}


Integer Integer::operator-() const
{
    Integer result(*this);
    result.Negate();
    return result;
}


Integer& Integer::operator-=(const Integer& t)
{
    reg_.CleanGrow(t.reg_.size());
    if (NotNegative())
    {
        if (t.NotNegative())
            PositiveSubtract(*this, *this, t);
        else
            PositiveAdd(*this, *this, t);
    }
    else
    {
        if (t.NotNegative())
        {
            PositiveAdd(*this, *this, t);
            sign_ = Integer::NEGATIVE;
        }
        else
            PositiveSubtract(*this, t, *this);
    }
    return *this;
}


Integer& Integer::operator++()
{
    if (NotNegative())
    {
        if (Increment(reg_.get_buffer(), reg_.size()))
        {
            reg_.CleanGrow(2*reg_.size());
            reg_[reg_.size()/2]=1;
        }
    }
    else
    {
        word borrow = Decrement(reg_.get_buffer(), reg_.size());
        assert(!borrow);
        if (WordCount()==0)
            *this = Zero();
    }
    return *this;
}

Integer& Integer::operator--()
{
    if (IsNegative())
    {
        if (Increment(reg_.get_buffer(), reg_.size()))
        {
            reg_.CleanGrow(2*reg_.size());
            reg_[reg_.size()/2]=1;
        }
    }
    else
    {
        if (Decrement(reg_.get_buffer(), reg_.size()))
            *this = -One();
    }
    return *this;
}


Integer& Integer::operator<<=(unsigned int n)
{
    const unsigned int wordCount = WordCount();
    const unsigned int shiftWords = n / WORD_BITS;
    const unsigned int shiftBits = n % WORD_BITS;

    reg_.CleanGrow(RoundupSize(wordCount+BitsToWords(n)));
    ShiftWordsLeftByWords(reg_.get_buffer(), wordCount + shiftWords,
                          shiftWords);
    ShiftWordsLeftByBits(reg_+shiftWords, wordCount+BitsToWords(shiftBits),
                         shiftBits);
    return *this;
}

Integer& Integer::operator>>=(unsigned int n)
{
    const unsigned int wordCount = WordCount();
    const unsigned int shiftWords = n / WORD_BITS;
    const unsigned int shiftBits = n % WORD_BITS;

    ShiftWordsRightByWords(reg_.get_buffer(), wordCount, shiftWords);
    if (wordCount > shiftWords)
        ShiftWordsRightByBits(reg_.get_buffer(), wordCount-shiftWords,
                              shiftBits);
    if (IsNegative() && WordCount()==0)   // avoid -0
        *this = Zero();
    return *this;
}


void PositiveAdd(Integer& sum, const Integer& a, const Integer& b)
{
    word carry;
    if (a.reg_.size() == b.reg_.size())
        carry = Add(sum.reg_.get_buffer(), a.reg_.get_buffer(),
                    b.reg_.get_buffer(), a.reg_.size());
    else if (a.reg_.size() > b.reg_.size())
    {
        carry = Add(sum.reg_.get_buffer(), a.reg_.get_buffer(),
                    b.reg_.get_buffer(), b.reg_.size());
        CopyWords(sum.reg_+b.reg_.size(), a.reg_+b.reg_.size(),
                  a.reg_.size()-b.reg_.size());
        carry = Increment(sum.reg_+b.reg_.size(), a.reg_.size()-b.reg_.size(),
                          carry);
    }
    else
    {
        carry = Add(sum.reg_.get_buffer(), a.reg_.get_buffer(),
                    b.reg_.get_buffer(), a.reg_.size());
        CopyWords(sum.reg_+a.reg_.size(), b.reg_+a.reg_.size(),
                  b.reg_.size()-a.reg_.size());
        carry = Increment(sum.reg_+a.reg_.size(), b.reg_.size()-a.reg_.size(),
                          carry);
    }

    if (carry)
    {
        sum.reg_.CleanGrow(2*sum.reg_.size());
        sum.reg_[sum.reg_.size()/2] = 1;
    }
    sum.sign_ = Integer::POSITIVE;
}

void PositiveSubtract(Integer &diff, const Integer &a, const Integer& b)
{
    unsigned aSize = a.WordCount();
    aSize += aSize%2;
    unsigned bSize = b.WordCount();
    bSize += bSize%2;

    if (aSize == bSize)
    {
        if (Compare(a.reg_.get_buffer(), b.reg_.get_buffer(), aSize) >= 0)
        {
            Subtract(diff.reg_.get_buffer(), a.reg_.get_buffer(),
                     b.reg_.get_buffer(), aSize);
            diff.sign_ = Integer::POSITIVE;
        }
        else
        {
            Subtract(diff.reg_.get_buffer(), b.reg_.get_buffer(),
                     a.reg_.get_buffer(), aSize);
            diff.sign_ = Integer::NEGATIVE;
        }
    }
    else if (aSize > bSize)
    {
        word borrow = Subtract(diff.reg_.get_buffer(), a.reg_.get_buffer(),
                               b.reg_.get_buffer(), bSize);
        CopyWords(diff.reg_+bSize, a.reg_+bSize, aSize-bSize);
        borrow = Decrement(diff.reg_+bSize, aSize-bSize, borrow);
        assert(!borrow);
        diff.sign_ = Integer::POSITIVE;
    }
    else
    {
        word borrow = Subtract(diff.reg_.get_buffer(), b.reg_.get_buffer(),
                               a.reg_.get_buffer(), aSize);
        CopyWords(diff.reg_+aSize, b.reg_+aSize, bSize-aSize);
        borrow = Decrement(diff.reg_+aSize, bSize-aSize, borrow);
        assert(!borrow);
        diff.sign_ = Integer::NEGATIVE;
    }
}


unsigned int Integer::MinEncodedSize(Signedness signedness) const
{
    unsigned int outputLen = max(1U, ByteCount());
    if (signedness == UNSIGNED)
        return outputLen;
    if (NotNegative() && (GetByte(outputLen-1) & 0x80))
        outputLen++;
    if (IsNegative() && *this < -Power2(outputLen*8-1))
        outputLen++;
    return outputLen;
}


int Integer::Compare(const Integer& t) const
{
    if (NotNegative())
    {
        if (t.NotNegative())
            return PositiveCompare(t);
        else
            return 1;
    }
    else
    {
        if (t.NotNegative())
            return -1;
        else
            return -PositiveCompare(t);
    }
}


int Integer::PositiveCompare(const Integer& t) const
{
    unsigned size = WordCount(), tSize = t.WordCount();

    if (size == tSize)
        return TaoCrypt::Compare(reg_.get_buffer(), t.reg_.get_buffer(), size);
    else
        return size > tSize ? 1 : -1;
}


bool Integer::GetBit(unsigned int n) const
{
    if (n/WORD_BITS >= reg_.size())
        return 0;
    else
        return bool((reg_[n/WORD_BITS] >> (n % WORD_BITS)) & 1);
}


unsigned long Integer::GetBits(unsigned int i, unsigned int n) const
{
    assert(n <= sizeof(unsigned long)*8);
    unsigned long v = 0;
    for (unsigned int j=0; j<n; j++)
        v |= GetBit(i+j) << j;
    return v;
}


byte Integer::GetByte(unsigned int n) const
{
    if (n/WORD_SIZE >= reg_.size())
        return 0;
    else
        return byte(reg_[n/WORD_SIZE] >> ((n%WORD_SIZE)*8));
}


unsigned int Integer::BitCount() const
{
    unsigned wordCount = WordCount();
    if (wordCount)
        return (wordCount-1)*WORD_BITS + BitPrecision(reg_[wordCount-1]);
    else
        return 0;
}


unsigned int Integer::ByteCount() const
{
    unsigned wordCount = WordCount();
    if (wordCount)
        return (wordCount-1)*WORD_SIZE + BytePrecision(reg_[wordCount-1]);
    else
        return 0;
}


unsigned int Integer::WordCount() const
{
    return CountWords(reg_.get_buffer(), reg_.size());
}


bool Integer::IsConvertableToLong() const
{
    if (ByteCount() > sizeof(long))
        return false;

    unsigned long value = reg_[0];
    value += SafeLeftShift<WORD_BITS, unsigned long>(reg_[1]);

    if (sign_ == POSITIVE)
        return (signed long)value >= 0;
    else
        return -(signed long)value < 0;
}


signed long Integer::ConvertToLong() const
{
    assert(IsConvertableToLong());

    unsigned long value = reg_[0];
    value += SafeLeftShift<WORD_BITS, unsigned long>(reg_[1]);
    return sign_ == POSITIVE ? value : -(signed long)value;
}


void Integer::swap(Integer& a)
{
    reg_.swap(a.reg_);
    std::swap(sign_, a.sign_);
}


Integer Integer::Plus(const Integer& b) const
{
    Integer sum((word)0, max(reg_.size(), b.reg_.size()));
    if (NotNegative())
    {
        if (b.NotNegative())
            PositiveAdd(sum, *this, b);
        else
            PositiveSubtract(sum, *this, b);
    }
    else
    {
        if (b.NotNegative())
            PositiveSubtract(sum, b, *this);
        else
        {
            PositiveAdd(sum, *this, b);
            sum.sign_ = Integer::NEGATIVE;
        }
    }
    return sum;
}


Integer Integer::Minus(const Integer& b) const
{
    Integer diff((word)0, max(reg_.size(), b.reg_.size()));
    if (NotNegative())
    {
        if (b.NotNegative())
            PositiveSubtract(diff, *this, b);
        else
            PositiveAdd(diff, *this, b);
    }
    else
    {
        if (b.NotNegative())
        {
            PositiveAdd(diff, *this, b);
            diff.sign_ = Integer::NEGATIVE;
        }
        else
            PositiveSubtract(diff, b, *this);
    }
    return diff;
}


Integer Integer::Times(const Integer &b) const
{
    Integer product;
    Multiply(product, *this, b);
    return product;
}


#undef A0
#undef A1
#undef B0
#undef B1

#undef T0
#undef T1
#undef T2
#undef T3

#undef R0
#undef R1
#undef R2
#undef R3

// do a 3 word by 2 word divide, returns quotient and leaves remainder in A
static word SubatomicDivide(word *A, word B0, word B1)
{
    // assert {A[2],A[1]} < {B1,B0}, so quotient can fit in a word
    assert(A[2] < B1 || (A[2]==B1 && A[1] < B0));

    dword p, u;
    word Q;

    // estimate the quotient: do a 2 word by 1 word divide
    if (B1+1 == 0)
        Q = A[2];
    else
        Q = word(MAKE_DWORD(A[1], A[2]) / (B1+1));

    // now subtract Q*B from A
    p = (dword) B0*Q;
    u = (dword) A[0] - LOW_WORD(p);
    A[0] = LOW_WORD(u);
    u = (dword) A[1] - HIGH_WORD(p) - (word)(0-HIGH_WORD(u)) - (dword)B1*Q;
    A[1] = LOW_WORD(u);
    A[2] += HIGH_WORD(u);

    // Q <= actual quotient, so fix it
    while (A[2] || A[1] > B1 || (A[1]==B1 && A[0]>=B0))
    {
        u = (dword) A[0] - B0;
        A[0] = LOW_WORD(u);
        u = (dword) A[1] - B1 - (word)(0-HIGH_WORD(u));
        A[1] = LOW_WORD(u);
        A[2] += HIGH_WORD(u);
        Q++;
        assert(Q);	// shouldn't overflow
    }

    return Q;
}


// do a 4 word by 2 word divide, returns 2 word quotient in Q0 and Q1
static inline void AtomicDivide(word *Q, const word *A, const word *B)
{
    if (!B[0] && !B[1]) // if divisor is 0, we assume divisor==2**(2*WORD_BITS)
    {
        Q[0] = A[2];
        Q[1] = A[3];
    }
    else
    {
        word T[4];
        T[0] = A[0]; T[1] = A[1]; T[2] = A[2]; T[3] = A[3];
        Q[1] = SubatomicDivide(T+1, B[0], B[1]);
        Q[0] = SubatomicDivide(T, B[0], B[1]);

#ifndef NDEBUG
        // multiply quotient and divisor and add remainder
        // make sure it equals dividend
        assert(!T[2] && !T[3] && (T[1] < B[1] || (T[1]==B[1] && T[0]<B[0])));
        word P[4];
        LowLevel::Multiply2(P, Q, B);
        Add(P, P, T, 4);
        assert(memcmp(P, A, 4*WORD_SIZE)==0);
#endif
    }
}

// for use by Divide(), corrects the underestimated quotient {Q1,Q0}
static void CorrectQuotientEstimate(word *R, word *T, word *Q, const word *B,
                                    unsigned int N)
{
    assert(N && N%2==0);

    if (Q[1])
    {
        T[N] = T[N+1] = 0;
        unsigned i;
        for (i=0; i<N; i+=4)
            LowLevel::Multiply2(T+i, Q, B+i);
        for (i=2; i<N; i+=4)
            if (LowLevel::Multiply2Add(T+i, Q, B+i))
                T[i+5] += (++T[i+4]==0);
    }
    else
    {
        T[N] = LinearMultiply(T, B, Q[0], N);
        T[N+1] = 0;
    }

    word borrow = Subtract(R, R, T, N+2);
    assert(!borrow && !R[N+1]);

    while (R[N] || Compare(R, B, N) >= 0)
    {
        R[N] -= Subtract(R, R, B, N);
        Q[1] += (++Q[0]==0);
        assert(Q[0] || Q[1]); // no overflow
    }
}

// R[NB] -------- remainder = A%B
// Q[NA-NB+2] --- quotient	= A/B
// T[NA+2*NB+4] - temp work space
// A[NA] -------- dividend
// B[NB] -------- divisor


void Divide(word* R, word* Q, word* T, const word* A, unsigned int NA,
            const word* B, unsigned int NB)
{
    assert(NA && NB && NA%2==0 && NB%2==0);
    assert(B[NB-1] || B[NB-2]);
    assert(NB <= NA);

    // set up temporary work space
    word *const TA=T;
    word *const TB=T+NA+2;
    word *const TP=T+NA+2+NB;

    // copy B into TB and normalize it so that TB has highest bit set to 1
    unsigned shiftWords = (B[NB-1]==0);
    TB[0] = TB[NB-1] = 0;
    CopyWords(TB+shiftWords, B, NB-shiftWords);
    unsigned shiftBits = WORD_BITS - BitPrecision(TB[NB-1]);
    assert(shiftBits < WORD_BITS);
    ShiftWordsLeftByBits(TB, NB, shiftBits);

    // copy A into TA and normalize it
    TA[0] = TA[NA] = TA[NA+1] = 0;
    CopyWords(TA+shiftWords, A, NA);
    ShiftWordsLeftByBits(TA, NA+2, shiftBits);

    if (TA[NA+1]==0 && TA[NA] <= 1)
    {
        Q[NA-NB+1] = Q[NA-NB] = 0;
        while (TA[NA] || Compare(TA+NA-NB, TB, NB) >= 0)
        {
            TA[NA] -= Subtract(TA+NA-NB, TA+NA-NB, TB, NB);
            ++Q[NA-NB];
        }
    }
    else
    {
        NA+=2;
        assert(Compare(TA+NA-NB, TB, NB) < 0);
    }

    word BT[2];
    BT[0] = TB[NB-2] + 1;
    BT[1] = TB[NB-1] + (BT[0]==0);

    // start reducing TA mod TB, 2 words at a time
    for (unsigned i=NA-2; i>=NB; i-=2)
    {
        AtomicDivide(Q+i-NB, TA+i-2, BT);
        CorrectQuotientEstimate(TA+i-NB, TP, Q+i-NB, TB, NB);
    }

    // copy TA into R, and denormalize it
    CopyWords(R, TA+shiftWords, NB);
    ShiftWordsRightByBits(R, NB, shiftBits);
}


void PositiveDivide(Integer& remainder, Integer& quotient,
                   const Integer& a, const Integer& b)
{
    unsigned aSize = a.WordCount();
    unsigned bSize = b.WordCount();

    if (!bSize)
        throw Integer::DivideByZero();

    if (a.PositiveCompare(b) == -1)
    {
        remainder = a;
        remainder.sign_ = Integer::POSITIVE;
        quotient = Integer::Zero();
        return;
    }

    aSize += aSize%2;	// round up to next even number
    bSize += bSize%2;

    remainder.reg_.CleanNew(RoundupSize(bSize));
    remainder.sign_ = Integer::POSITIVE;
    quotient.reg_.CleanNew(RoundupSize(aSize-bSize+2));
    quotient.sign_ = Integer::POSITIVE;

    WordBlock T(aSize+2*bSize+4);
    Divide(remainder.reg_.get_buffer(), quotient.reg_.get_buffer(),
           T.get_buffer(), a.reg_.get_buffer(), aSize, b.reg_.get_buffer(),
           bSize);
}

void Integer::Divide(Integer &remainder, Integer &quotient,
                     const Integer &dividend, const Integer &divisor)
{
    PositiveDivide(remainder, quotient, dividend, divisor);

    if (dividend.IsNegative())
    {
        quotient.Negate();
        if (remainder.NotZero())
        {
            --quotient;
            remainder = divisor.AbsoluteValue() - remainder;
        }
    }

    if (divisor.IsNegative())
        quotient.Negate();
}

void Integer::DivideByPowerOf2(Integer &r, Integer &q, const Integer &a,
                               unsigned int n)
{
    q = a;
    q >>= n;

    const unsigned int wordCount = BitsToWords(n);
    if (wordCount <= a.WordCount())
    {
        r.reg_.resize(RoundupSize(wordCount));
        CopyWords(r.reg_.get_buffer(), a.reg_.get_buffer(), wordCount);
        SetWords(r.reg_+wordCount, 0, r.reg_.size()-wordCount);
        if (n % WORD_BITS != 0)
            r.reg_[wordCount-1] %= (1 << (n % WORD_BITS));
    }
    else
    {
        r.reg_.resize(RoundupSize(a.WordCount()));
        CopyWords(r.reg_.get_buffer(), a.reg_.get_buffer(), r.reg_.size());
    }
    r.sign_ = POSITIVE;

    if (a.IsNegative() && r.NotZero())
    {
        --q;
        r = Power2(n) - r;
    }
}

Integer Integer::DividedBy(const Integer &b) const
{
    Integer remainder, quotient;
    Integer::Divide(remainder, quotient, *this, b);
    return quotient;
}

Integer Integer::Modulo(const Integer &b) const
{
    Integer remainder, quotient;
    Integer::Divide(remainder, quotient, *this, b);
    return remainder;
}

void Integer::Divide(word &remainder, Integer &quotient,
                     const Integer &dividend, word divisor)
{
    if (!divisor)
        throw Integer::DivideByZero();

    assert(divisor);

    if ((divisor & (divisor-1)) == 0)	// divisor is a power of 2
    {
        quotient = dividend >> (BitPrecision(divisor)-1);
        remainder = dividend.reg_[0] & (divisor-1);
        return;
    }

    unsigned int i = dividend.WordCount();
    quotient.reg_.CleanNew(RoundupSize(i));
    remainder = 0;
    while (i--)
    {
        quotient.reg_[i] = word(MAKE_DWORD(dividend.reg_[i], remainder) /
                           divisor);
        remainder = word(MAKE_DWORD(dividend.reg_[i], remainder) % divisor);
    }

    if (dividend.NotNegative())
        quotient.sign_ = POSITIVE;
    else
    {
        quotient.sign_ = NEGATIVE;
        if (remainder)
        {
            --quotient;
            remainder = divisor - remainder;
        }
    }
}

Integer Integer::DividedBy(word b) const
{
    word remainder;
    Integer quotient;
    Integer::Divide(remainder, quotient, *this, b);
    return quotient;
}

word Integer::Modulo(word divisor) const
{
    if (!divisor)
        throw Integer::DivideByZero();

    assert(divisor);

    word remainder;

    if ((divisor & (divisor-1)) == 0)	// divisor is a power of 2
        remainder = reg_[0] & (divisor-1);
    else
    {
        unsigned int i = WordCount();

        if (divisor <= 5)
        {
            dword sum=0;
            while (i--)
                sum += reg_[i];
            remainder = word(sum%divisor);
        }
        else
        {
            remainder = 0;
            while (i--)
                remainder = word(MAKE_DWORD(reg_[i], remainder) % divisor);
        }
    }

    if (IsNegative() && remainder)
        remainder = divisor - remainder;

    return remainder;
}


Integer Integer::AbsoluteValue() const
{
    Integer result(*this);
    result.sign_ = POSITIVE;
    return result;
}


Integer Integer::SquareRoot() const
{
    if (!IsPositive())
        return Zero();

    // overestimate square root
    Integer x, y = Power2((BitCount()+1)/2);
    assert(y*y >= *this);

    do
    {
        x = y;
        y = (x + *this/x) >> 1;
    } while (y<x);

    return x;
}

bool Integer::IsSquare() const
{
    Integer r = SquareRoot();
    return *this == r.Squared();
}

bool Integer::IsUnit() const
{
    return (WordCount() == 1) && (reg_[0] == 1);
}

Integer Integer::MultiplicativeInverse() const
{
    return IsUnit() ? *this : Zero();
}

Integer a_times_b_mod_c(const Integer &x, const Integer& y, const Integer& m)
{
    return x*y%m;
}

Integer a_exp_b_mod_c(const Integer &x, const Integer& e, const Integer& m)
{
    ModularArithmetic mr(m);
    return mr.Exponentiate(x, e);
}

Integer Integer::Gcd(const Integer &a, const Integer &b)
{
    return EuclideanDomainOf<Integer>().Gcd(a, b);
}

Integer Integer::InverseMod(const Integer &m) const
{
    assert(m.NotNegative());

    if (IsNegative() || *this>=m)
        return (*this%m).InverseMod(m);

    if (m.IsEven())
    {
        if (!m || IsEven())
            return Zero();	// no inverse
        if (*this == One())
            return One();

        Integer u = m.InverseMod(*this);
        return !u ? Zero() : (m*(*this-u)+1)/(*this);
    }

    WordBlock T(m.reg_.size() * 4);
    Integer r((word)0, m.reg_.size());
    unsigned k = AlmostInverse(r.reg_.get_buffer(), T.get_buffer(),
                               reg_.get_buffer(), reg_.size(),
                               m.reg_.get_buffer(), m.reg_.size());
    DivideByPower2Mod(r.reg_.get_buffer(), r.reg_.get_buffer(), k,
                      m.reg_.get_buffer(), m.reg_.size());
    return r;
}

word Integer::InverseMod(const word mod) const
{
    word g0 = mod, g1 = *this % mod;
    word v0 = 0, v1 = 1;
    word y;

    while (g1)
    {
        if (g1 == 1)
            return v1;
        y = g0 / g1;
        g0 = g0 % g1;
        v0 += y * v1;

        if (!g0)
            break;
        if (g0 == 1)
            return mod-v0;
        y = g1 / g0;
        g1 = g1 % g0;
        v1 += y * v0;
    }
    return 0;
}

// ********* ModArith stuff

const Integer& ModularArithmetic::Half(const Integer &a) const
{
    if (a.reg_.size()==modulus.reg_.size())
    {
        TaoCrypt::DivideByPower2Mod(result.reg_.begin(), a.reg_.begin(), 1,
                                    modulus.reg_.begin(), a.reg_.size());
        return result;
    }
    else
        return result1 = (a.IsEven() ? (a >> 1) : ((a+modulus) >> 1));
}

const Integer& ModularArithmetic::Add(const Integer &a, const Integer &b) const
{
    if (a.reg_.size()==modulus.reg_.size() && 
        b.reg_.size()==modulus.reg_.size())
    {
        if (TaoCrypt::Add(result.reg_.begin(), a.reg_.begin(), b.reg_.begin(),
                          a.reg_.size())
            || Compare(result.reg_.get_buffer(), modulus.reg_.get_buffer(),
                       a.reg_.size()) >= 0)
        {
            TaoCrypt::Subtract(result.reg_.begin(), result.reg_.begin(),
                               modulus.reg_.begin(), a.reg_.size());
        }
        return result;
    }
    else
    {
        result1 = a+b;
        if (result1 >= modulus)
            result1 -= modulus;
        return result1;
    }
}

Integer& ModularArithmetic::Accumulate(Integer &a, const Integer &b) const
{
    if (a.reg_.size()==modulus.reg_.size() && 
        b.reg_.size()==modulus.reg_.size())
    {
        if (TaoCrypt::Add(a.reg_.get_buffer(), a.reg_.get_buffer(),
                          b.reg_.get_buffer(), a.reg_.size())
            || Compare(a.reg_.get_buffer(), modulus.reg_.get_buffer(),
                       a.reg_.size()) >= 0)
        {
            TaoCrypt::Subtract(a.reg_.get_buffer(), a.reg_.get_buffer(),
                               modulus.reg_.get_buffer(), a.reg_.size());
        }
    }
    else
    {
        a+=b;
        if (a>=modulus)
            a-=modulus;
    }

    return a;
}

const Integer& ModularArithmetic::Subtract(const Integer &a,
                                           const Integer &b) const
{
    if (a.reg_.size()==modulus.reg_.size() && 
        b.reg_.size()==modulus.reg_.size())
    {
        if (TaoCrypt::Subtract(result.reg_.begin(), a.reg_.begin(),
                               b.reg_.begin(), a.reg_.size()))
            TaoCrypt::Add(result.reg_.begin(), result.reg_.begin(),
                          modulus.reg_.begin(), a.reg_.size());
        return result;
    }
    else
    {
        result1 = a-b;
        if (result1.IsNegative())
            result1 += modulus;
        return result1;
    }
}

Integer& ModularArithmetic::Reduce(Integer &a, const Integer &b) const
{
    if (a.reg_.size()==modulus.reg_.size() && 
        b.reg_.size()==modulus.reg_.size())
    {
        if (TaoCrypt::Subtract(a.reg_.get_buffer(), a.reg_.get_buffer(),
                               b.reg_.get_buffer(), a.reg_.size()))
            TaoCrypt::Add(a.reg_.get_buffer(), a.reg_.get_buffer(),
                          modulus.reg_.get_buffer(), a.reg_.size());
    }
    else
    {
        a-=b;
        if (a.IsNegative())
            a+=modulus;
    }

    return a;
}

const Integer& ModularArithmetic::Inverse(const Integer &a) const
{
    if (!a)
        return a;

    CopyWords(result.reg_.begin(), modulus.reg_.begin(), modulus.reg_.size());
    if (TaoCrypt::Subtract(result.reg_.begin(), result.reg_.begin(),
                           a.reg_.begin(), a.reg_.size()))
        Decrement(result.reg_.begin()+a.reg_.size(), 1,
                  modulus.reg_.size()-a.reg_.size());

    return result;
}

Integer ModularArithmetic::CascadeExponentiate(const Integer &x,
                  const Integer &e1, const Integer &y, const Integer &e2) const
{
    if (modulus.IsOdd())
    {
        MontgomeryRepresentation dr(modulus);
        return dr.ConvertOut(dr.CascadeExponentiate(dr.ConvertIn(x), e1,
                                                    dr.ConvertIn(y), e2));
    }
    else
        return AbstractRing<Integer>::CascadeExponentiate(x, e1, y, e2);
}

void ModularArithmetic::SimultaneousExponentiate(Integer *results,
        const Integer &base, const Integer *exponents,
        unsigned int exponentsCount) const
{
    if (modulus.IsOdd())
    {
        MontgomeryRepresentation dr(modulus);
        dr.SimultaneousExponentiate(results, dr.ConvertIn(base), exponents,
                                    exponentsCount);
        for (unsigned int i=0; i<exponentsCount; i++)
            results[i] = dr.ConvertOut(results[i]);
    }
    else
        AbstractRing<Integer>::SimultaneousExponentiate(results, base,
                                                    exponents, exponentsCount);
}


// ********************************************************

#define A0      A
#define A1      (A+N2)
#define B0      B
#define B1      (B+N2)

#define T0      T
#define T1      (T+N2)
#define T2      (T+N)
#define T3      (T+N+N2)

#define R0      R
#define R1      (R+N2)
#define R2      (R+N)
#define R3      (R+N+N2)


inline void MultiplyBottom(word *R, word *T, const word *A, const word *B,
                           unsigned int N)
{
#ifdef SSE2_INTRINSICS_AVAILABLE
    if (HasSSE2())
        RecursiveMultiplyBottom<P4Optimized>(R, T, A, B, N);
    else
#endif
        RecursiveMultiplyBottom<LowLevel>(R, T, A, B, N);
}

inline void MultiplyTop(word *R, word *T, const word *L, const word *A,
                        const word *B, unsigned int N)
{
#ifdef SSE2_INTRINSICS_AVAILABLE
    if (HasSSE2())
        RecursiveMultiplyTop<P4Optimized>(R, T, L, A, B, N);
    else
#endif
        RecursiveMultiplyTop<LowLevel>(R, T, L, A, B, N);
}


// R[N] --- result = X/(2**(WORD_BITS*N)) mod M
// T[3*N] - temporary work space
// X[2*N] - number to be reduced
// M[N] --- modulus
// U[N] --- multiplicative inverse of M mod 2**(WORD_BITS*N)

void MontgomeryReduce(word *R, word *T, const word *X, const word *M,
                      const word *U, unsigned int N)
{
    MultiplyBottom(R, T, X, U, N);
    MultiplyTop(T, T+N, X, R, M, N);
    word borrow = Subtract(T, X+N, T, N);
    // defend against timing attack by doing this Add even when not needed
    word carry = Add(T+N, T, M, N);
    assert(carry || !borrow);
    CopyWords(R, T + (borrow ? N : 0), N);
}

// R[N] ----- result = A inverse mod 2**(WORD_BITS*N)
// T[3*N/2] - temporary work space
// A[N] ----- an odd number as input

void RecursiveInverseModPower2(word *R, word *T, const word *A, unsigned int N)
{
    if (N==2)
        AtomicInverseModPower2(R, A[0], A[1]);
    else
    {
        const unsigned int N2 = N/2;
        RecursiveInverseModPower2(R0, T0, A0, N2);
        T0[0] = 1;
        SetWords(T0+1, 0, N2-1);
        MultiplyTop(R1, T1, T0, R0, A0, N2);
        MultiplyBottom(T0, T1, R0, A1, N2);
        Add(T0, R1, T0, N2);
        TwosComplement(T0, N2);
        MultiplyBottom(R1, T1, R0, T0, N2);
    }
}


#undef A0
#undef A1
#undef B0
#undef B1

#undef T0
#undef T1
#undef T2
#undef T3

#undef R0
#undef R1
#undef R2
#undef R3


// modulus must be odd
MontgomeryRepresentation::MontgomeryRepresentation(const Integer &m)
    : ModularArithmetic(m),
      u((word)0, modulus.reg_.size()),
      workspace(5*modulus.reg_.size())
{
    if (!modulus.IsOdd())
        throw std::runtime_error("MontgomeryRepresentation: "
            "Montgomery representation requires an odd modulus");

    RecursiveInverseModPower2(u.reg_.get_buffer(), workspace.get_buffer(),
                              modulus.reg_.get_buffer(), modulus.reg_.size());
}

const Integer& MontgomeryRepresentation::Multiply(const Integer &a,
                                                  const Integer &b) const
{
    word *const T = workspace.begin();
    word *const R = result.reg_.begin();
    const unsigned int N = modulus.reg_.size();
    assert(a.reg_.size()<=N && b.reg_.size()<=N);

    AsymmetricMultiply(T, T+2*N, a.reg_.get_buffer(), a.reg_.size(),
                       b.reg_.get_buffer(), b.reg_.size());
    SetWords(T+a.reg_.size()+b.reg_.size(),0, 2*N-a.reg_.size()-b.reg_.size());
    MontgomeryReduce(R, T+2*N, T, modulus.reg_.get_buffer(),
                     u.reg_.get_buffer(), N);
    return result;
}

const Integer& MontgomeryRepresentation::Square(const Integer &a) const
{
    word *const T = workspace.begin();
    word *const R = result.reg_.begin();
    const unsigned int N = modulus.reg_.size();
    assert(a.reg_.size()<=N);

    TaoCrypt::Square(T, T+2*N, a.reg_.get_buffer(), a.reg_.size());
    SetWords(T+2*a.reg_.size(), 0, 2*N-2*a.reg_.size());
    MontgomeryReduce(R, T+2*N, T, modulus.reg_.get_buffer(),
                     u.reg_.get_buffer(), N);
    return result;
}

Integer MontgomeryRepresentation::ConvertOut(const Integer &a) const
{
    word *const T = workspace.begin();
    word *const R = result.reg_.begin();
    const unsigned int N = modulus.reg_.size();
    assert(a.reg_.size()<=N);

    CopyWords(T, a.reg_.get_buffer(), a.reg_.size());
    SetWords(T+a.reg_.size(), 0, 2*N-a.reg_.size());
    MontgomeryReduce(R, T+2*N, T, modulus.reg_.get_buffer(),
                     u.reg_.get_buffer(), N);
    return result;
}

const Integer& MontgomeryRepresentation::MultiplicativeInverse(
                                                        const Integer &a) const
{
//  return (EuclideanMultiplicativeInverse(a, modulus)<<
//      (2*WORD_BITS*modulus.reg_.size()))%modulus;
    word *const T = workspace.begin();
    word *const R = result.reg_.begin();
    const unsigned int N = modulus.reg_.size();
    assert(a.reg_.size()<=N);

    CopyWords(T, a.reg_.get_buffer(), a.reg_.size());
    SetWords(T+a.reg_.size(), 0, 2*N-a.reg_.size());
    MontgomeryReduce(R, T+2*N, T, modulus.reg_.get_buffer(),
                     u.reg_.get_buffer(), N);
    unsigned k = AlmostInverse(R, T, R, N, modulus.reg_.get_buffer(), N);

//  cout << "k=" << k << " N*32=" << 32*N << endl;

    if (k>N*WORD_BITS)
        DivideByPower2Mod(R, R, k-N*WORD_BITS, modulus.reg_.get_buffer(), N);
    else
        MultiplyByPower2Mod(R, R, N*WORD_BITS-k, modulus.reg_.get_buffer(), N);

    return result;
}


//  mod Root stuff
Integer ModularRoot(const Integer &a, const Integer &dp, const Integer &dq,
                    const Integer &p, const Integer &q, const Integer &u)
{
    Integer p2 = ModularExponentiation((a % p), dp, p);
    Integer q2 = ModularExponentiation((a % q), dq, q);
    return CRT(p2, p, q2, q, u);
}

Integer CRT(const Integer &xp, const Integer &p, const Integer &xq,
            const Integer &q, const Integer &u)
{
    // isn't operator overloading great?
    return p * (u * (xq-xp) % q) + xp;
}



} // namespace

