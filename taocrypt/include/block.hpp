/* block.hpp                                
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


#ifndef TAO_CRYPT_BLOCK_HPP__
#define TAO_CRYPT_BLOCK_HPP__

#include <string.h>
#include "misc.hpp"


namespace TaoCrypt {

template<typename T>
T* reallocate(T* p, size_t oldSize, size_t newSize, bool preserve)
{
    if (oldSize == newSize)
        return p;

    if (preserve) {
        T* newPointer = new T[newSize];
        memcpy(newPointer, p, sizeof(T) * min(oldSize, newSize));
        delete[] p;
        return newPointer;
    }
    else {
        delete[] p;
        return new T[newSize];
    }
}


template<typename T>
class Block {
public:
    explicit Block(size_t s = 0) : sz_(s), buffer_(new T[sz_]) 
                    { CleanNew(sz_); }

    Block(const T* buff, size_t s) : sz_(s), buffer_(new T[sz_])
        { memcpy(buffer_, buff, sz_ * sizeof(T)); }

    Block(const Block& other) : sz_(other.sz_), buffer_(new T[sz_])
        { memcpy(buffer_, other.buffer_, sz_ * sizeof(T)); }

    Block& operator=(const Block& that) {
        Block tmp(that);
        swap(tmp);
        return *this;
    }

    T& operator[] (size_t i) { assert(i < sz_); return buffer_[i]; }
    const T& operator[] (size_t i) const 
        { assert(i < sz_); return buffer_[i]; }

    T* operator+ (size_t i) { return buffer_ + i; }
    const T* operator+ (size_t i) const { return buffer_ + i; }

    size_t size() const { return sz_; }

    T* get_buffer() const { return buffer_; }
    T* begin()      const { return get_buffer(); }

    void CleanGrow(size_t newSize)
    {
        if (newSize > sz_) {
            buffer_ = reallocate(buffer_, sz_, newSize, true);
            memset(buffer_ + sz_, 0, (newSize - sz_) * sizeof(T));
            sz_ = newSize;
        }
    }

    void CleanNew(unsigned int newSize)
    {
        New(newSize);
        memset(buffer_, 0, sz_ * sizeof(T));
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

    void swap(Block& other) {
        std::swap(sz_, other.sz_);
        std::swap(buffer_, other.buffer_);
    }

    ~Block() { delete[] buffer_; }
private:
    size_t sz_;     // size in Ts
    T*     buffer_;
};


typedef Block<byte> ByteBlock;
typedef Block<word> WordBlock;


} // namespace

#endif // TAO_CRYPT_BLOCK_HPP__
