/* buffer.hpp                                
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


/* yaSSL buffer header defines input and output buffers to simulate streaming
 * with SSL types and sockets
 */

#ifndef yaSSL_BUFFER_HPP
#define yaSSL_BUFFER_HPP

#include <cassert>              // assert
#include <functional>           // unary_function
#include "yassl_error.hpp"      // Error


namespace yaSSL {

typedef unsigned char byte;
typedef unsigned int  uint;
const uint AUTO = 0xFEEDBEEF;


// Checking Policy should implement a check function that tests whether the
// index is within the size limit of the array
struct Check {
    void check(uint i, uint limit) 
        { if (i >= limit) throw Error("Buffer Out of Range", range_error); }
};

struct NoCheck {
    void check(uint, uint) {}
};

/* in_buffer operates like a smart c style array with a checking option, 
 * meant to be read from through [] with AUTO index or read().
 * Should only write to at/near construction with assign() or raw (e.g., recv)
 * followed by add_size with the number of elements added by raw write.
 *
 * Not using vector because need checked []access, offset, and the ability to
 * write to the buffer bulk wise and have the correct size
 */
template<typename T,
         class CheckingPolicy = Check
        >
class in_buffer : public CheckingPolicy {
    uint   size_;                // number of elements in buffer
    uint   current_;             // current offset position in buffer
    T*     buffer_;              // storage for buffer
    T*     end_;                 // end of storage marker
public:
    in_buffer() : size_(0), current_(0), buffer_(0), end_(0) {}

    explicit in_buffer(uint s) : size_(0), current_(0),
                          buffer_(new T[s]), end_(buffer_ + s) {}
    // with assign
    in_buffer(uint s, const T* t, uint len) : size_(0), current_(0),
              buffer_(new T[s]), end_(buffer_ + s) { assign(t, len); }
    
    ~in_buffer() { delete [] buffer_; }

    // users can pass defualt zero length buffer and then allocate
    void allocate(uint s) { if (buffer_) 
                                  throw Error("Buffer ReAlloc", realloc_error);
                            buffer_ = new T[s]; end_ = buffer_ + s; }

    // for passing to raw writing functions at beginning, then use add_size
    T* get_buffer() const { return buffer_; }

    // after a raw write user can set new size
    // if you know the size before the write use assign()
    void add_size(uint i) { check(size_ + i-1, get_capacity()); size_ += i; }

    uint get_capacity()  const { return end_ - buffer_; }

    uint get_current()   const { return current_; }

    uint get_size()      const { return size_; }

    uint get_remaining() const { return size_ - current_; }

    void set_current(uint i) { check(i - 1, size_); current_ = i; }

    // read only access through [], advance current
    // user passes in AUTO index for ease of use
    const T& operator[](uint i) 
    {
        assert (i == AUTO);
        check(current_, size_);
        return buffer_[current_++];
    }
    // end of input test
    bool eof() { return current_ >= size_; }

    // write function, should use at/near construction
    void assign(const T* t, uint s)
    {
        check(current_, get_capacity());
        add_size(s);
        memcpy(&buffer_[current_], t, s);
    }

    // use read to query input, adjusts current
    void read(T* dst, uint length)
    {
        check(current_ + length - 1, size_);
        memcpy(dst, &buffer_[current_], length);
        current_ += length;
    }
private:
    in_buffer(const in_buffer&);              // hide copy
    in_buffer& operator=(const in_buffer&);   // and assign
};


/* out_buffer operates like a smart c style array with a checking option.
 * Meant to be written to through [] with AUTO index or write().
 * Size (current) counter increases when written to. Can be constructed with 
 * zero length buffer but be sure to allocate before first use. 
 * Don't use add write for a couple bytes, use [] instead, way less overhead.
 * 
 * Not using vector because need checked []access and the ability to
 * write to the buffer bulk wise and retain correct size
 */
template<typename T,
         class CheckingPolicy = Check
        >
class out_buffer : public CheckingPolicy {
    uint   current_;                // current offset and elements in buffer
    T*     buffer_;                 // storage for buffer
    T*     end_;                    // end of storage marker
public:
    // default
    out_buffer() : current_(0), buffer_(0), end_(0) {}

    // with allocate
    explicit out_buffer(uint s) : current_(0), buffer_(new T[s]), 
                           end_(buffer_ + s) {}
    // with assign
    out_buffer(uint s, const T* t, uint len) : current_(0),
                  buffer_(new T[s]), end_(buffer_+ s) { add(t, len); }

    ~out_buffer() { delete [] buffer_; }

    uint get_size() const { return current_; }

    uint get_capacity() const { return end_ - buffer_; }

    void   set_current(uint c) { check(c, get_capacity()); current_ = c; }

    // users can pass defualt zero length buffer and then allocate
    void allocate(uint s) { if (buffer_) 
                                  throw Error("Buffer ReAlloc", realloc_error);
                              buffer_ = new T[s]; end_ = buffer_ + s; }

    // for passing to reading functions when finished
    const T* get_buffer() const { return buffer_; }

    // allow write access through [], update current
    // user passes in AUTO as index for ease of use
    T& operator[](uint i) 
    {
        assert(i == AUTO);
        check(current_, get_capacity());
        return buffer_[current_++];
    }

    // end of output test
    bool eof() { return current_ >= get_capacity(); }

    void write(const T* t, uint s)
    {
        check(current_ + s - 1, get_capacity()); 
        memcpy(&buffer_[current_], t, s);
        current_ += s;
    }
private:
    out_buffer(const out_buffer&);              // hide copy
    out_buffer& operator=(const out_buffer&);   // and assign
};



// Checked input_bufer
typedef in_buffer<byte, Check> input_buffer;

// Checked output_buffer
typedef out_buffer<byte, Check> output_buffer;



// turn delete an incomplete type into comipler error instead of warning
template <typename T>
inline void checked_delete(T* p)
{
    typedef char complete_type[sizeof(T) ? 1 : -1];
    sizeof(complete_type);
    delete p;
}


// checked delete functor increases effeciency, no indirection on function call
// sets pointer to zero so safe for std conatiners
struct del_ptr_zero
{
    template <typename T>
    void operator()(T*& p) const
    {
        T* tmp = 0;
        std::swap(tmp, p);
        checked_delete(tmp); 
    }
};



} // naemspace

#endif // yaSSL_BUUFER_HPP
