/* file.hpp                                
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


#ifndef TAO_CRYPT_FILE_HPP
#define TAO_CRYPT_FILE_HPP

#include "misc.hpp"
#include "block.hpp"
#include <fstream>

namespace TaoCrypt {



class Sink {
    ByteBlock buffer_;
    uint32    current_;
public:
    explicit Sink(uint32 sz = 0) : buffer_(sz), current_(0) {}
    Sink(const byte* b, uint32 sz) : buffer_(b, sz), current_(0) {}

    uint32 size() const { return buffer_.size(); }
    void   set_size(uint32 sz) { buffer_.New(sz); }
    void   grow(uint32 sz)     { buffer_.CleanGrow(sz); }
    void   put(const byte*, uint32);
    byte*  get_buffer() const { return buffer_.get_buffer(); }
    const byte*  get_current() const { return &buffer_[current_]; }

    byte operator[] (uint32 i) { current_ = i; return next(); }
    byte next() { return buffer_[current_++]; }
    byte prev() { return buffer_[--current_]; }

    void eat(uint32 i) { current_ += i; }
    void reset(ByteBlock&);
private:
    // do i need these ???
    Sink(const Sink& that) : buffer_(that.buffer_), current_(that.current_) {}
    Sink& operator=(const Sink& that)
    {
        Sink tmp(that);
        swap(tmp);
        return *this;
    }

    void swap(Sink& other) 
    {
        buffer_.swap(other.buffer_);
        std::swap(current_, other.current_);
    }

};


class FileSource {
    std::ifstream file_;
public:
    explicit FileSource(const std::string& fname) : file_(fname.c_str()) {}
    FileSource(const std::string& fname, Sink& sink) : file_(fname.c_str())
            { get(sink); }
   
    uint32   size(bool use_current = false);
private:
    uint32   get(Sink&);
    uint32   size_left();                     

    FileSource(const FileSource&);            // hide
    FileSource& operator=(const FileSource&); // hide
};



} // namespace

#endif // TAO_CRYPT_FILE_HPP
