// file.hpp

#ifndef TAO_CRYPT_FILE_HPP__
#define TAO_CRYPT_FILE_HPP__

#include "misc.hpp"
#include <fstream>

namespace TaoCrypt {

byte* reallocate(byte* p, size_t oldSize, size_t newSize, bool preserve);

class ByteBlock {
public:
    explicit ByteBlock(size_t s = 0) : sz_(s), buffer_(new byte[sz_]) {}

    ByteBlock(const byte* buff, size_t s) : sz_(s), buffer_(new byte[sz_])
        { memcpy(buffer_, buff, sz_); }

    ByteBlock(const ByteBlock& other) : sz_(other.sz_), buffer_(new byte[sz_])
        { memcpy(buffer_, other.buffer_, sz_); }

    ByteBlock& operator=(const ByteBlock& that) 
    {
        ByteBlock tmp(that);
        swap(tmp);
        return *this;
    }

    byte& operator[] (size_t i) { assert(i < sz_); return buffer_[i]; }
    const byte& operator[] (size_t i) const 
        { assert(i < sz_); return buffer_[i]; }

    byte* operator+ (size_t i) { return buffer_ + i; }
    const byte* operator+ (size_t i) const { return buffer_ + i; }

    size_t size() const { return sz_; }

    byte* get_buffer() const { return buffer_; }
    byte* begin()      const { return get_buffer(); }

	void CleanGrow(size_t newSize)
	{
		if (newSize > sz_){
			buffer_ = reallocate(buffer_, sz_, newSize, true);
			memset(buffer_ + sz_, 0, newSize - sz_);
			sz_ = newSize;
		}
	}

	void CleanNew(unsigned int newSize)
    {
	    New(newSize);
		memset(buffer_, 0, sz_);
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

    void swap(ByteBlock& other) 
    {
        std::swap(sz_, other.sz_);
        std::swap(buffer_, other.buffer_);
    }

    ~ByteBlock() { delete[] buffer_; }
private:
    size_t sz_;     
    byte*  buffer_;
};


class Sink {
    ByteBlock buffer_;
public:
    Sink(size_t sz = 0) : buffer_(sz) {}

    size_t size() const { return buffer_.size(); }
    void   set_size(size_t sz) { buffer_.New(sz); }
    void   grow(size_t sz)     { buffer_.CleanGrow(sz); }
    void   put(const byte*, size_t);
    byte*  get_buffer() const { return buffer_.get_buffer(); }
    //size_t put(const Source&);

private:
    Sink(const Sink&);            // hide
    Sink& operator=(const Sink&); // hide
};


class FileSource {
    std::ifstream file_;
public:
    explicit FileSource(const std::string& fname) : file_(fname.c_str()) {}
   
    size_t   size(bool use_current = false);
    size_t   get(Sink&);
  
private:
    size_t   size_left();                     

    FileSource(const FileSource&);            // hide
    FileSource& operator=(const FileSource&); // hide
};



} // namespace

#endif // TAO_CRYPT_FILE_HPP__
