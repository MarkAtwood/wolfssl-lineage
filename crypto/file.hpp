// file.hpp

#ifndef TAO_CRYPT_FILE_HPP__
#define TAO_CRYPT_FILE_HPP__

#include "misc.hpp"
#include "block.hpp"
#include <fstream>

namespace TaoCrypt {



class Sink {
    ByteBlock buffer_;
    size_t    current_;
public:
    Sink(size_t sz = 0) : buffer_(sz), current_(0) {}

    size_t size() const { return buffer_.size(); }
    void   set_size(size_t sz) { buffer_.New(sz); }
    void   grow(size_t sz)     { buffer_.CleanGrow(sz); }
    void   put(const byte*, size_t);
    byte*  get_buffer() const { return buffer_.get_buffer(); }
    //size_t put(const Source&);

    byte operator[] (size_t i) { current_ = i; return next(); }
    byte next() { return buffer_[current_++]; }
    byte prev() { return buffer_[--current_]; }


private:
    Sink(const Sink&);            // hide
    Sink& operator=(const Sink&); // hide
};


class FileSource {
    std::ifstream file_;
public:
    explicit FileSource(const std::string& fname) : file_(fname.c_str()) {}
    FileSource(const std::string& fname, Sink& sink) : file_(fname.c_str())
            { get(sink); }
   
    size_t   size(bool use_current = false);
private:
    size_t   get(Sink&);
    size_t   size_left();                     

    FileSource(const FileSource&);            // hide
    FileSource& operator=(const FileSource&); // hide
};



} // namespace

#endif // TAO_CRYPT_FILE_HPP__
