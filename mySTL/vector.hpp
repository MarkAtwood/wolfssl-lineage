/* mySTL vector.hpp                                
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

/*
 *
 * Copyright (c) 1994
 * Hewlett-Packard Company
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation.  Hewlett-Packard Company makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 *
 * Copyright (c) 1996
 * Silicon Graphics Computer Systems, Inc.
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation.  Silicon Graphics makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 */


/* mySTL memory implements vector based on SGI STL
 *
 */

#ifndef mySTL_VECTOR_HPP
#define mySTL_VECTOR_HPP


#include "memory.hpp"     // auto_ptr
#include "helpers.hpp"    // construct, destory, fill, etc.
#include "algorithm.hpp"  // max
#include <new>            // ::operator new and delete, placement too


namespace mySTL {


template <typename T>
struct vector_base {
    T* start_;
    T* finish_;
    T* end_of_storage_;

    vector_base() : start_(0), finish_(0), end_of_storage_(0) {}
    vector_base(size_t n)
    {
        start_ = static_cast<T*>(::operator new(n * sizeof(T)));
        if (!start_) abort();
        finish_ = start_;
        end_of_storage_ = start_ + n;
    }

    ~vector_base() { ::operator delete(start_); }
};



template <typename T>
class vector {
public:
    vector() {}
    explicit vector(size_t n) : vec_(n) { uninit_fill_n(vec_.start_, n, T()); }

    ~vector() { destroy(vec_.start_, vec_.finish_); }

    vector(const vector& other) : vec_(other.size())
    {
        vec_.finish_ = uninit_copy(other.vec_.start_, other.vec_.finish_,
                                   vec_.start_);   
    }

    size_t capacity() const { return vec_.end_of_storage_ - vec_.start_; }

    size_t size() const { return vec_.finish_ - vec_.start_; }

    T&       operator[](size_t idx)       { return *(vec_.start_ + idx); }
    const T& operator[](size_t idx) const { return *(vec_.start_ + idx); }

    const T* begin() const { return vec_.start_; }
    const T* end()   const { return vec_.finish_; }

    void push_back(const T& v)
    {
        if (vec_.finish_ != vec_.end_of_storage_) {
            construct(vec_.finish_, v);
            ++vec_.finish_;
        }
        else
            insert_aux(vec_.finish_, v);
    }

    void resize(size_t n, const T& v)
    {
        if (n < size())
            erase(vec_.start_ + n, vec_.finish_);
        else
            insert(vec_.finish_, n - size(), v);
    }

    void insert(T* pos, size_t n, const T& v)
    {
        fill_insert(pos, n, v);
    }

    T* erase(T* first, T* last)
    {
        T* tmp = copy(last, vec_.finish_, first);
        destroy(tmp, vec_.finish_);
        vec_.finish_ -= last - first;

        return first;
    }

    void reserve(size_t n)
    {
        if (capacity() < n) {
            const size_t oldSz = size();
            auto_ptr<T> tmp(alloc_copy(n, vec_.start_, vec_.finish_));

            destroy(vec_.start_, vec_.finish_);
            ::operator delete(vec_.start_);

            vec_.start_ = tmp.release();
            vec_.finish_ = vec_.start_ + oldSz;
            vec_.end_of_storage_ = vec_.start_ + n;
        }
    }
private:
    vector_base<T> vec_;

    vector& operator=(const vector&);   // hide assign

    T* alloc_copy(size_t n, T* first, T* last)
    {
        auto_ptr<T> tmp(static_cast<T*>(::operator new(n * sizeof(T))));
        if (!tmp.get()) abort();
        uninit_copy(first, last, tmp.get());
        return tmp.release();
    }

    void insert_aux(T* pos, const T& v)
    {
        if (vec_.finish_ != vec_.end_of_storage_) {
            construct(vec_.finish_, *(vec_.finish_ - 1));
            ++vec_.finish_;

            T x = v;
            copy_backward(pos, vec_.finish_ - 2, vec_.finish_ - 1);
            *pos = x;
        }
        else {
            const size_t oldSz = size();
            const size_t len   = oldSz ? 2 * oldSz : 1;
            
            auto_ptr<T> start(static_cast<T*>(::operator new(len *
                                                             sizeof(T))));
            if (!start.get()) abort();
            T* finish = uninit_copy(vec_.start_, pos, start.get());

            construct(finish, v);
            ++finish;
            finish = uninit_copy(pos, vec_.finish_, finish);

            destroy(vec_.start_, vec_.finish_);
            ::operator delete(vec_.start_);

            vec_.start_  = start.release();
            vec_.finish_ = finish;
            vec_.end_of_storage_ = vec_.start_ + len;
        }
    }

    void fill_insert(T* pos, size_t n, const T& v)
    {
        if (n == 0) return;

        if ( size_t(vec_.end_of_storage_ - vec_.finish_) >= n) {
            const size_t elemsAfter = vec_.finish_ - pos;
            T x = v;
            T* oldFinish = vec_.finish_;

            if (elemsAfter > n) {
                uninit_copy(vec_.finish_ - n, vec_.finish_, vec_.finish_);
                vec_.finish_ += n;

                copy_backward(pos, oldFinish - n, oldFinish);
                fill(pos, pos + n, x);
            }
            else {
                uninit_fill_n(vec_.finish_, n - elemsAfter, x);
                vec_.finish_ += n - elemsAfter;

                uninit_copy(pos, oldFinish, vec_.finish_);
                vec_.finish_ += elemsAfter;

                fill(pos, oldFinish, x);
            }
        }
        else {
            const size_t oldSz = size();
            const size_t len   = oldSz + max(oldSz, n);
            
            auto_ptr<T> start(static_cast<T*>(::operator new(len *
                                                             sizeof(T))));
            if (!start.get()) abort();
            T* finish = uninit_copy(vec_.start_, pos, start.get());
            
            finish = uninit_fill_n(finish, n, v);
            finish = uninit_copy(pos, vec_.finish_, finish);

            destroy(vec_.start_, vec_.finish_);
            ::operator delete(vec_.start_);

            vec_.start_  = start.release();
            vec_.finish_ = finish;
            vec_.end_of_storage_ = vec_.start_ + len;
        }
    }
};



} // namespace mySTL

#endif // mySTL_VECTOR_HPP
