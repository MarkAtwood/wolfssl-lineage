/* file.cpp                                
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



#include "file.hpp"

namespace TaoCrypt {



size_t FileSource::size(bool use_current)
{
    using std::streampos;

    streampos current = file_.tellg();
    streampos begin;

    if (use_current)
        begin = current;
    else
        begin = file_.seekg(0, std::ios::beg).tellg();

    streampos end = file_.seekg(0, std::ios::end).tellg();
	file_.seekg(current);

	return end - begin;
}


size_t FileSource::size_left()
{
    return size(true);
}


size_t FileSource::get(Sink& sink)
{
    size_t sz(size());
    if (sink.size() < sz)
        sink.set_size(sz);

    file_.read(reinterpret_cast<char*>(sink.get_buffer()), sz);

    return sz;
}



void Sink::reset(ByteBlock& otherBlock)
{
    buffer_.swap(otherBlock);   
    current_ = 0;
}


}  // namespace
