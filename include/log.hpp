/* log.hpp                                
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


/* yaSSL log interface
 *
 */

#ifndef yaSSL_log_hpp__
#define yaSSL_log_hpp__

#include <fstream>
#include <ctime>


namespace yaSSL {


#ifdef NDEBUG

class Log {
public:
    Log() {}
    explicit Log(const char*) {}
    void Trace(const char*) {}
};


#else // NDEBUG


class Log {
    std::ofstream log_;
public:
    explicit Log(const char* str = "yaSSL.log") : log_(str, std::ios::app)
    {
        Trace("\n********** Logger Attached **********");
        time_t clicks = time(0);
        Trace(ctime(&clicks));
    }

    void Trace(const char* msg)
    {   
        log_ << msg << '\n';
    }
};


#endif // NDEBUG


} // naemspace

#endif // yaSSL_log_hpp__
