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

#ifndef yaSSL_LOG_HPP
#define yaSSL_LOG_HPP

#include <fstream>
#include <ctime>
#include "socket_wrapper.hpp"


namespace yaSSL {

typedef unsigned int uint;

#ifdef NDEBUG

class Log {
public:
    Log() {}
    explicit Log(const char*) {}
    void Trace(const char*) {}
    void ShowTCP(socket_t, bool ended = false) {}
    void ShowData(uint, bool sent = false) {}
};


#else // NDEBUG


class Log {
    std::ofstream log_;
public:
    explicit Log(const char* str = "yaSSL.log") : log_(str)
    {
        Trace("********** Logger Attached **********");
    }

    ~Log()
    {
        Trace("********** Logger Detached **********");
    }

    void Trace(const char* msg)
    {   
        time_t clicks = time(0);
        char   timeStr[32];

        // get rid of newline
        strncpy(timeStr, ctime(&clicks), sizeof(timeStr));
        unsigned int len = strlen(timeStr);
        timeStr[len - 1] = 0;

        log_ << timeStr << ": " << msg << '\n';
    }

    void ShowTCP(socket_t, bool ended = false);
    void ShowData(uint, bool sent = false);
};


#endif // NDEBUG


} // naemspace

#endif // yaSSL_LOG_HPP
