/* log.cpp
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

/*  Debug logging functions
 */


#include <sstream>
#include "log.hpp"


namespace yaSSL {

#ifndef NDEBUG


void Log::ShowTCP(socket_t fd, bool ended)
{
    sockaddr_in peeraddr;
    int         len = sizeof(peeraddr);
    getpeername(fd, (sockaddr*)&peeraddr, &len);

    const char* p = reinterpret_cast<const char*>(&peeraddr.sin_addr);
    std::stringstream msg;
    
    if (ended)
        msg << "yaSSL conn DONE  w/ peer ";
    else
        msg << "yaSSL conn BEGUN w/ peer ";
    for (int i = 0; i < 4; ++i) {
        msg << static_cast<unsigned short>(p[i]);
        if (i < 3) msg << ".";
    }
    msg << " port " << htons(peeraddr.sin_port);

    Trace(msg.str().c_str());
}


void Log::ShowData(uint bytes, bool sent)
{
    std::stringstream msg;

    if (sent)
        msg << "Sent     ";
    else
        msg << "Received ";
    msg << bytes << " bytes of application data";

    Trace(msg.str().c_str());
}



#endif // NDEBUG
} // namespace
