/* yassl_error.hpp                                
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


/* yaSSL error header defines error codes and an exception class
 */

#ifndef yaSSL_ERROR_HPP
#define yaSSL_ERROR_HPP

#include <stdexcept>


namespace yaSSL {


enum ErrorNumber {
    no_error            = 0,

    // 10 - 47 from AlertDescription, 0 also close_notify

    range_error         = 101,
    realloc_error       = 102,
    factory_error       = 103,
    unknown_cipher      = 104,
    prefix_error        = 105,
    record_layer        = 106,
    handshake_layer     = 107,
    out_of_order        = 108,
    bad_input           = 109,
    match_error         = 110,
    no_key_file         = 111,
    verify_error        = 112,
    send_error          = 113,
    receive_error       = 114,
};


enum Library { yaSSL_Lib = 0, CryptoLib, SocketLib };

// Base class for all yaSSL exceptions
class Error : public std::runtime_error {
    ErrorNumber error_;
    Library     lib_;
public:
    explicit Error(const char* s = "", ErrorNumber e = no_error,
                   Library l = yaSSL_Lib) 
        : std::runtime_error(s), error_(e), lib_(l) {}

    ErrorNumber get_number() const { return error_; }
};


} // naemspace

#endif // yaSSL_ERROR_HPP
