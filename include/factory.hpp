/* factory.hpp                                
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

/*  The factory header defines an Object Factory, used by SSL message and
 *  handshake types.
 *
 *  See Desgin Pattern in GoF and Alexandrescu's chapter in Modern C++ Design,
 *  page 208
 */



#ifndef yaSSL_factory_hpp__
#define yaSSL_factory_hpp__

#include <map>
#include "yassl_error.hpp"


namespace yaSSL {


// Factory uses its callback map to create objects by id,
// returning an abstract base pointer
template<class    AbstractProduct, 
         typename IdentifierType = int, 
         typename ProductCreator = AbstractProduct* (*)()
        >
class Factory {                                             
    typedef std::map<IdentifierType, ProductCreator> CallBackMap;
    CallBackMap callbacks_;
public:
    // pass function pointer to register all callbacks upon creation
    explicit Factory(void (*init)(Factory<AbstractProduct, IdentifierType,
                                  ProductCreator>&)) { init(*this); }
    // return true if registration succeeds
    bool Register(const IdentifierType& id, ProductCreator pc)
        { return callbacks_.insert(CallBackMap::value_type(id, pc)).second; }

    // return true if message id was previously registered
    bool UnRegister(const IdentifierType& id) 
        { return callbacks_.erase(id) == 1; }

    // THE Creator, returns a new object of the proper type or throws
    AbstractProduct* CreateObject(const IdentifierType& id) const
    {
        typename CallBackMap::const_iterator i = callbacks_.find(id);
        if (i == callbacks_.end()) 
            throw Error("UnKnown Facotry ClassID", factory_error);
        return (i->second)();
    }
private:
    Factory(const Factory&);            // hide copy
    Factory& operator=(const Factory&); // and assign
};


} // naemspace

#endif // yaSSL_factory_hpp__
