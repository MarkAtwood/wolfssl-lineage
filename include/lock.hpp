/* lock.hpp                                
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

#ifndef yaSSL_LOCK_HPP
#define yaSSL_LOCK_HPP


namespace yaSSL {


#ifdef MULTI_THREADED
    #ifdef WIN32
        #include <windows.h>

        class Mutex {
            CRITICAL_SECTION cs_;
        public:
            Mutex()  { InitializeCriticalSection(&cs_); }
            ~Mutex() { DeleteCriticalSection(&cs_);     }

            class Lock;
            friend class Lock;
    
            class Lock {
                Mutex& mutex_;
            public:
                explicit Lock(Mutex& lm) : mutex_(lm)
                {
                    EnterCriticalSection(&mutex_.cs_); 
                }

                ~Lock()
                {
                    LeaveCriticalSection(&mutex_.cs_); 
                }
            };
        };
    #else  // WIN32
        #include <pthread.h>

        class Mutex {
            pthread_mutex_t mutex_;
        public:

            Mutex()  { pthread_mutex_init(&mutex_, 0);    }
            ~Mutex() { pthread_mutex_destroy(&mutex_); }

            class Lock;
            friend class Lock;

            class Lock {
                Mutex& mutex_;
            public:
                explicit Lock(Mutex& lm) : mutex_(lm)
                {
                    pthread_mutex_lock(&mutex_.mutex_); 
                }

                ~Lock()
                {
                    pthread_mutex_unlock(&mutex_.mutex_); 
                }
            };
        };

    #endif // WIN32
#else  // MULTI_THREADED (WE'RE SINGLE)

    class Mutex {
    public:
        class Lock {
        public:
            explicit Lock(Mutex&) {}
        };
    };

#endif // MULTI_THREADED



} // namespace
#endif // yaSSL_LOCK_HPP
