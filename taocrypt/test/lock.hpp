// lock.hpp
#ifndef TAO_LOCK_HPP
#define TAO_LOCK_HPP



namespace taoLock {


#ifdef MULTI_THREADED
    #ifdef WIN32
        #include <windows.h>

        class LockManager {
            CRITICAL_SECTION cs_;
        public:
            LockManager()  { InitializeCriticalSection(&cs_); }
            ~LockManager() { DeleteCriticalSection(&cs_);     }

            class Lock;
            friend class Lock;
    
            class Lock {
                LockManager& manager_;
            public:
                explicit Lock(LockManager& lm) : manager_(lm)
                {
                    EnterCriticalSection(&manager_.cs_); 
                }

                ~Lock()
                {
                    LeaveCriticalSection(&manager_.cs_); 
                }
            };
        };
    #else  // WIN32
        #include <pthread.h>

        class LockManager {
            pthread_mutex_t mutex_;
        public:

            LockManager()  { pthread_mutex_init(&mutex_, 0);    }
            ~LockManager() { pthread_mutex_destroy(&mutex_); }

            class Lock;
            friend class Lock;

            class Lock {
                LockManager& manager_;
            public:
                explicit Lock(LockManager& lm) : manager_(lm)
                {
                    pthread_mutex_lock(&manager_.mutex_); 
                }

                ~Lock()
                {
                    pthread_mutex_unlock(&manager_.mutex_); 
                }
            };
        };

    #endif // WIN32
#else  // MULTI_THREADED (WE'RE SINGLE)

    class LockManager {
    public:
        class Lock {
        public:
            explicit Lock(LockManager&) {}
        };
    };

#endif // MULTI_THREADED


} // namespace

#endif // TAO_LOCK_HPP
