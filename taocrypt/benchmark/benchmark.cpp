// benchmark.cpp
// TaoCrypt benchmark

#include <string.h>
#include <stdio.h>

#include "runtime.hpp"
#include "des.hpp"
#include "aes.hpp"
#include "twofish.hpp"
#include "blowfish.hpp"


using namespace TaoCrypt;

void err_sys(const char* msg, int es)
{
    printf("%s", msg);
    exit(es);    
}

void bench_des();
void bench_aes();
void bench_blowfish();
void bench_twofish();

double current_time();

int main(int argc, char** argv)
{
    bench_des();
    bench_aes();
    bench_blowfish();
    bench_twofish();

    return 0;
}

const int megs = 5;  // how much to test

const byte key[] = 
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
};

const byte iv[] = 
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
    
};


byte plain [1024*1024];
byte cipher[1024*1024];


void bench_des()
{
    DES_EDE3_CBC_Encryption enc;
    enc.SetKey(key, 16, iv);

    double start = current_time();

    for(int i = 0; i < megs; i++)
        enc.Process(plain, cipher, sizeof(plain));

    double total = current_time() - start;

    double persec = 1 / total * megs;

    printf("3DES     %d megs took %f seconds, %5.2f MB/s\n", megs, total,
                                                             persec);
}


void bench_aes()
{
    AES_CBC_Encryption enc;
    enc.SetKey(key, 16, iv);

    double start = current_time();
 
    for(int i = 0; i < megs; i++)
        enc.Process(plain, cipher, sizeof(plain));

    double total = current_time() - start;

    double persec = 1 / total * megs;

    printf("AES      %d megs took %f seconds, %5.2f MB/s\n", megs, total,
                                                             persec);
}


void bench_twofish()
{
    Twofish_CBC_Encryption enc;
    enc.SetKey(key, 16, iv);

    double start = current_time();

    for(int i = 0; i < megs; i++)
        enc.Process(plain, cipher, sizeof(plain));

    double total = current_time() - start;

    double persec = 1 / total * megs;

    printf("Twofish  %d megs took %f seconds, %5.2f MB/s\n", megs, total,
                                                            persec);

}


void bench_blowfish()
{
    Blowfish_CBC_Encryption enc;
    enc.SetKey(key, 16, iv);

    double start = current_time();

    for(int i = 0; i < megs; i++)
        enc.Process(plain, cipher, sizeof(plain));

    double total = current_time() - start;

    double persec = 1 / total * megs;

    printf("Blowfish %d megs took %f seconds, %5.2f MB/s\n", megs, total,
                                                             persec);
}


#ifdef _WIN32

    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    double current_time()
    {
        static bool          init(false);
        static LARGE_INTEGER freq;
    
        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = true;
        }

        LARGE_INTEGER count;
        QueryPerformanceCounter(&count);

        return static_cast<double>(count.QuadPart) / freq.QuadPart;
    }

#else

    #include <sys/time.h>

    double current_time()
    {
        struct timeval tv;
        gettimeofday(&tv, 0);

        return static_cast<double>(tv.tv_sec) 
             + static_cast<double>(tv.tv_usec) / 1000000;
    }

#endif // _WIN32
