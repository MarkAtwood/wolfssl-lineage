// main.cpp

#include <string.h>
#include <stdio.h>

#include "sha.hpp"
#include "md5.hpp"
#include "hmac.hpp"
#include "arc4.hpp"
#include "des.hpp"
#include "integer.hpp"
#include "file.hpp"


using TaoCrypt::SHA;
using TaoCrypt::MD5;
using TaoCrypt::byte;
using TaoCrypt::HMAC;
using TaoCrypt::ARC4;
using TaoCrypt::DES;
using TaoCrypt::ENCRYPTION;
using TaoCrypt::DECRYPTION;


struct hashTest {
    byte*  message_;
    byte*  digest_; 
    size_t len_;

    hashTest(const char* m, const char* d) : message_((byte*)m),
             digest_((byte*)d), len_(strlen(m)) {}
};

void file_test(int, char**);
int  sha_test();
int  md5_test();
int  hmac_test();
int  arc4_test();
int  des_test();
int  int_test();
int  files_test();

int main(int argc, char** argv)
{
    if (argc > 1) 
        file_test(argc, argv);
    else {
        if (sha_test()) 
            printf("SHA  test failed!\n");
        else
            printf("SHA  test passed!\n");

        if (md5_test()) 
            printf("MD5  test failed!\n");
        else
            printf("MD5  test passed!\n");

        if (hmac_test())
            printf("HMAC test failed!\n");
        else
            printf("HMAC test passed!\n");

        if (arc4_test())
            printf("ARC4 test failed!\n");
        else
            printf("ARC4 test passed!\n");

        if (des_test())
            printf("DES  test failed!\n");
        else
            printf("DES  test passed!\n");
        if (int_test())
            printf("INT  test failed!\n");
        else
            printf("INT  test passed!\n");
        if (files_test())
            printf("FILE test failed!\n");
        else
            printf("FILE test passed!\n");
    }

    return 0;
}


int files_test()
{
    std::string name = "f:\\yassl\\test.txt";
    TaoCrypt::FileSource f(name);
    TaoCrypt::Sink sink;

    f.get(sink);

    return 0;
}


void file_test(int argc, char** argv)
{
    FILE* f;
    int   i = 0;
    MD5   md5;
    byte  buf[1000];
    byte  md5sum[MD5::DIGEST_SIZE];
    
    if( !( f = fopen( argv[1], "rb" ) )) {
        printf("Can't open %s\n", argv[1]);
        return;
    }
    while( ( i = fread(buf, 1, sizeof(buf), f )) > 0 )
        md5.Update(buf, i);
    
    md5.Final(md5sum);

    for(int j = 0; j < MD5::DIGEST_SIZE; j++ ) 
        printf( "%02x", md5sum[j] );
   
    printf("  %s\n", argv[1]);
}


int sha_test()
{
    SHA  sha;
    byte hash[SHA::DIGEST_SIZE];

    hashTest test_sha[] =
    {
        hashTest("abc", 
                 "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2"
                 "\x6C\x9C\xD0\xD8\x9D"),
        hashTest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                 "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29"
                 "\xE5\xE5\x46\x70\xF1"),
	    hashTest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaa", 
                 "\x00\x98\xBA\x82\x4B\x5C\x16\x42\x7B\xD7\xA1\x12\x2A\x5A\x44"
                 "\x2A\x25\xEC\x64\x4D"),
        hashTest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaa",
                 "\xAD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7"
                 "\x53\x99\x5E\x26\xA0")  
    };

    int times = sizeof(test_sha) / sizeof(hashTest);
    for (int i = 0; i < times; i++) {
        sha.Update(test_sha[i].message_, test_sha[i].len_);
        sha.Final(hash);

        if (memcmp(hash, test_sha[i].digest_, SHA::DIGEST_SIZE) != 0)
            return -1 - i;
    }

    return 0;
}


int md5_test()
{
    MD5  md5;
    byte hash[MD5::DIGEST_SIZE];

    hashTest test_md5[] =
    {
        hashTest("abc", 
                 "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f"
                 "\x72"),
        hashTest("message digest", 
                 "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61"
                 "\xd0"),
        hashTest("abcdefghijklmnopqrstuvwxyz",
                 "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1"
                 "\x3b"),
        hashTest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567"
                 "89",
                 "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d"
                 "\x9f"),
        hashTest("123456789012345678901234567890123456789012345678901234567890"
                 "12345678901234567890",
                 "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6"
                 "\x7a")
    };

    int times = sizeof(test_md5) / sizeof(hashTest);
    for (int i = 0; i < times; i++) {
        md5.Update(test_md5[i].message_, test_md5[i].len_);
        md5.Final(hash);

        if (memcmp(hash, test_md5[i].digest_, MD5::DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}


int hmac_test()
{
    HMAC<MD5> hmacMD5;
    byte hash[SHA::DIGEST_SIZE];  // biggest for both tests
    byte message[] = "this is my message to verify";

    hmacMD5.SetKey(message, 8);
    hmacMD5.Update(message, 28);
    hmacMD5.Final(hash);


    HMAC<SHA> hmacSHA;

    hmacSHA.SetKey(message, 8);
    hmacSHA.Update(message, 28);
    hmacSHA.Final(hash);

    return 0;
}


int arc4_test()
{
    ARC4::Encryption enc;
    ARC4::Decryption dec;

    byte key[] = "todds first key";
    byte msg[] = "this is the first message to test";
    byte cipher[24];
    byte plain [24];

    enc.SetKey(key, 8);
    dec.SetKey(key, 8);

    enc.Process(cipher, msg, 24);
    dec.Process(plain, cipher, 24);

    return 0;
}


int des_test()
{
    TaoCrypt::DES_EDE3_CBC_Encryption enc;
    TaoCrypt::DES_EDE3_CBC_Decryption dec;

    //TaoCrypt::DES_EDE2_CBC_Encryption enc;
    //TaoCrypt::DES_EDE2_CBC_Decryption dec;

    //TaoCrypt::DES_CBC_Encryption enc;
    //TaoCrypt::DES_CBC_Decryption dec;

    byte key[] = "todds first key with extra stuff";
    byte msg[] = "this is the first message to test";
    byte iv[]  = "12345678";
    byte cipher[24];
    byte plain [24];

    enc.SetKey(key, 24, iv);
    dec.SetKey(key, 24, iv);

    enc.Process(cipher, msg, 24);
    dec.Process(plain, cipher, 24);

    return 0;
}


int int_test()
{
    using TaoCrypt::Integer;
    Integer myInt;
    Integer myInt2;

    if (myInt == myInt2)
        printf("Int's equal\n");



    return 0;
}


