/* test.c */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "md5.h"
#include "sha.h"
#include "arc4.h"
#include "random.h"
#include "coding.h"
#include "asn.h"
#include "des3.h"


typedef struct testVector {
    char*  input;
    char*  output; 
    size_t inLen;
    size_t outLen;
} testVector;

int  md5_test();
int  sha_test();
int  arc4_test();
int  des3_test();
int  rsa_test();
int  random_test();

int PemToDer(const char* inName, const char* outName);


void err_sys(const char* msg, int es)
{
    printf("%s", msg);
    exit(es);    
}

/* func_args from test.h, so don't have to pull in other junk */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


void ctaocrypt_test(void* args)
{
    int ret = 0;

    ((func_args*)args)->return_code = -1; /* error state */
    

    if ( (ret = md5_test()) ) 
        err_sys("MD5      test failed!\n", ret);
    else
        printf( "MD5      test passed!\n");

    if ( (ret = sha_test()) ) 
        err_sys("SHA      test failed!\n", ret);
    else
        printf( "SHA      test passed!\n");

    if ( (ret = arc4_test()) )
        err_sys("ARC4     test failed!\n", ret);
    else
        printf( "ARC4     test passed!\n");

    if ( (ret = des3_test()) )
        err_sys("DES3     test failed!\n", ret);
    else
        printf( "DES3     test passed!\n");

    if ( (ret = random_test()) )
        err_sys("RANDOM   test failed!\n", ret);
    else
        printf( "RANDOM   test passed!\n");

    if ( (ret = rsa_test()) ) 
        err_sys("RSA      test failed!\n", ret);
    else
        printf( "RSA      test passed!\n");

    ((func_args*)args)->return_code = ret;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;

        ctaocrypt_test(&args);
        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */


int md5_test()
{
    Md5  md5;
    byte hash[MD5_DIGEST_SIZE];

    testVector a, b, c, d, e;
    testVector test_md5[5];
    int times = sizeof(test_md5) / sizeof(testVector), i;

    a.input  = "abc";
    a.output = "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f"
               "\x72";
    a.inLen  = strlen(a.input);
    a.outLen = strlen(a.output);

    b.input  = "message digest";
    b.output = "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61"
               "\xd0";
    b.inLen  = strlen(b.input);
    b.outLen = strlen(b.output);

    c.input  = "abcdefghijklmnopqrstuvwxyz";
    c.output = "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1"
               "\x3b";
    c.inLen  = strlen(c.input);
    c.outLen = strlen(c.output);

    d.input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345"
               "6789";
    d.output = "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d"
               "\x9f";
    d.inLen  = strlen(d.input);
    d.outLen = strlen(d.output);

    e.input  = "1234567890123456789012345678901234567890123456789012345678"
               "9012345678901234567890";
    e.output = "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6"
               "\x7a";
    e.inLen  = strlen(e.input);
    e.outLen = strlen(e.output);

    test_md5[0] = a;
    test_md5[1] = b;
    test_md5[2] = c;
    test_md5[3] = d;
    test_md5[4] = e;

    InitMd5(&md5);

    for (i = 0; i < times; ++i) {
        Md5Update(&md5, (byte*)test_md5[i].input, test_md5[i].inLen);
        Md5Final(&md5, hash);

        if (memcmp(hash, test_md5[i].output, MD5_DIGEST_SIZE) != 0)
            return -5 - i;
    }

    return 0;
}


int sha_test()
{
    Sha  sha;
    byte hash[SHA_DIGEST_SIZE];

    testVector a, b, c, d;
    testVector test_sha[4];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2"
               "\x6C\x9C\xD0\xD8\x9D";
    a.inLen  = strlen(a.input);
    a.outLen = strlen(a.output);

    b.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    b.output = "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29"
               "\xE5\xE5\x46\x70\xF1";
    b.inLen  = strlen(b.input);
    b.outLen = strlen(b.output);

    c.input  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaa";
    c.output = "\x00\x98\xBA\x82\x4B\x5C\x16\x42\x7B\xD7\xA1\x12\x2A\x5A\x44"
               "\x2A\x25\xEC\x64\x4D";
    c.inLen  = strlen(c.input);
    c.outLen = strlen(c.output);

    d.input  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaa";
    d.output = "\xAD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7"
               "\x53\x99\x5E\x26\xA0";
    d.inLen  = strlen(d.input);
    d.outLen = strlen(d.output);

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;
    test_sha[3] = d;

    InitSha(&sha);

    for (i = 0; i < times; ++i) {
        ShaUpdate(&sha, (byte*)test_sha[i].input, test_sha[i].inLen);
        ShaFinal(&sha, hash);

        if (memcmp(hash, test_sha[i].output, SHA_DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}


int arc4_test()
{
    byte cipher[16];
    byte plain[16];

    const char* keys[] = 
    {           
        "\x01\x23\x45\x67\x89\xab\xcd\xef",
        "\x01\x23\x45\x67\x89\xab\xcd\xef",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xef\x01\x23\x45"
    };

    testVector a, b, c, d;
    testVector test_arc4[4];

    int times = sizeof(test_arc4) / sizeof(testVector), i;

    a.input  = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    a.output = "\x75\xb7\x87\x80\x99\xe0\xc5\x96";
    a.inLen  = strlen(a.input);
    a.outLen = strlen(a.output);

    b.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    b.output = "\x74\x94\xc2\xe7\x10\x4b\x08\x79";
    b.inLen  = strlen(b.input);
    b.outLen = strlen(b.output);

    c.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    c.output = "\xde\x18\x89\x41\xa3\x37\x5d\x3a";
    c.inLen  = strlen(c.input);
    c.outLen = strlen(c.output);

    d.input  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    d.output = "\xd6\xa1\x41\xa7\xec\x3c\x38\xdf\xbd\x61";
    d.inLen  = strlen(d.input);
    d.outLen = strlen(d.output);

    test_arc4[0] = a;
    test_arc4[1] = b;
    test_arc4[2] = c;
    test_arc4[3] = d;

    for (i = 0; i < times; ++i) {
        Arc4 enc;
        Arc4 dec;

        Arc4SetKey(&enc, (byte*)keys[i], strlen(keys[i]));
        Arc4SetKey(&dec, (byte*)keys[i], strlen(keys[i]));

        Arc4Process(&enc, cipher, (byte*)test_arc4[i].input,
                    test_arc4[i].outLen);
        Arc4Process(&dec, plain,  cipher, test_arc4[i].outLen);

        if (memcmp(plain, test_arc4[i].input, test_arc4[i].outLen))
            return -20 - i;

        if (memcmp(cipher, test_arc4[i].output, test_arc4[i].outLen))
            return -20 - 5 - i;
    }

    return 0;
}


int des3_test()
{
    const byte vector[] = { /* "Now is the time for all " w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    byte plain[24];
    byte cipher[24];

    Des3 enc;
    Des3 dec;

    const byte key3[] = 
    {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte iv3[] = 
    {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
        
    };

    const byte verify3[] = 
    {
        0x43,0xa0,0x29,0x7e,0xd1,0x84,0xf8,0x0e,
        0x89,0x64,0x84,0x32,0x12,0xd5,0x08,0x98,
        0x18,0x94,0x15,0x74,0x87,0x12,0x7d,0xb0
    };


    Des3_SetKey(&enc, key3, iv3, DES_ENCRYPTION);
    Des3_CbcEncrypt(&enc, cipher, vector, sizeof(vector));
    Des3_SetKey(&dec, key3, iv3, DES_DECRYPTION);
    Des3_CbcDecrypt(&dec, plain, cipher, sizeof(cipher));

    if (memcmp(plain, vector, sizeof(plain)))
        return -31;

    if (memcmp(cipher, verify3, sizeof(cipher)))
        return -32;

    return 0;
}


int random_test()
{
    RNG  rng;
    byte block[32];
    int ret = InitRng(&rng);
    if (ret != 0) return -39;

    RNG_GenerateBlock(&rng, block, sizeof(block));

    return 0;
}


int rsa_test()
{
    byte   tmp[1024], tmp2[2048];
    size_t bytes, bytes2;
    RsaKey key;
    RNG    rng;
    word32 idx = 0;
    int    ret;
    byte   in[] = "Everyone gets Friday off.";
    word32 inLen = strlen((char*)in);
    byte   out[64];
    byte   plain[64];
    DecodedCert cert;

    FILE*  file = fopen("client-key.der", "rb"), * file2;

    if (!file)
        return -40;

    bytes = fread(tmp, 1, 1024, file);
  
    InitRsaKey(&key);  
    ret = RsaPrivateKeyDecode(tmp, &idx, &key, bytes);
    if (ret != 0) return -41;

    ret = InitRng(&rng);
    if (ret != 0) return -42;

    ret = RsaPublicEncrypt(in, inLen, out, sizeof(out), &key, &rng);  

    ret = RsaPrivateDecrypt(out, 64, plain, sizeof(plain), &key);

    if (memcmp(plain, in, inLen)) return -45;

    ret = RsaSSL_Sign(in, inLen, out, sizeof(out), &key, &rng);
    memset(plain, 0, sizeof(plain));
    ret = RsaSSL_Verify(out, 64, plain, sizeof(plain), &key);

    if (memcmp(plain, in, ret)) return -46;

    file2 = fopen("client-cert.der", "rb");
    if (!file2)
        return -47;

    bytes2 = fread(tmp2, 1, 2048, file2);

    InitDecodedCert(&cert, (byte*)&tmp2);

    ret = ParseCert(&cert, bytes2, CERT_TYPE, VERIFY, 0);
    if (ret != 0) return -48;

    FreeDecodedCert(&cert);
    FreeRsaKey(&key);

    fclose(file2);
    fclose(file);

    return 0;
}
