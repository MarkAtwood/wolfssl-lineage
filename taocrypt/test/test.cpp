// test.cpp
// test taocrypt functionality

#include <string.h>
#include <stdio.h>

#include "sha.hpp"
#include "md5.hpp"
#include "md2.hpp"
#include "hmac.hpp"
#include "arc4.hpp"
#include "des.hpp"
#include "rsa.hpp"
#include "dsa.hpp"
#include "aes.hpp"
#include "asn.hpp"
#include "dh.hpp"
#include "coding.hpp"
#include "random.hpp"


using TaoCrypt::byte;
using TaoCrypt::word32;
using TaoCrypt::SHA;
using TaoCrypt::MD5;
using TaoCrypt::MD2;
using TaoCrypt::HMAC;
using TaoCrypt::ARC4;
using TaoCrypt::DES_EDE3_CBC_Encryption;
using TaoCrypt::DES_EDE3_CBC_Decryption;
using TaoCrypt::DES_CBC_Encryption;
using TaoCrypt::DES_CBC_Decryption;
using TaoCrypt::DES_ECB_Encryption;
using TaoCrypt::DES_ECB_Decryption;
using TaoCrypt::AES_CBC_Encryption;
using TaoCrypt::AES_CBC_Decryption;
using TaoCrypt::AES_ECB_Encryption;
using TaoCrypt::AES_ECB_Decryption;
using TaoCrypt::RSA_PrivateKey;
using TaoCrypt::RSA_PublicKey;
using TaoCrypt::DSA_PrivateKey;
using TaoCrypt::DSA_PublicKey;
using TaoCrypt::DSA_Signer;
using TaoCrypt::DSA_Verifier;
using TaoCrypt::RSAES_Encryptor;
using TaoCrypt::RSAES_Decryptor;
using TaoCrypt::Source;
using TaoCrypt::FileSource;
using TaoCrypt::FileSource;
using TaoCrypt::HexDecoder;
using TaoCrypt::HexEncoder;
using TaoCrypt::Base64Decoder;
using TaoCrypt::Base64Encoder;
using TaoCrypt::CertDecoder;
using TaoCrypt::DH;
using TaoCrypt::EncodeDSA_Signature;
using TaoCrypt::DecodeDSA_Signature;



struct testVector {
    byte*  input_;
    byte*  output_; 
    size_t inLen_;
    size_t outLen_;

    testVector(const char* in, const char* out) : input_((byte*)in),
               output_((byte*)out), inLen_(strlen(in)), outLen_(strlen(out)) {}
};

void file_test(int, char**);
int  sha_test();
int  md5_test();
int  md2_test();
int  hmac_test();
int  arc4_test();
int  des_test();
int  aes_test();
int  rsa_test();
int  dsa_test();
int  dh_test();

TaoCrypt::RandomNumberGenerator rng;


void err_sys(const char* msg, int es)
{
    printf("%s", msg);
    exit(es);    
}

// func_args from test.hpp, so don't have to pull in other junk
struct func_args {
    int    argc;
    char** argv;
    int    return_code;
};


void taocrypt_test(void* args)
{
    ((func_args*)args)->return_code = -1; // error state
    

    int ret = 0;
    if ( (ret = sha_test()) ) 
        err_sys("SHA  test failed!\n", ret);
    else
        printf( "SHA  test passed!\n");

    if ( (ret = md5_test()) ) 
        err_sys("MD5  test failed!\n", ret);
    else
        printf( "MD5  test passed!\n");

    if ( (ret = md2_test()) ) 
        err_sys("MD2  test failed!\n", ret);
    else
        printf( "MD2  test passed!\n");

    if ( ( ret = hmac_test()) )
        err_sys("HMAC test failed!\n", ret);
    else
        printf( "HMAC test passed!\n");

    if ( (ret = arc4_test()) )
        err_sys("ARC4 test failed!\n", ret);
    else
        printf( "ARC4 test passed!\n");

    if ( (ret = des_test()) )
        err_sys("DES  test failed!\n", ret);
    else
        printf( "DES  test passed!\n");

    if ( (ret = aes_test()) )
        err_sys("AES  test failed!\n", ret);
    else
        printf( "AES  test passed!\n");

    if ( (ret = rsa_test()) )
        err_sys("RSA  test failed!\n", ret);
    else
        printf( "RSA  test passed!\n");

    if ( (ret = dh_test()) )
        err_sys("DH   test failed!\n", ret);
    else
        printf( "DH   test passed!\n");

    if ( (ret = dsa_test()) )
        err_sys("DSA  test failed!\n", ret);
    else
        printf( "DSA  test passed!\n");

    ((func_args*)args)->return_code = ret;
}


// so overall tests can pull in test function 
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;

        taocrypt_test(&args);
        return args.return_code;
    }

#endif // NO_MAIN_DRIVER


void file_test(char* file, byte* check)
{
    FILE* f;
    int   i(0);
    MD5   md5;
    byte  buf[1024];
    byte  md5sum[MD5::DIGEST_SIZE];
    
    if( !( f = fopen( file, "rb" ) )) {
        printf("Can't open %s\n", file);
        return;
    }
    while( ( i = fread(buf, 1, sizeof(buf), f )) > 0 )
        md5.Update(buf, i);
    
    md5.Final(md5sum);
    memcpy(check, md5sum, sizeof(md5sum));

    for(int j = 0; j < MD5::DIGEST_SIZE; ++j ) 
        printf( "%02x", md5sum[j] );
   
    printf("  %s\n", file);
}


int sha_test()
{
    SHA  sha;
    byte hash[SHA::DIGEST_SIZE];

    testVector test_sha[] =
    {
        testVector("abc", 
                 "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2"
                 "\x6C\x9C\xD0\xD8\x9D"),
        testVector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                 "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29"
                 "\xE5\xE5\x46\x70\xF1"),
        testVector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaa", 
                 "\x00\x98\xBA\x82\x4B\x5C\x16\x42\x7B\xD7\xA1\x12\x2A\x5A\x44"
                 "\x2A\x25\xEC\x64\x4D"),
        testVector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaaaa",
                 "\xAD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7"
                 "\x53\x99\x5E\x26\xA0")  
    };

    int times( sizeof(test_sha) / sizeof(testVector) );
    for (int i = 0; i < times; ++i) {
        sha.Update(test_sha[i].input_, test_sha[i].inLen_);
        sha.Final(hash);

        if (memcmp(hash, test_sha[i].output_, SHA::DIGEST_SIZE) != 0)
            return -1 - i;
    }

    return 0;
}


int md5_test()
{
    MD5  md5;
    byte hash[MD5::DIGEST_SIZE];

    testVector test_md5[] =
    {
        testVector("abc", 
                 "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f"
                 "\x72"),
        testVector("message digest", 
                 "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61"
                 "\xd0"),
        testVector("abcdefghijklmnopqrstuvwxyz",
                 "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1"
                 "\x3b"),
        testVector("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345"
                 "6789",
                 "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d"
                 "\x9f"),
        testVector("1234567890123456789012345678901234567890123456789012345678"
                 "9012345678901234567890",
                 "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6"
                 "\x7a")
    };

    int times( sizeof(test_md5) / sizeof(testVector) );
    for (int i = 0; i < times; ++i) {
        md5.Update(test_md5[i].input_, test_md5[i].inLen_);
        md5.Final(hash);

        if (memcmp(hash, test_md5[i].output_, MD5::DIGEST_SIZE) != 0)
            return -5 - i;
    }

    return 0;
}


int md2_test()
{
    MD2  md5;
    byte hash[MD2::DIGEST_SIZE];

    testVector test_md2[] =
    {
		testVector("",
                   "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x69"
                   "\x27\x73"),
		testVector("a",
                   "\x32\xec\x01\xec\x4a\x6d\xac\x72\xc0\xab\x96\xfb\x34\xc0"
                   "\xb5\xd1"),
		testVector("abc",
                   "\xda\x85\x3b\x0d\x3f\x88\xd9\x9b\x30\x28\x3a\x69\xe6\xde"
                   "\xd6\xbb"),
		testVector("message digest",
                   "\xab\x4f\x49\x6b\xfb\x2a\x53\x0b\x21\x9f\xf3\x30\x31\xfe"
                   "\x06\xb0"),
		testVector("abcdefghijklmnopqrstuvwxyz",
                   "\x4e\x8d\xdf\xf3\x65\x02\x92\xab\x5a\x41\x08\xc3\xaa\x47"
                   "\x94\x0b"),
		testVector("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                   "0123456789",
                   "\xda\x33\xde\xf2\xa4\x2d\xf1\x39\x75\x35\x28\x46\xc3\x03"
                   "\x38\xcd"),
		testVector("12345678901234567890123456789012345678901234567890123456"
                   "789012345678901234567890",
                   "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d\xc9\x80\x6c\x3c\x66\xf3"
                   "\xef\xd8")
    };

    int times( sizeof(test_md2) / sizeof(testVector) );
    for (int i = 0; i < times; ++i) {
        md5.Update(test_md2[i].input_, test_md2[i].inLen_);
        md5.Final(hash);

        if (memcmp(hash, test_md2[i].output_, MD2::DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}


int hmac_test()
{
    HMAC<MD5> hmacMD5;
    byte hash[MD5::DIGEST_SIZE];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    };

    testVector test_hmacMD5[] = 
    {
        testVector("Hi There",
                 "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc"
                 "\x9d"),
        testVector("what do ya want for nothing?",
                 "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7"
                 "\x38"),
        testVector("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
                 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
                 "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
                 "\xDD\xDD\xDD\xDD\xDD\xDD",
                 "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3"
                 "\xf6")
    };

    int times( sizeof(test_hmacMD5) / sizeof(testVector) );
    for (int i = 0; i < times; ++i) {
        hmacMD5.SetKey((byte*)keys[i], strlen(keys[i]));
        hmacMD5.Update(test_hmacMD5[i].input_, test_hmacMD5[i].inLen_);
        hmacMD5.Final(hash);

        if (memcmp(hash, test_hmacMD5[i].output_, MD5::DIGEST_SIZE) != 0)
            return -20 - i;
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

    testVector test_arc4[] =
    {
        testVector("\x01\x23\x45\x67\x89\xab\xcd\xef",
                   "\x75\xb7\x87\x80\x99\xe0\xc5\x96"),
        testVector("\x00\x00\x00\x00\x00\x00\x00\x00",
                   "\x74\x94\xc2\xe7\x10\x4b\x08\x79"),
        testVector("\x00\x00\x00\x00\x00\x00\x00\x00",
                   "\xde\x18\x89\x41\xa3\x37\x5d\x3a"),
        testVector("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                   "\xd6\xa1\x41\xa7\xec\x3c\x38\xdf\xbd\x61")
    };


    int times( sizeof(test_arc4) / sizeof(testVector) );
    for (int i = 0; i < times; ++i) {
        ARC4::Encryption enc;
        ARC4::Decryption dec;

        enc.SetKey((byte*)keys[i], strlen(keys[i]));
        dec.SetKey((byte*)keys[i], strlen(keys[i]));

        enc.Process(cipher, test_arc4[i].input_, test_arc4[i].outLen_);
        dec.Process(plain,  cipher, test_arc4[i].outLen_);

        if (memcmp(plain, test_arc4[i].input_, test_arc4[i].outLen_))
            return -30 - i;

        if (memcmp(cipher, test_arc4[i].output_, test_arc4[i].outLen_))
            return -40 - i;
    }

    return 0;
}


int des_test()
{
    //ECB mode
    DES_ECB_Encryption enc;
    DES_ECB_Decryption dec;

 
    const byte key[] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    const byte iv[] =  { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };

    const char vector[] = "Now is the time for all ";  // strlen == 24
    byte plain[24];
    byte cipher[24];

    enc.SetKey(key, sizeof(key));
    enc.Process(cipher, (byte*)vector, strlen(vector));
    dec.SetKey(key, sizeof(key));
    dec.Process(plain, cipher, sizeof(cipher));

    if (memcmp(plain, vector, sizeof(plain)))
        return -50;

    const byte verify1[] = 
    {
        0x3f,0xa4,0x0e,0x8a,0x98,0x4d,0x48,0x15,
        0x6a,0x27,0x17,0x87,0xab,0x88,0x83,0xf9,
        0x89,0x3d,0x51,0xec,0x4b,0x56,0x3b,0x53
    };

    if (memcmp(cipher, verify1, sizeof(cipher)))
        return -51;

    // CBC mode
    DES_CBC_Encryption enc2;
    DES_CBC_Decryption dec2;

    enc2.SetKey(key, sizeof(key), iv);
    enc2.Process(cipher, (byte*)vector, strlen(vector));
    dec2.SetKey(key, sizeof(key), iv);
    dec2.Process(plain, cipher, sizeof(cipher));

    if (memcmp(plain, vector, sizeof(plain)))
        return -52;

    const byte verify2[] = 
    {
        0xe5,0xc7,0xcd,0xde,0x87,0x2b,0xf2,0x7c,
        0x43,0xe9,0x34,0x00,0x8c,0x38,0x9c,0x0f,
        0x68,0x37,0x88,0x49,0x9a,0x7c,0x05,0xf6
    };

    if (memcmp(cipher, verify2, sizeof(cipher)))
        return -53;

    // EDE3 CBC mode
    DES_EDE3_CBC_Encryption enc3;
    DES_EDE3_CBC_Decryption dec3;

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

    enc3.SetKey(key3, sizeof(key3), iv3);
    enc3.Process(cipher, (byte*)vector, strlen(vector));
    dec3.SetKey(key3, sizeof(key3), iv3);
    dec3.Process(plain, cipher, sizeof(cipher));

    if (memcmp(plain, vector, sizeof(plain)))
        return -54;

    const byte verify3[] = 
    {
        0x43,0xa0,0x29,0x7e,0xd1,0x84,0xf8,0x0e,
        0x89,0x64,0x84,0x32,0x12,0xd5,0x08,0x98,
        0x18,0x94,0x15,0x74,0x87,0x12,0x7d,0xb0
    };

    if (memcmp(cipher, verify3, sizeof(cipher)))
        return -55;

    return 0;
}


int aes_test()
{
    AES_CBC_Encryption enc;
    AES_CBC_Decryption dec;
    const int bs(TaoCrypt::AES::BLOCK_SIZE);

    byte key[] = "0123456789abcdef";
    byte iv[]  = "1234567890abcdef";
    byte msg[] = "now is the time ";
    byte cipher[bs];
    byte plain [bs];

    enc.SetKey(key, bs, iv);
    dec.SetKey(key, bs, iv);

    enc.Process(cipher, msg, bs);
    dec.Process(plain, cipher, bs);

    if (memcmp(plain, msg, bs))
        return -60;

    const byte verify[] = 
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };

    if (memcmp(cipher, verify, bs))
        return -61;

    AES_ECB_Encryption enc2;
    AES_ECB_Decryption dec2;

    enc2.SetKey(key, bs, iv);
    dec2.SetKey(key, bs, iv);

    enc2.Process(cipher, msg, bs);
    dec2.Process(plain, cipher, bs);

    if (memcmp(plain, msg, bs))
        return -62;

    const byte verify2[] = 
    {
        0xd0,0xc9,0xd9,0xc9,0x40,0xe8,0x97,0xb6,
        0xc8,0x8c,0x33,0x3b,0xb5,0x8f,0x85,0xd1
    };

    if (memcmp(cipher, verify2, bs))
        return -63;

    return 0;
}


int rsa_test()
{
    std::string name = "../certs/client-key.der";
	Source source;
    FileSource(name, source);
    if (source.size() == 0) {
        FileSource("../../certs/client-key.der", source);  // for testsuite
        if (source.size() == 0) {
            FileSource("../../../certs/client-key.der", source); // Debug dir
            if (source.size() == 0)
                err_sys("where's your certs dir?", -79);
        }
    }
    RSA_PrivateKey priv(source);

    RSAES_Encryptor enc(priv);
    byte message[] = "Everyone gets Friday off.";
    const int len(strlen((char*)message));
    byte cipher[64];
    enc.Encrypt(message, len, cipher, rng);

    RSAES_Decryptor dec(priv);
    byte plain[64];
    dec.Decrypt(cipher, sizeof(cipher), plain, rng);

    if (memcmp(plain, message, len))
        return -70;

    dec.SSL_Sign(message, len, cipher, rng);
    if (!enc.SSL_Verify(message, len, cipher))
        return -71;


    // test decode   
    name = "../certs/client-cert.der";
    Source source2;
    FileSource(name, source2);
    if (source2.size() == 0) {
        FileSource("../../certs/client-cert.der", source2);  // for testsuite
        if (source2.size() == 0) {
            FileSource("../../../certs/client-cert.der", source2); // Debug dir
            if (source2.size() == 0)
                err_sys("where's your certs dir?", -79);
        }
    }
    CertDecoder cd(source2);
    Source source3(cd.GetPublicKey().GetKey(), cd.GetPublicKey().size());
    RSA_PublicKey pub(source3);
 
    return 0;
}


int dh_test()
{
    std::string name = "../certs/dh1024.dat";
    Source source;
    FileSource(name, source);
    if (source.size() == 0) {
        FileSource("../../certs/dh1024.dat", source);  // for testsuite
        if (source.size() == 0) {
            FileSource("../../../certs/dh1024.dat", source); // win32 Debug dir
            if (source.size() == 0)
                err_sys("where's your certs dir?", -79);
        }
    }
    HexDecoder hDec(source);

    DH dh(source);

    byte pub[128];
    byte priv[128];
    byte agree[128];
    byte pub2[128];
    byte priv2[128];
    byte agree2[128];

    DH dh2(dh);

    dh.GenerateKeyPair(rng, priv, pub);
    dh2.GenerateKeyPair(rng, priv2, pub2);
    dh.Agree(agree, priv, pub2); 
    dh2.Agree(agree2, priv2, pub);

    
    if ( memcmp(agree, agree2, dh.GetByteLength()) )
        return -80;

    return 0;
}


int dsa_test()
{
    std::string name = "../certs/dsa512.der";
    Source source;
    FileSource(name, source);
    if (source.size() == 0) {
        FileSource("../../certs/dsa512.der", source);  // for testsuite
        if (source.size() == 0) {
            FileSource("../../../certs/dsa512.der", source); // win32 Debug dir
            if (source.size() == 0)
                err_sys("where's your certs dir?", -89);
        }
    }

    const char msg[] = "this is the message";
    byte signature[80];

    DSA_PrivateKey priv(source);
    DSA_Signer signer(priv);
    word32 signLen = signer.Sign((byte*)msg, sizeof(msg), signature, rng);

    byte encoded[sizeof(signature) + 16];
    byte decoded[sizeof(encoded)];

    word32 encSz = EncodeDSA_Signature(signer.GetR(), signer.GetS(), encoded);
    DecodeDSA_Signature(decoded, encoded, encSz);

    assert(memcmp(decoded, signature, signLen) == 0);

    DSA_PublicKey pub(priv);
    DSA_Verifier verifier(pub);

    if (!verifier.Verify((byte*)msg, sizeof(msg), signature))
        return -90;

    return 0;
}
