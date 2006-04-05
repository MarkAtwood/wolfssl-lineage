INCLUDES = -I../include

lib_LTLIBRARIES = libctaocrypt.la
libctaocrypt_la_SOURCES = aes.c arc4.c asn.c coding.c des3.c dh.c hmac.c \
    integer.c md5.c random.c rsa.c sha.c
libctaocrypt_la_LDFLAGS = -no-undefined -version-info 0:0:0
AM_CFLAGS = -Wall
EXTRA_DIST = ../include/*.h misc.c

