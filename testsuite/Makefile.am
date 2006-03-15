INCLUDES = -I../include -I../ctaocrypt/include
bin_PROGRAMS    = testsuite
testsuite_SOURCES = testsuite.c ../ctaocrypt/test/test.c \
    ../examples/client/client.c ../examples/server/server.c \
    ../examples/echoclient/echoclient.c ../examples/echoserver/echoserver.c
testsuite_CFLAGS  = -Wall -Wno-unused -DNO_MAIN_DRIVER $(PTHREAD_CFLAGS)
testsuite_LDFLAGS      = -L../src $(PTHREAD_LDFLAGS)
testsuite_LDADD        = ../src/libcyassl.la $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
testsuite_DEPENDENCIES = ../src/libcyassl.la 
EXTRA_DIST = testsuite.dsp input quit
