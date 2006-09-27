INCLUDES = -I../../include
bin_PROGRAMS    = echoserver
echoserver_SOURCES  = echoserver.c
echoserver_CFLAGS = -Wall $(PTHREAD_CFLAGS)
echoserver_LDFLAGS  = -L../../src $(PTHREAD_LDFLAGS) -lm
echoserver_LDADD       = ../../src/libcyassl.la $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
echoserver_DEPENDENCIES= ../../src/libcyassl.la
EXTRA_DIST = echoserver.dsp
