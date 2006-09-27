INCLUDES = -I../../include
bin_PROGRAMS    = echoclient
echoclient_SOURCES  = echoclient.c
echoclient_CFLAGS = -Wall -Wno-unused $(PTHREAD_CFLAGS)
echoclient_LDFLAGS     = -L../../src $(PTHREAD_LDFLAGS) -lm
echoclient_LDADD       = ../../src/libcyassl.la $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
echoclient_DEPENDENCIES= ../../src/libcyassl.la
EXTRA_DIST = echoclient.dsp input quit
