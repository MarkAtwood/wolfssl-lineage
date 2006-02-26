INCLUDES = -I../../include
bin_PROGRAMS    = echoclient
echoclient_SOURCES  = echoclient.c
echoclient_CFLAGS = -Wall -Wno-unused $(PTHREAD_CFLAGS)
echoclient_LDFLAGS  = -L../../src/ -L../../ctaocrypt/src $(PTHREAD_LDFLAGS)
echoclient_LDADD    = -lcyassl -lctaocrypt $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
EXTRA_DIST = echoclient.dsp input quit
