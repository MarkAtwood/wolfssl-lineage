INCLUDES = -I../../include
bin_PROGRAMS    = echoserver
echoserver_SOURCES  = echoserver.c
echoserver_CFLAGS = -Wall $(PTHREAD_CFLAGS)
echoserver_LDFLAGS  = -L../../src/ -L../../ctaocrypt/src $(PTHREAD_LDFLAGS)
echoserver_LDADD    = -lcyassl -lctaocrypt $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
EXTRA_DIST = echoserver.dsp
