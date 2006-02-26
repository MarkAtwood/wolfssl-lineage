INCLUDES = -I../../include
bin_PROGRAMS    = server
server_SOURCES  = server.c
server_CFLAGS = -Wall $(PTHREAD_CFLAGS)
server_LDFLAGS  = -L../../src/ -L../../ctaocrypt/src $(PTHREAD_LDFLAGS)
server_LDADD    = -lcyassl -lctaocrypt $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
EXTRA_DIST = server.dsp
