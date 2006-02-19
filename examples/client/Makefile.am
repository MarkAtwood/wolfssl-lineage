INCLUDES = -I../../include
bin_PROGRAMS    = client
client_SOURCES  = client.c
client_CFLAGS = -Wall $(PTHREAD_CFLAGS)
client_LDFLAGS  = -L../../src/ -L../../ctaocrypt/src
client_LDADD    = -lcyassl -lctaocrypt $(EXTRA_SOCKET)
EXTRA_DIST = client.dsp
