INCLUDES = -I../../include
bin_PROGRAMS    = client
client_SOURCES  = client.c
client_CFLAGS = -Wall -Wno-unused $(PTHREAD_CFLAGS)
client_LDFLAGS  = -L../../src/ -L../../ctaocrypt/src $(PTHREAD_LDFLAGS)
client_LDADD    = -lcyassl -lctaocrypt $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
EXTRA_DIST = client.dsp
