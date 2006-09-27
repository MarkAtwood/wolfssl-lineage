INCLUDES = -I../../include
bin_PROGRAMS    = client
client_SOURCES  = client.c
client_CFLAGS = -Wall -Wno-unused $(PTHREAD_CFLAGS)
client_LDFLAGS      = -L../../src $(PTHREAD_LDFLAGS) -lm
client_LDADD        = ../../src/libcyassl.la $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
client_DEPENDENCIES = ../../src/libcyassl.la 
EXTRA_DIST = client.dsp
