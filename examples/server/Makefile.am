INCLUDES = -I../../include
bin_PROGRAMS    = server
server_SOURCES  = server.c
server_CFLAGS = -Wall $(PTHREAD_CFLAGS)
server_LDFLAGS      = -L../../src $(PTHREAD_LDFLAGS) -lm
server_LDADD        = ../../src/libcyassl.la $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
server_DEPENDENCIES = ../../src/libcyassl.la
EXTRA_DIST = server.dsp
