INCLUDES = -I../../include
bin_PROGRAMS    = client
client_SOURCES  = client.c
client_CFLAGS = -Wall -Wno-unused
client_LDFLAGS      = -L../../src -lm
client_LDADD        = ../../src/libcyassl.la
client_DEPENDENCIES = ../../src/libcyassl.la
EXTRA_DIST = client.dsp
