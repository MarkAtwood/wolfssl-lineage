INCLUDES = -I../../include
bin_PROGRAMS    = client
client_SOURCES  = client.cpp
client_CXXFLAGS = -Wall -Wno-unused $(PTHREAD_CFLAGS)
client_LDFLAGS  = -L../../src/ -L../../taocrypt/src
client_LDADD    = -lyassl -ltaocrypt $(EXTRA_SOCKET)
EXTRA_DIST = client.dsp
