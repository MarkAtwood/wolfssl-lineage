INCLUDES = -I../../include
bin_PROGRAMS    = server
server_SOURCES  = server.cpp
server_CXXFLAGS = -Wall -Wno-unused $(PTHREAD_CFLAGS)
server_LDFLAGS  = -L../../src/ -L../../taocrypt/src
server_LDADD    = -lyassl -ltaocrypt $(EXTRA_SOCKET)
server_DEPENDENCIES = ../../src/libyassl.a ../../taocrypt/src/libtaocrypt.a
EXTRA_DIST = server.dsp
