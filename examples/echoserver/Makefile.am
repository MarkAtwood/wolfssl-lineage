INCLUDES = -I../../include
bin_PROGRAMS        = echoserver
echoserver_SOURCES  = echoserver.cpp
echoserver_LDFLAGS  = -L../../src/ -L../../taocrypt/src
echoserver_LDADD    = -lyassl -ltaocrypt $(EXTRA_SOCKET)
EXTRA_DIST = echoserver.dsp
