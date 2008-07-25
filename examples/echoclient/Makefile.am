INCLUDES = -I../../include
bin_PROGRAMS    = echoclient
echoclient_SOURCES  = echoclient.c
echoclient_CFLAGS = -Wall -Wno-unused
echoclient_LDFLAGS     = -L../../src -lm
echoclient_LDADD       = ../../src/libcyassl.la
echoclient_DEPENDENCIES= ../../src/libcyassl.la
EXTRA_DIST = echoclient.dsp input quit echoclient.sln echoclient.vcproj
