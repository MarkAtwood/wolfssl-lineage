INCLUDES = -I../include -I../taocrypt/include -I../mySTL
bin_PROGRAMS       = testsuite
testsuite_SOURCES  = testsuite.cpp ../taocrypt/test/test.cpp \
	../examples/client/client.cpp ../examples/server/server.cpp \
	../examples/echoclient/echoclient.cpp \
	../examples/echoserver/echoserver.cpp
testsuite_LDFLAGS  = -L../src/ -L../taocrypt/src
testsuite_CXXFLAGS = -DNO_MAIN_DRIVER
testsuite_LDADD    = -lyassl -ltaocrypt $(EXTRA_PTHREAD) $(EXTRA_SOCKET)
EXTRA_DIST = testsuite.dsp test.hpp input quit
