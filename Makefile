objects = src/yassl_imp.o src/yassl_int.o src/factory.o src/crypto_wrapper.o \
	src/handshake.o src/ssl.o src/cert_wrapper.o src/socket_wrapper.o


all: $(objects) libyassl.a

libyassl.a: $(objects)
	ar -cr ./lib/$@ $(objects)
	ranlib ./lib/$@


CPPFLAGS = -Wall -g -I./include -I./cryptopp51 -I./SMPDist/include/smp \
	-I./SMPDist/include/esnacc/c++

server: src/server.o libyassl.a
	g++ -g -o $@ src/server.o -lyassl -lcryptopp -lcmapi -lcmlasn -lctil \
	-lc++asn1 -L./lib -L./SMPDist/lib -L./cryptopp51

client: src/client.o libyassl.a
	g++ -g -o $@ src/client.o -lyassl -lcryptopp -lcmapi -lcmlasn -lctil \
	-lc++asn1 -L./lib -L./SMPDist/lib -L./cryptopp51


.PHONY: clean
clean:
	rm *.o
	rm libyassl.a
	rm server
	rm client

