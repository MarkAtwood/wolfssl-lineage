objects = aes.o aestables.o algebra.o arc4.o asn.o des.o file.o hash.o \
	integer.o md5.o misc.o random.o rsa.o sha.o


all: $(objects) libtaocrypt.a

libtaocrypt.a: $(objects)
	ar -cr $@ $(objects)
	ranlib $@


CPPFLAGS = -Wall -g

main: main.o libtaocrypt.a
	g++ -g -o main.exe main.o -L. -ltaocrypt 

.PHONY: clean
clean:
	rm *.o
	rm libtaocrypt.a
	rm main.exe

