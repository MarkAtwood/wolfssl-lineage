SUBDIRS = src ctaocrypt examples testsuite
EXTRA_DIST = cyassl.dsp cyassl.dsw certs/*.pem certs/*.der certs/*.txt lib/dummy

basic:
	cd src; make; cd ../testsuite; make; cd ../

openssl-links:
	cd lib; ln -s ../src/libcyassl.a libcrypto.a; \
    ln -s ../src/libcyassl.a libssl.a; cd ../
    
