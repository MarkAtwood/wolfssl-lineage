SUBDIRS = src ctaocrypt examples testsuite
EXTRA_DIST = cyassl.dsp cyassl.dsw certs/*.pem certs/*.der certs/*.txt \
    lib/dummy cyassl.sln cyassl.vcproj cyassl-iphone.xcodeproj/project.pbxproj \
    doc/*.pdf

basic:
	cd src; make; cd ../testsuite; make; cd ../

openssl-links:
	cd lib; ln -s ../src/.libs/libcyassl.a libcrypto.a; \
    ln -s ../src/.libs/libcyassl.a libssl.a; \
    ln -s ../src/.libs/libcyassl.a libcyassl.a; cd ../

install:
	mkdir ${prefix}/cyassl; \
    mkdir ${prefix}/cyassl/include; \
    mkdir ${prefix}/cyassl/include/openssl; \
    cp include/openssl/*.h ${prefix}/cyassl/include/openssl; \
    make openssl-links; \
    mkdir ${prefix}/cyassl/lib; \
    cp lib/*.a ${prefix}/cyassl/lib
