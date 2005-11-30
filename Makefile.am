SUBDIRS = taocrypt src examples testsuite
EXTRA_DIST = yassl.dsp yassl.dsw certs/*.pem certs/*.d* certs/*.txt doc/*.html \
	doc/*.png mySTL/*.hpp stunnel/stunnel.* stunnel/*.txt stunnel/src/*.c


lib-only:
	cd taocrypt/src; make; cd ../../src; make; cd ../

