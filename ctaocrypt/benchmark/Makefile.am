INCLUDES = -I../include
bin_PROGRAMS = benchmark
benchmark_SOURCES = benchmark.c
benchmark_LDFLAGS      = -L../src -lm
benchmark_LDADD        = ../src/libctaocrypt.la
benchmark_DEPENDENCIES = ../src/libctaocrypt.la
EXTRA_DIST =  benchmark.dsp *.der
