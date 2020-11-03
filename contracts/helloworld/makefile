CC=eosio-cpp
CFLAGS=-I.
SOURCES := $(shell find . -name '*.cpp')
BUILDDIR=build
CONTRACTNAME=helloworld

build:
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -o $(BUILDDIR)/$(CONTRACTNAME).wasm $(SOURCES)