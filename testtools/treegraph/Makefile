#
#
#
OCFALIB_TOP_DIR=../..
#include global.makeinfo
VERSION=2.2
RELEASE=$(VERSIONTAG)
DISTDIR=/usr/local/ocfa$(RELEASE)
INSTALLDIR=/usr/local/ocfa$(RELEASE)
include ../../OS.makeinfo

all: treegraphdump.cpp
	g++ -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_REENTRANT -ggdb treegraphdump.cpp -o treegraphdump -I../../inc/ $(DISTDIR)/lib/libocfatreegraph.so  $(DISTDIR)/lib/libocfamisc.so

clean:
	rm treegraphdump

install: treegraphdump
	cp treegraphdump $(DISTDIR)/bin/

