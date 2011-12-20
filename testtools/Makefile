include ../RELEASE.makeinfo
#
#
#
SUBTARGETS=treegraph
DISTTARGETS=$(SUBTARGETS)
OCFALIB_TOP_DIR=..
#include global.makeinfo
VERSION=2.2
RELEASE=$(VERSIONTAG)
DISTDIR=/usr/local/ocfa$(RELEASE)
INSTALLDIR=/usr/local/ocfa$(RELEASE)
include ../OS.makeinfo

all:
	returnValue=0;\
	for dir in $(SUBTARGETS);\
	do \
	$(MAKE) -C $$dir; \
	if [ $$? != 0 ]; then \
	        exit 1 ;\
	fi ; \
	done; \
	exit $$returnValue

clean:
	returnValue=0;\
	for dir in $(SUBTARGETS);\
	do \
	$(MAKE) clean -C $$dir; \
	if [ $$? != 0 ]; then \
		exit 1 ;\
	fi ; \
	done; \
	exit $$returnValue

install: installinc installsub installdist installgroup installsyslog installprofile
	returnValue=0;\
	for dir in $(SUBTARGETS);\
	do \
	$(MAKE) install -C $$dir; \
	if [ $$? != 0 ]; then \
		exit 1 ;\
	fi ; \
	done; \
	exit $$returnValue


