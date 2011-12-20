#
#
#
SUBTARGETS=misc treegraph fs evidence store message module facade
OCFALIB_TOP_DIR=.
#include global.makeinfo
include RELEASE.makeinfo
VERSION=2.3
RELEASE=$(VERSIONTAG)
DISTDIR=/usr/local/ocfa$(RELEASE)
INSTALLDIR=/usr/local/ocfa$(RELEASE)
include OS.makeinfo
SHELL := /bin/bash

all:
	echo release=$(RELEASE)
	if [ $(CONF_OK) ]; then \
		echo Configuration seems ok; \
	else \
		echo Can not build with bad configuration;\
		exit 1;\
	fi;
	returnValue=0;\
	for dir in $(SUBTARGETS);\
	do \
	$(MAKE) -C $$dir; \
	if [ $$? != 0 ]; then \
	        exit 1 ;\
	fi ; \
	done; \
	exit $$returnValue

dpkg:
	if [ `dpkg --print-architecture` == "amd64" ] ; then \
		cd misc; make dpkg;\
		cd ../treegraph; make dpkg;\
		cd ../fs; make dpkg;\
		cd ../evidence; make dpkg;\
		cd ../store; make dpkg;\
		cd ../message; make dpkg;\
		cd ../module; make dpkg;\
		cd ../facade; make dpkg;\
		cd ..;\
	else \
		echo -n "Build debian packages only on amd64 architecture, not on ";\
		dpkg --print-architecture;\
		exit 1;\
	fi;\

clean:
	cd misc; make clean
	cd evidence; make clean
	cd treegraph;make clean
	cd fs; make clean
	cd module; make clean
	cd facade; make clean
	cd store; make clean
	cd message; make clean

install: installinc installsub installdist installgroup installsyslog installprofile
	chmod 755 $(DISTDIR)
	if [ -e /usr/local/digiwash$(VERSION) ]; then \
	rm /usr/local/digiwash$(VERSION); \
	fi;
	ln -fs $(DISTDIR) /usr/local/digiwash$(VERSION)
	if [ -e /usr/local/digiwash ]; then \
	rm /usr/local/digiwash; \
	fi;
	ln -fs /usr/local/digiwash$(VERSION) /usr/local/digiwash



installdist:
	install -d $(DISTDIR)/etc
	cp dist/etc/motd $(DISTDIR)/etc/motd
	install -d $(DISTDIR)/schema
	cp dist/schema/ocfa.xsd $(DISTDIR)/schema

installinc:
	install -d $(OCFAINCINSTDIR)
	install -d $(OCFAINCINSTDIR)/misc/
	install -d $(OCFAINCINSTDIR)/misc/Exception/
	install -d $(OCFAINCINSTDIR)/evidence/
	install -d $(OCFAINCINSTDIR)/treegraph/
	install -d $(OCFAINCINSTDIR)/fs/
	install -d $(OCFAINCINSTDIR)/store/
	install -d $(OCFAINCINSTDIR)/message/
	install -d $(OCFAINCINSTDIR)/module/
	install -d $(OCFAINCINSTDIR)/facade/
	install inc/*.hpp $(OCFAINCINSTDIR)/
	install inc/misc/*.hpp $(OCFAINCINSTDIR)/misc/
	install inc/misc/Exception/*.hpp $(OCFAINCINSTDIR)/misc/Exception/
	install inc/evidence/*.hpp $(OCFAINCINSTDIR)/evidence/
	install inc/treegraph/*.hpp $(OCFAINCINSTDIR)/treegraph/
	install inc/fs/*.hpp $(OCFAINCINSTDIR)/fs/
	install inc/store/*.hpp $(OCFAINCINSTDIR)/store/
	install inc/message/*.hpp $(OCFAINCINSTDIR)/message/
	install inc/module/*.hpp $(OCFAINCINSTDIR)/module/
	install inc/facade/*.hpp $(OCFAINCINSTDIR)/facade/
#	mv $(OCFAINCINSTDIR)/misc/OcfaObject.hpp $(OCFAINCINSTDIR)/OcfaObject.hpp
	
installgroup:
	inst/addocfagroup 
	chown root:ocfa $(DISTDIR)/etc
	chmod 770 $(DISTDIR)/etc


installsyslog:
	cd misc/syslog;./install.pl

installprofile:
	if [ ! -f $(DISTDIR)/.profile ]; then \
		echo OCFAROOT=$(INSTALLDIR) > $(DISTDIR)/.profile;\
		echo OCFARELEASE=$(RELEASE) >> $(DISTDIR)/.profile;\
		echo export OCFARELEASE >> $(DISTDIR)/.profile;\
		cat dist/etc/profile >> $(DISTDIR)/.profile;\
	fi


installsub:	
	echo subtargets are $(SUBTARGETS)
	echo INSTALLIB Is $(INSTALLIB)
	returnValue=0
	for dir in $(SUBTARGETS);\
	do \
	echo doing install $$dir;\
	$(MAKE) -C $$dir install; \
	if [ $$? != 0 ] ; then \
	exit 1; \
	fi ; \
	$(MAKE) -C $$dir installadd; \
	if [ $$? != 0 ] ; then \
	exit 1; \
	fi ; \
	done; 
	echo 0
	exit 0

rootinstall: 
	echo make rootinstall is depricated
	echo use 'make install' instead !!
	exit 1
