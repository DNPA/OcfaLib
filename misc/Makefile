include ../RELEASE.makeinfo
#
#The project is the name of the sub project of the washing machine.
#
OCFALIB_TOP_DIR=..
PROJECT=ocfamisc
INTERFACEDIR=../inc/misc
EXTRAINCFLAGS=-I$(BOOSTINCDIR)
include ../global.makeinfo
GCCFLAGS += $(GCCFLAGS_MISC)
#GCCFLAGS += $(GCCFLAGS_STRICT)  
OBJFILESLIB=${BUILDDIR}/OcfaLogger.lo  $(BUILDDIR)/OcfaFile.lo $(BUILDDIR)/OcfaContent.lo $(BUILDDIR)/OcfaHandle.lo $(BUILDDIR)/OcfaObject.lo $(BUILDDIR)/OcfaException.lo $(BUILDDIR)/Scalar.lo $(BUILDDIR)/DateTime.lo $(BUILDDIR)/ModuleInstance.lo ${BUILDDIR}/SimpleLogger.lo $(BUILDDIR)/OcfaConfig.lo $(BUILDDIR)/SimpleConfig.lo $(BUILDDIR)/ItemIdentifier.lo $(BUILDDIR)/EvidenceIdentifier.lo $(BUILDDIR)/MemBuf.lo $(BUILDDIR)/DigestPair.lo $(BUILDDIR)/SimpleItem.lo $(BUILDDIR)/ScalarMetaValue.lo $(BUILDDIR)/ArrayMetaValue.lo $(BUILDDIR)/TableMetaValue.lo $(BUILDDIR)/ModuleInstanceFactory.lo $(BUILDDIR)/IPAddress.lo $(BUILDDIR)/OcfaGroup.lo $(BUILDDIR)/FsUtil.lo $(BUILDDIR)/MetaUtil.lo
# the libs which should be linked with our object files
#
#OBJFILESTEST=$(BUILDDIR)/LibCryptDigestPair.lo $(BUILDDIR)/DigestPairFactory.lo
LOG4COBJFILES=$(BUILDDIR)/Log4cxxLogger.lo $(BUILDDIR)/OcfaFileAppender.lo
SYSLOGOBJFILES=$(BUILDDIR)/SyslogLogger.lo $(BUILDDIR)/syslogbuf.lo $(BUILDDIR)/GlobalMutex.lo
NULLLOGOBJFILES=$(BUILDDIR)/NullLogger.lo $(BUILDDIR)/nullbuf.lo
LOG4CLIBS=/usr/local/lib/liblog4cxx.la
LIBS=-lcrypto -l$(BOOST_REGEX_LIB) -l$(BOOST_FILESYSTEM_LIB) $(LIBCRYPTDIR) $(LICONV_IF_NEEDED)
INCFLAGS+=$(INCCRYPTDIR)
# OcfaObject has a special status because it is not in the 
# 
$(BUILDDIR)/OcfaObject.lo: $(SRCDIR)/OcfaObject.cpp $(OCFAINCDIR)/OcfaObject.hpp
	if [ ! -d $(BUILDDIR) ]; then mkdir $(BUILDDIR);fi
	$(LIBTOOL) --tag=CPP --mode=compile $(CPP) -ggdb -c $(GCCFLAGS) $(INCFLAGS) -o $@ $<
#
# Target which creates an shared library. You will always need a
# library because you want to run your regression tests. 
#
#
lib$(PROJECT): $(OBJFILESLIB)
	echo INSTALLIB is $(INSTALLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_MISC) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) ${INCFLAGS}

static: $(OBJFILESLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) -static ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(O
	BJFILESLIB) ${INCFLAGS}

all: lib$(PROJECT)  syslog nulllog

# Target that creates the executable for the tests.
#
test: all $(OBJFILESTEST)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(GCCFLAGS) -Wall -I../inc -Iinc $(OBJFILESTEST) test/simpledemo.cpp $(LTLINKFLAGS) -o  test/simpledemo build/libocfamisc.la
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(GCCFLAGS) -Wall -I../inc -Iinc $(OBJFILESTEST) test/valgrind/group.cpp $(LTLINKFLAGS) -o  test/valgrind/group build/libocfamisc.la
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(GCCFLAGS) -Wall -I../inc -Iinc $(OBJFILESTEST) test/valgrind/log.cpp $(LTLINKFLAGS) -o  test/valgrind/log build/libocfamisc.la

$(BUILDDIR)/%.lo: $(SRCDIR)/%.cpp $(IMPLINCDIR)/log4c/%.hpp
	if [ ! -d $(BUILDDIR) ]; then mkdir $(BUILDDIR);fi
	$(LIBTOOL) --tag=CPP --mode=compile $(CPP) -ggdb -c $(INCFLAGS) -o $@ $<

log4c: all $(LOG4COBJFILES)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(LIBS) $(LOG4CLIBS) -lpthread -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_MISC_LOG4C) $(LTLINKFLAGS) -o $(BUILDDIR)/libocfalog4c.la $(BUILDDIR)/lib$(PROJECT).la $(LOG4COBJFILES) 

syslog: lib$(PROJECT) $(SYSLOGOBJFILES)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(LIBS) -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_MISC_SYSLOG) $(LTLINKFLAGS) -o $(BUILDDIR)/libocfasyslog.la ${BUILDDIR}/lib$(PROJECT).la $(SYSLOGOBJFILES)

nulllog: lib$(PROJECT) $(NULLLOGOBJFILES)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(LIBS) -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_MISC_NULL) $(LTLINKFLAGS) -o $(BUILDDIR)/libocfanulllog.la ${BUILDDIR}/lib$(PROJECT).la $(NULLLOGOBJFILES)

installadd: all		
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/libocfasyslog.la $(INSTALLIB)
	if [ -f $(BUILDDIR)/libocfalog4c.la ] ; then $(LIBTOOL) --mode=install cp $(BUILDDIR)/libocfalog4c.la $(INSTALLIB);fi

installlog4c:
	$(LIBTOOL) --mode=install cp etc/log4c.properties $(INSTALL_ETC)


dpkg: lib$(PROJECT) syslog 
	install -d $(PWD)/build/debian/$(DISTDIR)
	ln -s $(DISTDIR) $(PWD)/build/debian/usr/local/digiwash$(VERSION)
	ln -s /usr/local/digiwash$(VERSION) $(PWD)/build/debian/usr/local/digiwash 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/misc/
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/misc/Exception/
	libtool --mode=install install build/libocfamisc.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libocfanulllog.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libocfasyslog.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/misc.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/OcfaObject.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/misc/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/misc/
	install ../inc/misc/Exception/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/misc/Exception/	
	install -d $(PWD)/build/debian/$(DISTDIR)/schema
	cp ../dist/schema/ocfa.xsd  $(PWD)/build/debian/$(DISTDIR)/schema/
	install -d $(PWD)/build/debian/$(DISTDIR)/etc/
	cp ../dist/etc/motd $(PWD)/build/debian/$(DISTDIR)/etc/
	cp ../dist/etc/profile $(PWD)/build/debian/$(DISTDIR)/.profile
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	cp pkg/debian/post* build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfamisc
	cp ../LICENCE build/debian/usr/share/doc/libocfamisc/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfamisc/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfamisc/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfamisc/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfamisc_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

