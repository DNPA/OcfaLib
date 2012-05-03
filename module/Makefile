include ../RELEASE.makeinfo
OCFALIB_TOP_DIR=..
#
#The project is the name of the sub project of the washing machine.
#
PROJECT=ocfamodule
INTERFACEDIR=../inc/module
EXTRAINCFLAGS=-I../store/inc
LIBS=
EXTRAINCFLAGS=-I$(BOOSTINCDIR)
include ../global.makeinfo 
GCCFLAGS += $(GCCFLAGS_MODULE)
#GCCFLAGS += $(GCCFLAGS_STRICT)
#GCCFLAGS= -DLINUX $(GCCFLAGS)
#
OBJFILESLIB=$(BUILDDIR)/OcfaModule.lo $(BUILDDIR)/EvidenceTreeWalker.lo

#NOTE: adding $(TREEGRAPHLIB) to the dependencies is a hack. For some reason adding it to the filesystem lib makefile does not work on Ubuntu 11.10
lib$(PROJECT): $(OBJFILESLIB)
	$(LIBTOOL) --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_MODULE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) $(MSGLIB) $(XMLLIB) $(STORELIB) $(TREEGRAPHLIB) ${INCFLAGS}

simpledemo: test/simpledemo.cpp 
	$(LIBTOOL) --mode=link $(CPP) -Wall -I../inc -Iinc test/simpledemo.cpp $(LTLINKFLAGS) -o  simpledemo $(FSLIB) $(XMLLIB) $(MISCLIB) 

installadd: all


dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/module/
	libtool --mode=install install build/libocfamodule.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/module.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/module/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/module/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfamodule
	cp ../LICENCE build/debian/usr/share/doc/libocfamodule/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfamodule/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfamodule/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfamodule/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfamodule_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

