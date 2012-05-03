include ../RELEASE.makeinfo
OCFALIB_TOP_DIR=..
#
#The project is the name of the sub project of the washing machine.
#
PROJECT=ocfafacade
INTERFACEDIR=../inc/facade
LIBS=
EXTRAINCFLAGS=-I$(BOOSTINCDIR)
include ../global.makeinfo 
GCCFLAGS += $(GCCFLAGS_FACADE)
#GCCFLAGS += $(GCCFLAGS_STRICT)
#GCCFLAGS= -DLINUX $(GCCFLAGS)
#
OBJFILESLIB=$(BUILDDIR)/BaseAccessor.lo $(BUILDDIR)/EvidenceFileAccessor.lo $(BUILDDIR)/EvidenceDeriveAccessor.lo $(BUILDDIR)/TargetAccessor.lo $(BUILDDIR)/KickstartAccessor.lo $(BUILDDIR)/XMLAccessor.lo $(BUILDDIR)/DataStoreModule.lo

lib$(PROJECT): $(OBJFILESLIB)
	$(LIBTOOL) --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_FACADE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) $(MODULELIB) ${INCFLAGS}

installadd: all

dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/facade/
	libtool --mode=install install build/libocfafacade.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/facade.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/ocfa.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/facade/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/facade/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/ocfa-lib
	cp ../LICENCE build/debian/usr/share/doc/ocfa-lib/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/ocfa-lib/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/ocfa-lib/changelog.Debian
	gzip --best build/debian/usr/share/doc/ocfa-lib/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/ocfa-lib_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

