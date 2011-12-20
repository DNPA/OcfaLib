#
#The project is the name of the sub project of the washing machine.
#
include ../RELEASE.makeinfo
LIBTOOL=libtool
PROJECT=ocfaevidence
OCFALIB_TOP_DIR=..
INTERFACEDIR=../inc/evidence
LIBS=-lxerces-c $(LICONV_IF_NEEDED)
EXTRAINCFLAGS=-I$(BOOSTINCDIR)
include ../global.makeinfo
GCCFLAGS += $(GCCFLAGS_EVIDENCE)
#GCCFLAGS += -Wformat-nonliteral -Wabi -Wcast-qual -Wold-style-cast -Wwrite-strings -Wunreachable-code -Wshadow
# -Waggregate-return 
#GCCFLAGS += $(GCCFLAGS_STRICT)
#
#The buildFiles define the object files that should be build. When you want to 
# compile a new file, you should add it to this list. Because it is added here, Make will
# automatically start looking for a similar file in the $(SRC) directory. 
#
OBJFILESLIB=$(BUILDDIR)/DomTopNode.lo $(BUILDDIR)/DomEvidence.lo $(BUILDDIR)/JobInfo.lo $(BUILDDIR)/CoParent.lo $(BUILDDIR)/CoParentImpl.lo $(BUILDDIR)/DomOcfaIterator.lo $(BUILDDIR)/DomCoParentIterator.lo $(BUILDDIR)/DomChildIterator.lo $(BUILDDIR)/DomMetaIterator.lo  $(BUILDDIR)/DomLogIterator.lo  $(BUILDDIR)/DomArgumentIterator.lo  $(BUILDDIR)/DomJobIterator.lo $(BUILDDIR)/DomActiveJob.lo  $(BUILDDIR)/DomExtendableEvidence.lo $(BUILDDIR)/EvidenceFactory.lo $(BUILDDIR)/DomEvidenceFactory.lo $(BUILDDIR)/OcfaErrorHandler.lo $(BUILDDIR)/DomHelper.lo

# Target which creates an shared library. You will always need a
# library because you want to run your regression tests. 
#
#

lib$(PROJECT): $(OBJFILESLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_EVIDENCE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) $(MISCLIB) ${INCFLAGS}

static: $(OBJFILESLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) -static ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) $(MISCLIB) ${INCFLAGS}

#
# Target that creates the executable for the tests.
#
test: all
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) -Wall -I../inc -Iinc test/simpledemo.cpp -o simpledemo $(LTLINKFLAGS) build/libocfaevidence.la ../misc/build/libocfamisc.la

installadd: all


dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/evidence/
	libtool --mode=install install build/libocfaevidence.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/evidence.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/evidence/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/evidence/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfaevidence
	cp ../LICENCE build/debian/usr/share/doc/libocfaevidence/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfaevidence/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfaevidence/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfaevidence/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfaevidence_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

