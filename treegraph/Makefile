include ../RELEASE.makeinfo
#
#The project is the name of the sub project of the washing machine.
#
PROJECT=ocfatreegraph
INTERFACEDIR=../inc/treegraph
LIBS=
OCFALIB_TOP_DIR=..
include ../global.makeinfo
GCCFLAGS += $(GCCFLAGS_TG)
INCFLAGS += -I $(BOOSTINCDIR) 
#GCCFLAGS += $(GCCFLAGS_STRICT)
#
#The buildFiles define the object files that should be build. When you want to 
# compile a new file, you should add it to this list. Because it is added here, Make will
# automatically start looking for a similar file in the $(SRC) directory. 
#

OBJFILESLIB=$(BUILDDIR)/TreeGraphModuleLoader.lo $(BUILDDIR)/NodeDataInterface.lo $(BUILDDIR)/NodeDirInterface.lo $(BUILDDIR)/InvalidNode.lo

all: lib$(PROJECT) 

lib$(PROJECT): $(OBJFILESLIB)
	$(LIBTOOL) --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_TREEGRAPH) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) $(MISCLIB) ${INCFLAGS}

installadd:
	echo No aditional installs for treegraph lib

dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/treegraph/
	libtool --mode=install install build/libocfatreegraph.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/treegraph.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/treegraph/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/treegraph/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfatreegraph
	cp ../LICENCE build/debian/usr/share/doc/libocfatreegraph/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfatreegraph/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfatreegraph/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfatreegraph/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfatreegraph_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

