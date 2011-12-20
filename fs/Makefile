include ../RELEASE.makeinfo
#
#The project is the name of the sub project of the washing machine.
#
PROJECT=ocfafs
INTERFACEDIR=../inc/fs
LIBS=
NTFSLIBS=-lntfs
OCFALIB_TOP_DIR=..
EXTRAINCFLAGS=-I$(BOOSTINCDIR)
include ../global.makeinfo
GCCFLAGS += $(GCCFLAGS_FS)
#GCCFLAGS += $(GCCFLAGS_STRICT)
#
#The buildFiles define the object files that should be build. When you want to 
# compile a new file, you should add it to this list. Because it is added here, Make will
# automatically start looking for a similar file in the $(SRC) directory. 
#

OBJFILESLIB=$(BUILDDIR)/ProcMountsModuleInfo.lo $(BUILDDIR)/FileSystemModuleInfoFactory.lo 

OBJFILEBASICLIB=$(BUILDDIR)/BasicFsEntity.lo  $(BUILDDIR)/BasicFsConnectedNode.lo  $(BUILDDIR)/BasicFileDump.lo $(BUILDDIR)/FileDumpOfDeletedNode.lo $(BUILDDIR)/FileDumpOfUnalocatedNode.lo $(BUILDDIR)/BasicFsFileSystem.lo $(BUILDDIR)/constructorBasicFsFileSystem.lo

OBJFILEUNIXLIB=$(BUILDDIR)/BasicFsEntity.lo  $(BUILDDIR)/BasicFsConnectedNode.lo  $(BUILDDIR)/BasicFileDump.lo $(BUILDDIR)/FileDumpOfDeletedNode.lo $(BUILDDIR)/FileDumpOfUnalocatedNode.lo $(BUILDDIR)/BasicFsFileSystem.lo $(BUILDDIR)/UnixFileSystem.lo $(BUILDDIR)/UnixConnectedNode.lo

OBJFILESENCASELIB=$(BUILDDIR)/BasicFsEntity.lo  $(BUILDDIR)/BasicFsConnectedNode.lo  $(BUILDDIR)/BasicFileDump.lo $(BUILDDIR)/FileDumpOfDeletedNode.lo $(BUILDDIR)/FileDumpOfUnalocatedNode.lo $(BUILDDIR)/BasicFsFileSystem.lo $(BUILDDIR)/EncaseExportTopNode.lo $(BUILDDIR)/EncaseExportOfFileSystem.lo $(BUILDDIR)/DeletedPseudoNode.lo $(BUILDDIR)/EncaseExportOfVolume.lo $(BUILDDIR)/FileDumpOfSwapPartition.lo $(BUILDDIR)/SystemPseudoNode.lo


#
# Target which creates an shared library. You will always need a
# library because you want to run your regression tests. 
#
#

all: lib$(PROJECT) basic unix encaseexport

lib$(PROJECT): $(OBJFILESLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_FS) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) $(MISCLIB) ${INCFLAGS}

basic: $(OBJFILEBASICLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_FS_BASIC) $(LTLINKFLAGS) -o $(BUILDDIR)/libBasicFsFileSystem.la $(OBJFILEBASICLIB) $(MISCLIB) ${INCFLAGS}

unix: $(OBJFILEUNIXLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_FS_UNIX) $(LTLINKFLAGS) -o $(BUILDDIR)/libUnixFileSystem.la $(OBJFILEUNIXLIB) $(MISCLIB) ${INCFLAGS}

encaseexport: $(OBJFILESENCASELIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_FS_ENCASE) $(LTLINKFLAGS) -o $(BUILDDIR)/libEncaseExport.la $(OBJFILESENCASELIB) $(MISCLIB) ${INCFLAGS}

# Target that creates the executable for the tests.
#
test: all
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) -ggdb $(GCCFLAGS) $(INCFLAGS) -Iinc test/simpledemo.cpp $(LTSLINKFLAGS) -o  simpledemo build/libocfafs.la
	#$(MAKE) -C test

installadd: all
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/libBasicFsFileSystem.la $(INSTALLIB)
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/libEncaseExport.la $(INSTALLIB)
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/libUnixFileSystem.la $(INSTALLIB)



dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/fs/
	libtool --mode=install install build/libocfafs.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libUnixFileSystem.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libBasicFsFileSystem.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libEncaseExport.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/fs.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/fs/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/fs/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfafs
	cp ../LICENCE build/debian/usr/share/doc/libocfafs/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfafs/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfafs/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfafs/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfafs_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

