include ../RELEASE.makeinfo
#
#The project is the name of the sub project of the washing machine.
#
#
OCFALIB_TOP_DIR=..
#LIBTOOL=libtool
PROJECT=ocfastore
INTERFACEDIR=../inc/store
EXTRAINCFLAGS=-I$(BOOSTINCDIR)
include ../global.makeinfo
GCCFLAGS += $(GCCFLAGS_STORE)
#GCCFLAGS += $(GCCFLAGS_STRICT)
#GCCFLAGS= -DLINUX $(GCCFLAGS)
OBJFILESLIB=$(BUILDDIR)/AbstractRepository.lo $(BUILDDIR)/ConcreteEvidenceStoreEntity.lo $(BUILDDIR)/FileMetaStoreEntity.lo $(BUILDDIR)/PgRepository.lo $(BUILDDIR)/SimpleRepository.lo $(BUILDDIR)/ConcreteStoreEntity.lo $(BUILDDIR)/PgItem.lo  $(BUILDDIR)/LibCryptDigestPair.lo $(BUILDDIR)/DigestPairFactory.lo $(BUILDDIR)/BlobMetaStoreEntity.lo $(BUILDDIR)/PgBlobRepository.lo  $(BUILDDIR)/PgFileRepository.lo

OBJBASELIB=$(BUILDDIR)/AbstractRepository.lo  $(BUILDDIR)/ConcreteStoreEntity.lo $(BUILDDIR)/ConcreteEvidenceStoreEntity.lo $(BUILDDIR)/FileMetaStoreEntity.lo $(BUILDDIR)/Filename.lo $(BUILDDIR)/LibCryptDigestPair.lo $(BUILDDIR)/DigestPairFactory.lo $(BUILDDIR)/BlobMetaStoreEntity.lo $(BUILDDIR)/PgRepository.lo $(BUILDDIR)/SimpleRepository.lo $(BUILDDIR)/PgItem.lo $(BUILDDIR)/MetaStoreEntity.lo
OBJPGLIBBLOB=$(BUILDDIR)/PgRepository.lo $(BUILDDIR)/SimpleRepository.lo $(BUILDDIR)/PgItem.lo  $(BUILDDIR)/PgBlobRepository.lo  
OBJPGLIBFILE=$(BUILDDIR)/PgRepository.lo $(BUILDDIR)/SimpleRepository.lo $(BUILDDIR)/PgItem.lo $(BUILDDIR)/PgFileRepository.lo


# the libs which should be linked with our object files
#
LIBS+=-lpq -lcrypto $(LIBPQDIR) ../misc/build/libocfamisc.la
INCFLAGS += -I$(INCPQDIR)

# OcfaObject has a special status because it is not in the 
# 
#
# Target which creates an shared library. You will always need a
# library because you want to run your regression tests. 
#
#

all: lib$(PROJECT) pgblob pgfile

lib$(PROJECT): $(OBJBASELIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP)  -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_STORE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJBASELIB) ${INCFLAGS} $(MISCLIB) $(LIBS)

pgblob: $(OBJPGLIBBLOB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_STORE_PG) $(LTLINKFLAGS) -o $(BUILDDIR)/libpgblob.la $(OBJPGLIBBLOB) ${INCFLAGS}

pgfile:	$(OBJPGLIBFILE)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) -version-info $(VERSION_STORE_PG) $(LTLINKFLAGS) -o $(BUILDDIR)/libpgfile.la $(OBJPGLIBFILE) ${INCFLAGS}



# Target that creates the executable for the tests.
#
test: all
	$(LIBTOOL) --tag=CPP --mode=link  $(CPP) -Wall -I../inc -Iinc test/simpledemo.cpp $(LTLINKFLAGS) -o  simpledemo build/libocfamisc.la

installadd: all
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/lib*.la $(INSTALLIB)
	install -d $(INSTALL_BIN)
	cp db/cleanupdb.sh $(INSTALL_BIN)
	cp db/storedb.sql $(INSTALL_BIN)
	cp db/createdb.sh $(INSTALL_BIN)



dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/store/
	libtool --mode=install install build/libocfastore.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libpgblob.la $(PWD)/build/debian$(INSTALLIB)/
	libtool --mode=install install build/libpgfile.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/store.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/store/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/store/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfastore
	cp ../LICENCE build/debian/usr/share/doc/libocfastore/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfastore/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfastore/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfastore/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfastore_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

