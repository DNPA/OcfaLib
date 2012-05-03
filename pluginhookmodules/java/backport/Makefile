

VERSION=0.3
PREFIX=/usr/local/ocfa$(VERSION)
INSTALLIB=$(PREFIX)/lib
PROJECT=javamodule
SRCDIR=src
BUILDDIR=build
INCDIR=inc -I/usr/include/pgsql/ -I../../ipc/arch/klpd/inc -I/usr/local/pgsql/include/ -I../../ipc/inc -I/usr/java/jdk1.5.0_01/include/ -Iinc
LIBNAME=$(PROJECT)
LIBFILE=lib$(LIBNAME).so
LIBS=-ljava

GCCFLAGS=-Wall -pedantic-errors -Wno-long-long
DISTDIR=../../dist
DISTCLASSDIR=$(DISTDIR)/javaclasses
OBJFILES=$(BUILDDIR)/JavaDissector.lo $(BUILDDIR)/JavaExtractor.lo $(BUILDDIR)/JavaComponent.lo $

all:  $(OBJFILES)
	$(LIBTOOL) --mode=link $(CPP) $(LIBS) -rpath $(INSTALLIB) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILES) 


$(BUILDDIR)/%.lo: $(SRCDIR)/%.cpp
	if [ ! -d $(BUILDDIR) ]; then mkdir $(BUILDDIR);fi
	$(LIBTOOL) --mode=compile $(CPP) -g -c $(GCCFLAGS) -I$(INCDIR) -o $@ $<



javadissector: ../../ipc/build/libocfa.la $(BUILDDIR)/JavaDissector.lo
	$(LIBTOOL) --mode=link $(CPP) -g $(LIBS) -o $(BUILDDIR)/JavaDissector -L/usr/java/jdk1.5.0_01/jre/lib/i386 ../../ipc/build/libocfa.la $(BUILDDIR)/JavaDissector.lo 

javaextractor: ../../ipc/build/libocfa.la $(BUILDDIR)/JavaExtractor.lo $(BUILDDIR)/JavaComponent.lo
	$(LIBTOOL) --mode=link $(CPP) -g $(LIBS) -o $(BUILDDIR)/JavaExtractor -L/usr/java/jdk1.5.0_01/jre/lib/i386 ../../ipc/build/libocfa.la $(BUILDDIR)/JavaExtractor.lo $(BUILDDIR)/JavaComponent.lo

clean:
	if [ -d doc/generated ]; then rm -r doc/generated; fi
	$(LIBTOOL) rm  $(BUILDDIR)/*.lo

install: all javastuff
	if [ ! -d $(DISTCLASSDIR) ]; then mkdir $(DISTCLASSDIR);fi
	cp -r $(BUILDDIR)/ocfa $(DISTCLASSDIR)

uninstall:
	rm -r $(INSTALLLIB)

javastuff: $(SRCDIR)/ocfa/Dissector.java $(SRCDIR)/ocfa/Extractor.java
	javac $(SRCDIR)/ocfa/Dissector.java -d $(BUILDDIR)
	javac $(SRCDIR)/ocfa/Extractor.java -d $(BUILDDIR)

