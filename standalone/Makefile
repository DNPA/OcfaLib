include ../RELEASE.makeinfo
#
#The project is the name of the sub project of the washing machine.
#
#
OCFALIB_TOP_DIR=..
#LIBTOOL=libtool
PROJECT=filemessage
INTERFACEDIR=../inc/message
include ../global.makeinfo
#GCCFLAGS= -DLINUX $(GCCFLAGS)
OBJFILESLIB=$(BUILDDIR)/FileMessage.lo  $(BUILDDIR)/FileMessageBox.lo $(BUILDDIR)/MessageEvent.lo 

# the libs which should be linked with our object files
#

# OcfaObject has a special status because it is not in the 
# 
#
# Target which creates an shared library. You will always need a
# library because you want to run your regression tests. 
#
#

all: lib$(PROJECT) 

lib$(PROJECT): $(OBJFILESLIB)
	$(LIBTOOL) --mode=link $(CPP)  -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) ${INCFLAGS}

test: all $(BUILDDIR)/test.lo
	$(LIBTOOL) --tag=CPP g++ -o $(BUILDDIR)/test $(BUILDDIR)/test.lo $(BUILDDIR)/lib$(PROJECT).la 

