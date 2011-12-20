include ../RELEASE.makeinfo
#
#The project is the name of the sub project of the washing machine.
#
# Make sure ACEROOT points to the root of your ACE installation
#ACEROOT=~/OcfaLib/message/thirdparty/ACE_wrappers
OCFALIB_TOP_DIR=..
#LIBTOOL=libtool
PROJECT=ocfamessage
INTERFACEDIR=../inc/message
#EXTRAINCFLAGS=-I $(ACEROOT)
EXTRAINCFLAGS=-I$(ACEINCDIR) -I$(BOOSTINCDIR) 
include ../RELEASE.makeinfo
include ../global.makeinfo
GCCFLAGS += $(GCCFLAGS_MSG)
#GCCFLAGS += $(GCCFLAGS_MSG)
GCCFLAGS += -DACE_LACKS_SYSLOG_H -D_REENTRANT



#RJM:CODEREVIEW OBJFILESLIB=$(BUILDDIR)/CustomMessageBox.lo $(BUILDDIR)/ConcreteMessageBox.lo $(BUILDDIR)/ModuleAddress.lo $(BUILDDIR)/ConcreteMessage.lo $(BUILDDIR)/MessageBox.lo $(BUILDDIR)/CastStrategy.lo $(BUILDDIR)/MessageWrapper.lo $(BUILDDIR)/OcfaStreamHandler.lo
OBJFILESLIB=$(BUILDDIR)/XMLWrapperConverter.lo $(BUILDDIR)/DomHelper.lo $(BUILDDIR)/OcfaErrorHandler.lo $(BUILDDIR)/CustomMessageBox.lo $(BUILDDIR)/MessagingEndPoint.lo $(BUILDDIR)/ConcreteMessage.lo $(BUILDDIR)/MessageBox.lo $(BUILDDIR)/CastStrategy.lo $(BUILDDIR)/MessageWrapper.lo $(BUILDDIR)/OcfaStreamHandler.lo $(BUILDDIR)/OcfaReactorTask.lo $(BUILDDIR)/ReceiveSockHandler.lo
#RJM:CODEREVIEW OBJCLIENTLIB=$(BUILDDIR)/ClientMessageBox.lo
#RJM:CODEREVIEW OBJSERVERLIB=$(BUILDDIR)/ServerMessageBox.lo
OBJCLIENTLIB=$(BUILDDIR)/ConnectMessagingEndPoint.lo
OBJSERVERLIB=$(BUILDDIR)/AcceptMessagingEndPoint.lo

# the libs which should be linked with our object files
#
LIBS=-lpthread -lxerces-c ../misc/build/libocfamisc.la $(LIBLDL) -L/usr/local/lib -lACE

# OcfaObject has a special status because it is not in the 
# 
#
# Target which creates an shared library. You will always need a
# library because you want to run your regression tests. 
#
#

all: lib$(PROJECT) client server

lib$(PROJECT): $(OBJFILESLIB) 
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) -rpath $(INSTALLIB) -release $(RELEASE) -DACE_LACKS_SYSLOG_H $(LTLINKFLAGS) -o $(BUILDDIR)/lib$(PROJECT).la $(OBJFILESLIB) -I$(ACEROOT) ${INCFLAGS} ${LIBS}

client: $(OBJCLIENTLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/libConnectMessagingEndPoint.la $(OBJCLIENTLIB) #RJM:CODEREVIEW
	#RJM:CODEREVIEW$(LIBTOOL) --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/libClientMessageBox.la $(OBJCLIENTLIB)
	 

server: $(OBJSERVERLIB)
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/libAcceptMessagingEndPoint.la $(OBJSERVERLIB)
	#RJM:CODEREVIEW $(LIBTOOL) --mode=link $(CPP) ${LIBS} -rpath $(INSTALLIB) -release $(RELEASE) $(LTLINKFLAGS) -o $(BUILDDIR)/libServerMessageBox.la$(OBJSERVERLIB)
# Target that creates the executable for the tests.
#
test: all
	$(LIBTOOL) --tag=CPP --mode=link $(CPP) $(GCCFLAGS) -Wall -I../inc -Iinc test/simpledemo.cpp $(LTLINKFLAGS) -o  simpledemo build/libocfamessage.la ../misc/build/libocfamisc.la

installadd: all
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/libConnectMessagingEndPoint.la $(INSTALLIB)
	$(LIBTOOL) --mode=install cp $(BUILDDIR)/libAcceptMessagingEndPoint.la $(INSTALLIB)
	# $(LIBTOOL) --mode=install cp $(BUILDDIR)/libClientMessageBox.la $(INSTALLIB)
	# $(LIBTOOL) --mode=install cp $(BUILDDIR)/libServerMessageBox.la $(INSTALLIB)



dpkg: lib$(PROJECT) 
	install -d $(PWD)/build/debian/$(INSTALLIB)
	install -d $(PWD)/build/debian/$(OCFAINCINSTDIR)/message/
	libtool --mode=install install build/libocfamessage.la $(PWD)/build/debian/$(INSTALLIB)/
	libtool --mode=install install build/libAcceptMessagingEndPoint.la $(PWD)/build/debian$(INSTALLIB)/
	libtool --mode=install install build/libConnectMessagingEndPoint.la $(PWD)/build/debian/$(INSTALLIB)/
	install ../inc/message.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/
	install ../inc/message/*.hpp $(PWD)/build/debian/$(OCFAINCINSTDIR)/message/	
	install -d build/debian/DEBIAN
	cp pkg/debian/control build/debian/DEBIAN/
	install -d build/debian/usr/share/doc/libocfamessage
	cp ../LICENCE build/debian/usr/share/doc/libocfamessage/copyright
	echo "See ocfa.sourceforge.net for details" > build/debian/usr/share/doc/libocfamessage/changelog
	echo "See ocfa.sourceforge.net for details" >  build/debian/usr/share/doc/libocfamessage/changelog.Debian
	gzip --best build/debian/usr/share/doc/libocfamessage/*
	cd build;fakeroot dpkg-deb --build debian
	install -d ../debian
	mv build/debian.deb ../debian/libocfamessage_$(RELEASE)_amd64.deb
	rm -rf build/debian
	

