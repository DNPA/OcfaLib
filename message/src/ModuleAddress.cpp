//The Open Computer Forensics Library
//Copyright (C) KLPD 2003..2006  <ocfa@dnpa.nl>
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
						
#include "ModuleAddress.hpp"
#include <string>
#include <iostream>
#include <unistd.h>
#include <iconv.h>
#include <errno.h>
#include <netinet/in.h>

using namespace std;
using namespace ocfa::misc;

namespace ocfa {
  namespace message {

    /**Constructor for ModuleAddress using string representation that was created
     * somwhere else from a module instance object */
    /** The basic constructor*/ 
    ModuleAddress::ModuleAddress(string host, string moduleName, string nameSpace,
				   string instanceName) : mihostname(host),
				   mimodulename(moduleName),minamespace(nameSpace),miinstancename(instanceName), miport(0){
					   
    }
    /**Copy constructor from a ModuleAddress */
    ModuleAddress::ModuleAddress(const ModuleAddress &minst):mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
	    mihostname=minst.getHostname();
	    mimodulename=minst.getModuleName();
            minamespace=minst.getNameSpace();
	    miinstancename=minst.getInstanceName();
            miport=minst.getPort();
    }

    /* Construct a ModuleAddress from a ModuleInstance */
    ModuleAddress::ModuleAddress(const ModuleInstance &minst):mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
	    mihostname=minst.getHostname();
	    mimodulename=minst.getModuleName();
            minamespace=minst.getNameSpace();
	    miinstancename=minst.getInstanceName();
            miport=minst.getPort();
    }

    ModuleAddress::ModuleAddress(const ModuleInstance *minst):mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
       mihostname=minst->getHostname();
       mimodulename=minst->getModuleName();
       minamespace=minst->getNameSpace();
       miinstancename=minst->getInstanceName();
       miport=minst->getPort();
    }


    /**Convenience copy constructor*/
    ModuleAddress::ModuleAddress(const ModuleAddress *minst):mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
       mihostname=minst->getHostname();
       mimodulename=minst->getModuleName();
       minamespace=minst->getNameSpace();
       miinstancename=minst->getInstanceName();
       miport=minst->getPort();
    }
    /**Destructor*/
    ModuleAddress::~ModuleAddress() { 
    }
    /**Retreive the hostname*/
    string ModuleAddress::getHostname() const {
      return mihostname;
    }
    /**Retreive the module name */
    string ModuleAddress::getModuleName() const {
      return mimodulename;
    }
    /**Retreive the module its namespace */
    string ModuleAddress::getNameSpace() const {
      return minamespace;
    }
    /** Retreive the module its instance name */
    string ModuleAddress::getInstanceName() const {
      return miinstancename;
    }
    void ModuleAddress::setPort(unsigned int port){
      miport = port;
    }
    unsigned int ModuleAddress::getPort() const {
      return miport; 
    } 
    string ModuleAddress::getModuleClass() const {
      return minamespace + string(":") + mimodulename;
    }
    /** Get the string representation of the object*/
    string ModuleAddress::getInstanceURI() const {
      string uri=mihostname + string(":") + mimodulename + string(":") + minamespace + string(":") + miinstancename;
      return uri;
    }
  }
}
