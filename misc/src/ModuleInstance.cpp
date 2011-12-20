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
						
#include <misc/ModuleInstance.hpp>
#include <misc/syslog_level.hpp>
#include <misc/OcfaException.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <iconv.h>
#include <errno.h>
#include <netinet/in.h>

using namespace std;
namespace ocfa {
  namespace misc {
    /** Static member for parsing module instance string representations*/
    regex_t *ModuleInstance::_preg = 0;
    /**Initialize the regular expression*/
    regex_t *ModuleInstance::pReg(){
       if (_preg == 0){
         _preg = new regex_t;
	 if (regcomp(_preg,"(.*):(.*):(.*):(.*)",REG_EXTENDED) == 0){
            return _preg;
	 } else {
            return 0;
	 }
       } else {
         return _preg;
       }
    }
    /**Constructor for ModuleInstance using string representation that was created
     * somwhere else from a module instance object */
    ModuleInstance::ModuleInstance(string instanceURI): OcfaObject("ModuleInstance","ocfa"),mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
      regex_t *preg = pReg();
      const int nmatch = 5;
      regmatch_t pmatch[nmatch];
      if (preg != 0){
        //char errstr[128];
        int errcode = 0;
        if ((errcode = regexec(preg, instanceURI.c_str(), nmatch, pmatch, 0)) == 0){
            if (pmatch[1].rm_so != -1){
              mihostname = instanceURI.substr(pmatch[1].rm_so,pmatch[1].rm_eo -pmatch[1].rm_so);
            }
            if (pmatch[2].rm_so != -1){
              mimodulename = instanceURI.substr(pmatch[2].rm_so,pmatch[2].rm_eo -pmatch[2].rm_so);
            }
            if (pmatch[3].rm_so != -1){
              minamespace = instanceURI.substr(pmatch[3].rm_so,pmatch[3].rm_eo -pmatch[3].rm_so);
            }
            if (pmatch[4].rm_so != -1){
              miinstancename = instanceURI.substr(pmatch[4].rm_so,pmatch[4].rm_eo -pmatch[4].rm_so);
            }
        }
        else {
           throw OcfaException("instanceURI (" + instanceURI + ") does not match regular expression for module instance uri",this);
	}
      }
      else {
	throw OcfaException("instanceURI (" + instanceURI + ") parsed against non pressent regular expression",this);
      }
    }
    /** The basic constructor*/ 
    ModuleInstance::ModuleInstance(string host, string moduleName, string nameSpace,
				   string instanceName) : OcfaObject("ModuleInstance","ocfa"),mihostname(host),
				   mimodulename(moduleName),minamespace(nameSpace),miinstancename(instanceName), miport(0){
					   
    }
    /**Copy constructor */
    ModuleInstance::ModuleInstance(ModuleInstance &minst):OcfaObject(minst),mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
	    mihostname=minst.getHostname();
	    mimodulename=minst.getModuleName();
            minamespace=minst.getNameSpace();
	    miinstancename=minst.getInstanceName();
            miport=minst.getPort();
    }
    /**Convenience copy constructor*/
    ModuleInstance::ModuleInstance(const ModuleInstance *minst):OcfaObject("ModuleInstance","ocfa"),mihostname(""),mimodulename(""),minamespace(""),miinstancename(""), miport(0) {
       mihostname=minst->getHostname();
       mimodulename=minst->getModuleName();
       minamespace=minst->getNameSpace();
       miinstancename=minst->getInstanceName();
       miport=minst->getPort();
    }
    /**Destructor*/
    ModuleInstance::~ModuleInstance() { 
    }
    /**Retreive the hostname*/
    string ModuleInstance::getHostname() const {
      return mihostname;
    }
    /**Retreive the module name */
    string ModuleInstance::getModuleName() const {
      return mimodulename;
    }
    /**Retreive the module its namespace */
    string ModuleInstance::getNameSpace() const {
      return minamespace;
    }
    /** Retreive the module its instance name */
    string ModuleInstance::getInstanceName() const {
      return miinstancename;
    }
    void ModuleInstance::setPort(unsigned int port){
      miport = port;
    }
    unsigned int ModuleInstance::getPort() const {
      return miport; 
    } 
    string ModuleInstance::getModuleClass() const {
      return minamespace + string(":") + mimodulename;
    }
    /** Get the string representation of the object*/
    string ModuleInstance::getInstanceURI() const {
      string uri=mihostname + string(":") + mimodulename + string(":") + minamespace + string(":") + miinstancename;
      return uri;
    }
  }
}
