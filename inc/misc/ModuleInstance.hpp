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
						
#ifndef _OCFA_MODINST_
#define _OCFA_MODINST_
#include <string>
#include <regex.h> 
#include "../OcfaObject.hpp"
namespace ocfa{
  namespace misc {
    /*
     * A class for holding the base module instance identification 
     * */
    class ModuleInstance:public OcfaObject {
    public:
  
      /** Copy constructor */
      ModuleInstance(ModuleInstance & mi);
      /** Sort of copy constructor with pointer, for convenience of module builder */
      ModuleInstance(const ModuleInstance * mi);
      /** Constructor that is used to construct a ModuleInstance from messages (sender) */
      ModuleInstance(std::string instanceURI);
      /** The basic constuctor for ModuleInstance */
      ModuleInstance(std::string host, std::string moduleName, std::string nameSpace,
		     std::string instanceName);
      /**Destructor for ModuleInstance */
      ~ModuleInstance();
      /** Retreive the hostname or/ip of the system the module is running on */
      std::string getHostname() const;
      /** Retreive the name of the module*/
      std::string getModuleName() const;
      /** Retreive the namespace the module is running in */
      std::string getNameSpace() const;
      /** Retrieve the name of the particular instance of the module that makes 
       * module instances unique even if multiple instances of the smae module
       * are running on the same machine */
      std::string getInstanceName() const;
      /** Retreive a string representation of the ModuleInstance that is usable
       * in messages*/
      std::string getModuleClass() const;
      std::string getInstanceURI() const;
      unsigned int getPort() const;
      void setPort(unsigned int port);
      static regex_t *pReg();
    protected:

    private: 
      std::string mihostname;
      std::string mimodulename;
      std::string minamespace;
      std::string miinstancename;
      unsigned int miport;
      static regex_t *_preg; 
    };
  }
}
#endif
