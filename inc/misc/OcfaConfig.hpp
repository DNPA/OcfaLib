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
						
#include <map>
#include <string>
#include "../OcfaObject.hpp"
#include "ModuleInstance.hpp"
#ifndef included_config_hpp
#define included_config_hpp
namespace ocfa {

  namespace misc {
    /** Singleton class for retreiving configuration information from a config file */
    class OcfaConfig: public OcfaObject {
    public:
      /** Fetch a handle to the OcfaConfig instance */
      static OcfaConfig *Instance();
      /** This method is used to fetch a particular entry from the config file.
       *  If the entry is not found in the named section, than this method will
       *  return the value in the default section instead.*/
      virtual std::string getValue(std::string name,OcfaObject *caller=0) const=0;
      /** This method does the same as getValue, except that it does not default
       * when the value is not found. */
      virtual std::string getValueByCaller(std::string name,OcfaObject *caller=0) const = 0;
      /** The first time baptize is called, the config will be named according to the module instance info*/
      virtual void baptize(ModuleInstance *modinstance)=0; 
      virtual ~OcfaConfig() {};
    protected:
      OcfaConfig();
    private:
      static OcfaConfig *_instance;
    };
  }
}
#endif
