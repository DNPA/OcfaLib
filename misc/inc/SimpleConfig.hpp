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
#include <vector>
#include <string>
#include <OcfaObject.hpp>
#include <misc/OcfaConfig.hpp>
#ifndef included_simpleconfig_hpp
#define included_simpleconfig_hpp

using namespace std;

namespace ocfa {
  namespace misc {
    class SimpleConfig: public OcfaConfig {
    public:
      string getValue(string name,OcfaObject *caller=0) const;
      string getValueByCaller(string name, OcfaObject *caller) const;
       SimpleConfig();
       ~SimpleConfig();
       virtual void baptize(ModuleInstance *modinstance);
    private:
        map < string, string > d_keyvalpairs;
	string mModuleName;
    };
  }
}
#endif
