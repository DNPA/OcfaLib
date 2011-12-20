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

#include "misc/MetaUtil.hpp"
#include "misc/OcfaLogger.hpp"

namespace ocfa {
  namespace misc {
    namespace metautil {
       void addMetaToMap(std::map < std::string, misc::MetaValue * > *metamap,std::string key, misc::MetaValue *val){    
          if (metamap) {
            std::map < std::string, misc::MetaValue * >::iterator found=(*metamap).find(key);  
            if (found != (*metamap).end()) {          
              OcfaLogger::Instance()->syslog(LOG_DEBUG) << "addMetaToMap: deleting old vallue assigned to " << key << std::endl;
              delete found->second;
            }
            (*metamap)[key] = val;     
          }    
          return;
       }
    }
  }
}

