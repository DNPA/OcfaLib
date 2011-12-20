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
						
#ifndef __OCFALOGGER__
#define __OCFALOGGER__
#include "syslog_level.hpp"
#include "ModuleInstance.hpp"
#include "VoidToFunction.hpp"

namespace ocfa {
  namespace misc {
    /** Singleton class used for logging */
    class OcfaLogger:public OcfaObject {
    public:	
      /** Retreive a pointer to the logger  singleton */
      static OcfaLogger *Instance();
      /** The first time baptize is called, the logger will be named according to the module instance info 
       **/
      virtual void baptize(ModuleInstance *modinstance)=0;
      /** Change the minimal loglever at what the logger should log */
      virtual void setLevel(std::string level)=0;
      /** New method to allow logging during process evidence to log the xmlid**/
      virtual void setcontext(std::string context)=0;
      virtual void clearcontext()=0;
      /**
       * changes the log level for a certain prefix if the logger supports it.
       * If the logger does not support it, the general loglevel is changed. 
       */
      virtual void setLevel(std::string level, std::string prefix) = 0;
      /* Fetch the ostream of the logger, that we should use to log to */
      virtual std::ostream& syslog(syslog_level level, const OcfaObject *object)=0;
      virtual std::ostream& syslog(syslog_level level, std::string prefix = "") = 0;
      virtual bool needsStdIO()=0;
      virtual ~OcfaLogger(){};
    protected:
      OcfaLogger();
    private:
      static OcfaLogger *_instance;
    }; 
  } 
}
#endif
