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
						
#include <SimpleLogger.hpp>
#include <misc/VoidToFunction.hpp>
#include <misc/PolicyLoader.hpp>
#include <misc/OcfaLogger.hpp>
#include <misc/OcfaConfig.hpp>
#include "GlobalMutex.hpp"
//#include </Log4cxxLogger.hpp>
#include <iostream>
#include <iomanip>
typedef BasicConstructor< ocfa::misc::OcfaLogger > CLoggerType;
namespace ocfa {
  namespace misc {
    OcfaLogger *OcfaLogger::_instance = 0;
    OcfaLogger *OcfaLogger::Instance() {
      if (_instance ==0) {
        GlobalMutex automutex();
	_instance = new SimpleLogger();
        if (OcfaConfig::Instance()) {
	  std::string esyslog = OcfaConfig::Instance()->getValue("syslog");
	  _instance->setLevel(esyslog);
          try {	
	    std::string myLib=ocfa::misc::OcfaConfig::Instance()->getValue("loglib");
	    if (myLib == "") {
	      throw(std::string("OcfaLogger::Instance() : No config entry found named for loglib"));
	    }
	    PolicyLoader<CLoggerType> pl(myLib,"createOcfaLogger");
	    CLoggerType *constructor=pl.constructor();
            OcfaLogger *oldlogger=_instance; 
	    _instance = (*constructor)();
            delete oldlogger;
	    _instance->setLevel(esyslog);
	  } catch (...){
            _instance->getLogStream(LOG_ERR) << "Loglib not found. Using simplelogger.\n";
	  }
        }
      }
      return _instance;
    }
    OcfaLogger::OcfaLogger() : OcfaObject("OcfaLogger","ocfa") {

    }
  }
}
