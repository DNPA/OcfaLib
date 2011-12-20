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
						
#ifndef _OCFALOGGER
#define _OCFALOGGER
#include <iostream>
#include <fstream>
#include <misc/OcfaLogger.hpp>
#include <misc/syslog_level.hpp>
#include <misc/OcfaException.hpp>
namespace ocfa {
 namespace misc {
  class SimpleLogger: public OcfaLogger{
  public: 
    void baptize(ModuleInstance *minst);
    void setLevel(std::string level);
    void setLevel(std::string level, std::string prefix); 
    void setcontext(std::string context){}
    void clearcontext(){}    
    virtual std::ostream &syslog(syslog_level level, const OcfaObject *object);
    virtual std::ostream &syslog(syslog_level level, std::string prefix = "");
    SimpleLogger();
    SimpleLogger(const SimpleLogger&):OcfaLogger(),prefix(""),marktime(0),cnull(0),clog(0),minlevel(LOG_ERR) {
        throw OcfaException("No copy constructing of SimpleLogger",this);
    }
    bool needsStdIO(){
       return true;
    }
    virtual ~SimpleLogger();
  private:
    const SimpleLogger& operator=(const SimpleLogger&){
       throw OcfaException("No operator= invocation alowed for SimpleLogger",this);
       return *this;
    }
    std::string prefix;
    time_t marktime;
    std::ofstream *cnull;
    std::ostream *clog;
    syslog_level minlevel;
  };
 }
}
#endif
