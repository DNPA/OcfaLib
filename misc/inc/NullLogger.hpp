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
						
#ifndef _OCFALOGGERSYSLOG
#define _OCFALOGGERSYSLOG
#include <iostream>
#include <fstream>
#include <misc/OcfaLogger.hpp>
#include <misc/syslog_level.hpp>
#include <misc/OcfaException.hpp>
#include "nullbuf.hpp"
using namespace std;
namespace ocfa {
 namespace misc {
  class NullLogger: public OcfaLogger{
  public: 
    void baptize(ModuleInstance *minst);
    void setLevel(string level);
    void setLevel(std::string level, std::string inPrefix); 
    void setcontext(std::string context){ }
    void clearcontext(){}
    virtual std::ostream &syslog(syslog_level level, const OcfaObject *object);
    virtual std::ostream &syslog(syslog_level level, std::string prefix = "");
    NullLogger();
    NullLogger(const ocfa::misc::NullLogger&):OcfaLogger(),marktime(0),logbufmap(),logstreammap() {
       throw OcfaException("No copy constructing NullLoggers",this);
    }
    bool needsStdIO(){
       return false;
    }
    virtual ~NullLogger();
  private:
    const NullLogger& operator=(NullLogger&) {
       throw OcfaException("No assigning from NullLoggers",this);
       return *this;
    }
    time_t marktime;
    std::map<pthread_t,nullbuf *> logbufmap;
    std::map<pthread_t,std::ostream *> logstreammap;
  };
 }
}
extern "C" {
	  ocfa::misc::OcfaLogger *createOcfaLogger();
}

#endif
