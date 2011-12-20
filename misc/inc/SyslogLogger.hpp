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
#include <string>
#include <misc/OcfaLogger.hpp>
#include <misc/syslog_level.hpp>
#include <misc/OcfaException.hpp>
#include "syslogbuf.hpp"
using namespace std;
namespace ocfa {
 namespace misc {
  class SyslogLogger: public OcfaLogger{
  public: 
    void baptize(ModuleInstance *minst);
    void setLevel(string level);
    void setLevel(std::string level, std::string inPrefix); 
    void setcontext(std::string context){mContext=context;mHasContext=true; }
    void clearcontext(){mHasContext=false;}
    virtual std::ostream &syslog(syslog_level level, const OcfaObject *object);
    virtual std::ostream &syslog(syslog_level level, std::string prefix = "");
    SyslogLogger();
    SyslogLogger(const ocfa::misc::SyslogLogger&):OcfaLogger(),marktime(0),logbufmap(),logstreammap(),mHasContext(false) {
       throw OcfaException("No copy constructing SyslogLoggers",this);
    }
    bool needsStdIO(){return false;}
    virtual ~SyslogLogger();
  private:
    std::string levelString(syslog_level level);
    const SyslogLogger& operator=(SyslogLogger&) {
       throw OcfaException("No assigning from SyslogLoggers",this);
       return *this;
    }
    time_t marktime;
    std::map<pthread_t,syslogbuf *> logbufmap;
    std::map<pthread_t,std::ostream *> logstreammap;
    std::ofstream *cnull;
    syslog_level minlevel;
    bool mHasContext;
    std::string mContext;
  };
 }
}
extern "C" {
	  ocfa::misc::OcfaLogger *createOcfaLogger();
}

#endif
