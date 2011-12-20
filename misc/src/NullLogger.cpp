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
						
#include <NullLogger.hpp>
#include <misc/OcfaException.hpp>
#include <misc/OcfaConfig.hpp>
#include <misc/OcfaLogger.hpp>
#include <iostream>
#include <fstream>
using namespace std;
namespace ocfa {
  namespace misc {
	NullLogger::NullLogger():OcfaLogger(),marktime(0),logbufmap(),logstreammap() {
	    updateTypeName("NullLogger");
	}
	void NullLogger::baptize(ModuleInstance *) {
	}
	NullLogger::~NullLogger() {
	   throw OcfaException("NullLogger can not be deleted as this breaks the tests",this);
	}
	void NullLogger::setLevel(std::string ) {
	}

        void NullLogger::setLevel(string , string ){
        }
    
	
        ostream & NullLogger::syslog(syslog_level , const OcfaObject *) {
		if ( logstreammap.find(pthread_self()) == logstreammap.end()) {
                      logbufmap[pthread_self()]=new nullbuf();
		      logstreammap[pthread_self()]=new ostream(logbufmap[pthread_self()]);
		}
    		return *(logstreammap[pthread_self()]);
  	} 

  	ostream & NullLogger::syslog(syslog_level , string ){
	    if ( logstreammap.find(pthread_self()) == logstreammap.end()) {
	           logbufmap[pthread_self()]=new nullbuf();
                   logstreammap[pthread_self()]=new ostream(logbufmap[pthread_self()]);
            }
  	    return *(logstreammap[pthread_self()]);
  	}
  }
}

ocfa::misc::OcfaLogger *createOcfaLogger(){
	  return new ocfa::misc::NullLogger();
}

