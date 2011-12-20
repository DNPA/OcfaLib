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
						
#include <SyslogLogger.hpp>
#include <GlobalMutex.hpp>
#include <misc/OcfaException.hpp>
#include <misc/OcfaConfig.hpp>
#include <misc/OcfaLogger.hpp>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <syslog.h>
using namespace std;
namespace ocfa {
  namespace misc {
	SyslogLogger::SyslogLogger():OcfaLogger(),marktime(0),logbufmap(),logstreammap(),cnull(0),minlevel(static_cast<syslog_level>(LOG_DEBUG)) {
	    GlobalMutex automutex();
	    updateTypeName("SyslogLogger");
	    //logstream=new ostream(&logbuf);
	    openlog("unbaptized",LOG_PID,LOG_USER);
	    cnull=new std::ofstream("/dev/null");
	    if (!cnull->is_open()) {
	       cnull=new std::ofstream("NULL"); //Untested, windows null device
	       if (!cnull->is_open()) {
	             throw OcfaException("Unable to open /dev/null for writing",this);
	       }
	    }
	}
	void SyslogLogger::baptize(ModuleInstance *minst) {
	    ocfaLog(static_cast<ocfa::misc::syslog_level>(LOG_DEBUG),"SyslogLogger::baptize");
	    GlobalMutex automutex();
	    closelog();
            string prefix=minst->getNameSpace() +"::" + minst->getModuleName();
	    char *buffer=static_cast<char *>(calloc(1,prefix.size()+2));
	    strncpy(buffer,prefix.c_str(),prefix.size());
	    openlog(buffer,LOG_PID,LOG_USER);
	}
	SyslogLogger::~SyslogLogger() {
	   ocfaLog(static_cast<ocfa::misc::syslog_level>(LOG_DEBUG),"SyslogLogger::~SyslogLogger");
	   throw OcfaException("SyslogLogger can not be deleted as this breaks the tests",this);
	}
	void SyslogLogger::setLevel(std::string esyslog) {
            ocfaLog(static_cast<syslog_level>(LOG_NOTICE),"SyslogLogger::setLevel called");
	    if (esyslog == "debug")
                     minlevel = static_cast<syslog_level>(LOG_DEBUG);
            else if (esyslog == "info")
                     minlevel = static_cast<syslog_level>(LOG_INFO);
            else if (esyslog == "notice")
                     minlevel = static_cast<syslog_level>(LOG_NOTICE);
            else if (esyslog == "warning")
                     minlevel = static_cast<syslog_level>(LOG_WARNING);
            else if (esyslog == "err")
                     minlevel = static_cast<syslog_level>(LOG_ERR);
            else if (esyslog == "crit")
                     minlevel = static_cast<syslog_level>(LOG_CRIT);
            else if (esyslog == "alert")
                     minlevel = static_cast<syslog_level>(LOG_ALERT);
            else if (esyslog == "emerg")
                     minlevel = static_cast<syslog_level>(LOG_EMERG);
            else {
                     minlevel=static_cast<syslog_level>(LOG_NOTICE);
                     ocfaLog(static_cast<syslog_level>(LOG_ERR),"Unknown syslog level: " + esyslog);
            }											    
	}

        void SyslogLogger::setLevel(string inLevel, string ){
          setLevel(inLevel);
        }
        
	std::string SyslogLogger::levelString(syslog_level level) {
           switch (level) {
		   case LOG_DEBUG: return "DEBUG";
		   case LOG_INFO: return "INFO";
		   case LOG_NOTICE: return "NOTICE";
		   case LOG_WARNING: return "WARNING";
		   case LOG_ERR: return "ERROR";
		   case LOG_CRIT: return "CRITICAL";
		   case LOG_ALERT: return "ALERT";
		   case LOG_EMERG: return "EMERGENCY";
		   default: return "BOGUS";
	   }
	}
	
        ostream & SyslogLogger::syslog(syslog_level level, const OcfaObject *inObject) {
	     if (level <= minlevel) {
    		string prefix="[" + levelString(level) + "]" + inObject->getClassNameSpace() + ":" + inObject->getClassName() + " ";
                if (mHasContext) {
                   prefix += std::string("{context=") + mContext + std::string("} ");
                }
		int ilevel=static_cast<int>(level);
		if ( logstreammap.find(pthread_self()) == logstreammap.end()) {
                      logbufmap[pthread_self()]=new syslogbuf();
		      logstreammap[pthread_self()]=new ostream(logbufmap[pthread_self()]);
		}
    		logbufmap[pthread_self()]->conf(ilevel, prefix.c_str());
    		return *(logstreammap[pthread_self()]);
	     } else {
                return *cnull;
	     }
  	} 

  	ostream & SyslogLogger::syslog(syslog_level level, string inGivenPrefix){
	  int ilevel=static_cast<int>(level);
	  if (ilevel <= minlevel) {
	    if ( logstreammap.find(pthread_self()) == logstreammap.end()) {
	           logbufmap[pthread_self()]=new syslogbuf();
                   logstreammap[pthread_self()]=new ostream(logbufmap[pthread_self()]);
            }
            string prefix=string("[") + levelString(level) + "]" + inGivenPrefix;
            if (mHasContext) {
                   prefix += std::string("{context=") + mContext + std::string("} ");
            }
            logbufmap[pthread_self()]->conf(ilevel,prefix.c_str());	  
  	    return *(logstreammap[pthread_self()]);
	  }
	  else {
               return *cnull;
	  }
  	}
  }
}

ocfa::misc::OcfaLogger *createOcfaLogger(){
	  return new ocfa::misc::SyslogLogger();
}

