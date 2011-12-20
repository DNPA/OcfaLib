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
#include <misc/OcfaException.hpp>
#include <misc/OcfaConfig.hpp>
#include <iostream>
#include <fstream>
using namespace std;
namespace ocfa {
 namespace misc {
	SimpleLogger::SimpleLogger():OcfaLogger(),prefix(""),marktime(0),cnull(0),clog(0),minlevel(LOG_NOTICE) {
	    updateTypeName("SimpleLogger");
	    minlevel=LOG_NOTICE;
	    prefix="";
	    cnull=new std::ofstream("/dev/null");
	    
	    (*cnull) << "writer" << endl;
	    
	    //  exit (0);
	    if (!cnull->is_open()) {
	      cnull=new std::ofstream("NULL"); //Untested, windows null device
	      if (!cnull->is_open()) {
		//cerr << "throwing exception" << endl;
		//exit(0);
	        throw OcfaException("Unable to open /dev/null for writing",this);
	      }
	    }	  
	    clog = &cerr;	      
            minlevel=LOG_INFO;
	}
	void SimpleLogger::baptize(ModuleInstance *minst) {
	    ocfaLog(LOG_DEBUG,"SimpleLogger::baptize");
            if (prefix == "") {
	       ocfaLog(LOG_DEBUG,"SimpleLogger::baptize 1st time is 0k");
               prefix="("+minst->getNameSpace() +")::" + minst->getModuleName();
	    } else {
               throw OcfaException("Can not baptize the logger twice",this);
	    }
	    ocfaLog(LOG_DEBUG,"Fetching syslog level from config");
	    string esyslog = OcfaConfig::Instance()->getValue("syslog",this);
	    ocfaLog(LOG_DEBUG,"Setting loggin level for logger");
	    setLevel(esyslog);
	    ocfaLog(LOG_DEBUG,"SimpleLogger::baptize done");
	}
	SimpleLogger::~SimpleLogger() {
	   //ocfaLog(LOG_NOTICE,"SimpleLogger::~SimpleLogger (screw the tests)");
	   //throw OcfaException("SimpleLogger can not be deleted as this breaks the tests",this);
	}
	void SimpleLogger::setLevel(std::string esyslog) {
	  if (esyslog == "debug")
		  minlevel = LOG_DEBUG;
	  else if (esyslog == "info")
		  minlevel = LOG_INFO;
	  else if (esyslog == "notice")
		  minlevel = LOG_NOTICE;
	  else if (esyslog == "warning")
		  minlevel = LOG_WARNING;
	  else if (esyslog == "err")
		  minlevel = LOG_ERR;
	  else if (esyslog == "crit")
		  minlevel = LOG_CRIT;
	  else if (esyslog == "alert")
		  minlevel = LOG_ALERT;
	  else if (esyslog == "emerg")
		  minlevel = LOG_EMERG;
	  else {
               minlevel=LOG_NOTICE;
	       ocfaLog(LOG_ERR,"Unknown syslog level: " + esyslog); 
	  }
	}
	
  void SimpleLogger::setLevel(string inLevel, string ){

    setLevel(inLevel);
  }
  ostream & SimpleLogger::syslog(syslog_level level, const OcfaObject *inObject) {
    
    return syslog(level, inObject->getClassNameSpace() + ":" + inObject->getClassName());
  } 

  ostream & SimpleLogger::syslog(syslog_level level, string inGivenPrefix){

    if (level <= minlevel) {
      time_t now=time(NULL);
      string usedprefix=prefix;
      if (usedprefix=="") usedprefix="([undef]):[undef]";
      if ((now != marktime) && (prefix != "")) {
	(*clog) << usedprefix << ": MARK  " << ctime(&now) << endl;
	marktime=now;
      }
      (*clog) << usedprefix << inGivenPrefix << ": ";
      return *clog;
    } else {
      return *cnull;
    }

  }
 } 
}

