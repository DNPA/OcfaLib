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
						
#include <string>
#include <iostream>
#include <unistd.h>
#include <map>
#include <misc.hpp>
#include <DomLogIterator.hpp>
using namespace std;
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    DomLogIterator::DomLogIterator(const DOMNodeList *
			     loglines):
      DomOcfaIterator(loglines), logtime(NULL) {
	      updateTypeName("DomLogIterator");
    } 
    DomLogIterator::~DomLogIterator() {
      if (logtime != 0) {
	delete logtime;
	logtime = 0;
      }
    }
    DateTime *DomLogIterator::getTime() {
      if (logtime != 0) {
	delete logtime;
	logtime = 0;
      }
      logtime = new DateTime(atol(getAttr("time").c_str()), "OCFA");
      return logtime;
    }
    syslog_level DomLogIterator::getPrio() const {
      string prio = getAttr("prio");
      if (prio == string("debug"))
	  return LOG_DEBUG;
      if (prio == string("info"))
	  return LOG_INFO;
      if (prio == string("notice"))
	  return LOG_NOTICE;
      if (prio == string("warning"))
	  return LOG_WARNING;
      if (prio == string("err"))
	  return LOG_ERR;
      if (prio == string("crit"))
	  return LOG_CRIT;
      if (prio == string("alert"))
	  return LOG_ALERT;
      if (prio == string("emerg"))
	  return LOG_EMERG;
        return LOG_NOTICE;
    }
    string DomLogIterator::getLine() const {
      return getVal();
    }
  }
}
