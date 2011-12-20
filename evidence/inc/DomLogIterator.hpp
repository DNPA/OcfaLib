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
						
#ifndef _DOMLOGITERATOR_
#define _DOMLOGITERATOR_
#include <string>
#include <evidence/LogIterator.hpp>
#include <DomOcfaIterator.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
namespace ocfa {
  namespace evidence {
    class DomLogIterator:public DomOcfaIterator, public LogIterator {
    public:
        DomLogIterator(const xercesc::DOMNodeList * loglist);
        virtual ~ DomLogIterator();
	DomLogIterator(const DomLogIterator& dli):OcfaIterator(dli),DomOcfaIterator(dli),LogIterator(dli),logtime(0) {
           throw misc::OcfaException("No copying allowed for DomLogIterator",this);
	}
	const DomLogIterator& operator=(const DomLogIterator&) {
           throw misc::OcfaException("No assignment allowed for DomLogIterator",this);
	   return *this;
	}
        misc::DateTime * getTime();
        misc::syslog_level getPrio() const;
        std::string getLine() const;
    private:
	misc::DateTime * logtime;
    };
}}
#endif
