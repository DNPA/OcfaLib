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
#include <evidence/CoParentIterator.hpp>
#include <DomOcfaIterator.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
namespace ocfa {
  namespace evidence {
    class DomCoParentIterator:public DomOcfaIterator, public CoParentIterator {
    public:
	    //JCW:CODEREVIEW:Documentatie
      DomCoParentIterator(const xercesc::DOMNodeList * coparentlist,
			  std::string caseid);
        virtual ~ DomCoParentIterator();
	DomCoParentIterator(const  DomCoParentIterator& cpi):OcfaIterator(cpi), DomOcfaIterator(cpi),CoParentIterator(cpi),mCaseID(""){
           throw misc::OcfaException("Copying of DomCoParentIterator not allowed",this);
	}
	const DomCoParentIterator& operator=(const DomCoParentIterator&) {
           throw misc::OcfaException("Assignment of DomCoParentIterator not allowed",this);
	   return *this;
	}
	virtual void getCoParent(CoParent **cp);
    private:
        std::string mCaseID;
    };
}}
