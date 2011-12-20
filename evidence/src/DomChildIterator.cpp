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
#include "misc.hpp"
#include <DomChildIterator.hpp>
#include <DomCoParentIterator.hpp>
using namespace std;
using namespace xercesc;
namespace ocfa {
  namespace evidence {
    DomChildIterator::DomChildIterator(const DOMNodeList *
				 childs,std::string caseid):DomOcfaIterator(childs),cpit(0),
      mCaseID(caseid) {
	      cpit=0;
	      updateTypeName("DomChildIterator");
    } 
    DomChildIterator::~DomChildIterator() {
      if (cpit != NULL) {
	delete cpit;
	cpit = 0;
      }
    }
    string DomChildIterator::getChildEvidenceID() const {
      return getAttr("evidenceid");
    }
    string DomChildIterator::getChildRelationName() const {
      return getAttr("relname");
    }
    CoParentIterator *DomChildIterator::getCoParentIterator() {
      if (cpit != NULL) {
	delete cpit;
	cpit = NULL;
      }
      xercesc::DOMNodeList *coparents = getSubItNodeList("coparent");
      if (coparents == 0)
	return 0;
      cpit = new DomCoParentIterator(coparents,mCaseID);
      return cpit;
    }
  }
}
