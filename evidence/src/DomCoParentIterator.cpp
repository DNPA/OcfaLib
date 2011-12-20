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
#include "DomCoParentIterator.hpp"
#include "CoParentImpl.hpp"
using namespace std;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    DomCoParentIterator::DomCoParentIterator(const xercesc::DOMNodeList *
				       coparents,std::string caseid):DomOcfaIterator(coparents),mCaseID(caseid) {
        updateTypeName("DomCoParentIterator");
    } 
    DomCoParentIterator::~DomCoParentIterator() {
    }            
    void DomCoParentIterator::getCoParent(CoParent **newcp) {
      if (*newcp != 0)
	      throw OcfaException("Target of getCoParent not a  NULL pointer",this);
      string evidenceid = getVal();
      string item = getAttr("item");
      string esrc = getAttr("src");
      int jobidint = atoi(getAttr("jobid").c_str());
      string childref = getAttr("rename");
      *newcp = new CoParentImpl(mCaseID ,item,esrc,evidenceid,jobidint);
      (*newcp)->setRelName(childref);
      return;
    }
  }
}
