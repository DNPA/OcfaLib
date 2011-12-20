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
#include <DomArgumentIterator.hpp>
using namespace std;
using namespace xercesc;
namespace ocfa {
  namespace evidence {
    DomArgumentIterator::DomArgumentIterator(const DOMNodeList *
				       arguments):
      DomOcfaIterator(arguments) {
	      updateTypeName("DomArgumentIterator");
    } 
    DomArgumentIterator::~DomArgumentIterator() {
    }
    string DomArgumentIterator::getName() const {
      return getAttr("name");
    }
    string DomArgumentIterator::getVal() const {
      return DomOcfaIterator::getVal();
    }
  }
}
