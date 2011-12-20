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
#include <DomOcfaIterator.hpp>
#include <DomHelper.hpp>
#include <xercesc/util/XMLString.hpp>
using namespace std;
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    DomOcfaIterator::DomOcfaIterator(const DOMNodeList * itobjs):
	    OcfaObject("DomOcfaIterator","evidence"),
	    mCurrent(0),
	    mIndex(0),
            mOItems(itobjs)	    
    {
      updateTypeName("DomOcfaIterator");
      if (mOItems == 0)
	throw
	  OcfaException
	  ("OcfaIterator::OcfaIterator called with NULL DOMNodeList pointer",
	   this);
      if (mOItems->getLength() > 0) {
	mIndex = 0;
	mCurrent = dynamic_cast < DOMElement * >(mOItems->item(mIndex));
      }
      else {
	throw
	  OcfaException
	  ("OcfaIterator::OcfaIterator called with empty DOMNodeList",
	   this);
      }
    }
    DomOcfaIterator::~DomOcfaIterator() {
    }

    size_t DomOcfaIterator::items(string name) const {
      if (mCurrent == NULL) {
	throw OcfaException("OcfaIterator::items called with current=NULL",
			    this);
      }
      DOMNodeList *subitems = DomHelper::getInstance()->getElementsByTagName(mCurrent,name);
      return subitems->getLength();
    }
    size_t DomOcfaIterator::size() const {
       return mOItems->getLength();
    }
    size_t DomOcfaIterator::getIndex() const {
       return mIndex;
    }
    string DomOcfaIterator::getAttr(string name) const {
      if (mCurrent == NULL) {
	throw OcfaException("OcfaIterator::getAttr called with mCurrent=NULL",
			    this);
      }
      string rval=DomHelper::getInstance()->getAttribute(mCurrent,name);
      ocfaLog(LOG_DEBUG,"getAttr("+name+") returned "+rval);
      return rval;
    }

    void DomOcfaIterator::setAttr(string name, string val) {
      DomHelper::getInstance()->setAttribute(mCurrent,name,val);
    }

    string DomOcfaIterator::getVal() const {
      if (mCurrent == NULL) {
	throw OcfaException("OcfaIterator::getVal called with mCurrent=NULL",
			    this);
      }
      char *targval = DomHelper::transcode(mCurrent->getTextContent());
      string argval(targval);
      XMLString::release(&targval);
      return argval;
    }

    DOMNodeList *DomOcfaIterator::getSubItNodeList(string name) const {
      if (mCurrent == NULL) {
	throw OcfaException("OcfaIterator::getSubIt called with mCurrent=NULL",
			    this);
      }
      DOMNodeList *coparents = DomHelper::getInstance()->getElementsByTagName(mCurrent,name);
      if (coparents->getLength() > 0) {
	return coparents;
      }
      else {
	return 0;
      }
    }

    bool DomOcfaIterator::next() {

      if (mOItems->getLength() > (mIndex + 1)) {
	mIndex++;
	mCurrent = dynamic_cast < DOMElement * >(mOItems->item(mIndex));
	return true;
      }
      else {
	return false;
      }
    }
    void DomOcfaIterator::last() {
	mIndex = mOItems->getLength() - 1;
	mCurrent = dynamic_cast < DOMElement * >(mOItems->item(mIndex));
	return;
    }
    xercesc::DOMElement *DomOcfaIterator::getCurrent() const{
       return mCurrent;
    }
  }
}
