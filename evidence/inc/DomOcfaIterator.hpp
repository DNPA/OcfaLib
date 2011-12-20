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
						
#ifndef _DOMOCFAITERATOR_
#define _DOMOCFAITERATOR_
#include <misc/OcfaException.hpp>
#include <evidence/OcfaIterator.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMElement.hpp>
namespace ocfa {
  namespace evidence {
    class DomOcfaIterator:virtual public OcfaIterator, public OcfaObject {
    public:
			  /**Try to proceed to the next item, returns false on failure
			   *        *
			   *               * Please note that using this method WILL invalidate pointers that
			   *                      * were aquired from the iterator or one of its sibling iterators.*/
      virtual bool next();
			  /**Try to proceed to the last item, returns false on failure
			    *        *
			    *               * Please note that using this method WILL invalidate pointers that
			    *                      * were aquired from the iterator or one of its sibling iterators.*/
      virtual void last();
    protected:
      DomOcfaIterator(const xercesc::DOMNodeList * nodes);
      const DomOcfaIterator& operator=(const DomOcfaIterator&) {
              throw misc::OcfaException("No assignment allowed for DomOcfaIterator",this);
	      return *this;
      }
      virtual ~ DomOcfaIterator();
      size_t items(string name) const;
      string getAttr(string name) const;
      void setAttr(string name, string val);
      string getVal() const;
      size_t size() const;
      size_t getIndex() const;
        xercesc::DOMNodeList * getSubItNodeList(string name) const;
        xercesc::DOMElement * getCurrent() const;
      DomOcfaIterator(const DomOcfaIterator& doi):OcfaIterator(doi),OcfaObject(doi),mCurrent(0),mIndex(0),mOItems(0) {
         throw misc::OcfaException("No copying allowed for DomOcfaIterator",this);
      }
    private:
      xercesc::DOMElement * mCurrent;
      size_t mIndex;
      //JCW:CODEREVIEW: Naamgeving!
      const xercesc::DOMNodeList * mOItems;
    };
}}
#endif
