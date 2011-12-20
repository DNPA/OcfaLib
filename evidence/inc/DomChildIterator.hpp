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
						
#ifndef _DOMCHILDITERATOR_
#define _DOMCHILDITERATOR_
#include <evidence/ChildIterator.hpp>
#include <evidence/CoParentIterator.hpp>
#include <DomOcfaIterator.hpp>
#include <string>
#include <xercesc/dom/DOMNodeList.hpp>
namespace ocfa {
  namespace evidence {
    class DomChildIterator:public ChildIterator, public DomOcfaIterator {
    public:
      DomChildIterator(const xercesc::DOMNodeList * childlist,
		       std::string casid);
      DomChildIterator(const DomChildIterator& ia):OcfaIterator(ia),ChildIterator(ia),DomOcfaIterator(ia),cpit(0),mCaseID("") {
          throw misc::OcfaException("No copy allowed of DomChildIterator",this);
      }
      const DomChildIterator& operator=(const DomChildIterator&) {
          throw misc::OcfaException("No assignment allowed for DomChildIterator",this);
      }
      virtual ~DomChildIterator();
		  /**Get the value of the active Child reference */
      string getChildEvidenceID() const;
		 /**Retreive the parentchild relationship name that the child has with respect to the active parent evidence */
      string getChildRelationName() const;
		  /**Get a coparent iterator for this childReference
		    *        *
		    *               * Please note that the pointer returned will remain valid only
		    *                      * during a single run of processEvidence and only as long as
		    *                             * no next() or last() is called on the ChildIterator or its its JobIterator
		    *                                    * */
      CoParentIterator *getCoParentIterator();
    private:
        CoParentIterator * cpit;
        std::string mCaseID;

    };
}}
#endif
