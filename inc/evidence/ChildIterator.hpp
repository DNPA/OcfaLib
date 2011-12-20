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
						
#ifndef _CHILDITERATOR_HPP
#define _CHILDITERATOR_HPP
#include "../misc.hpp"
#include "OcfaIterator.hpp"
#include "CoParentIterator.hpp"
#include <string>

namespace ocfa {
  namespace evidence {
    //The ChildIterator is a class that is accessable AND (RE)INITALIZED by
    //JobIterator::getChildIterator() and is used to iterate over the references
    //to child evidences that were created in a particular job.
    class ChildIterator: virtual public OcfaIterator {
    public:
      /**Get the value of the active Child reference */
      virtual std::string getChildEvidenceID() const =0;
      /**Retreive the parentchild relationship name that the child has with respect to the active parent evidence */
      virtual std::string getChildRelationName() const =0;
      /**Get a coparent iterator for this childReference 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the ChildIterator or its its JobIterator
       * */
      virtual CoParentIterator *getCoParentIterator()=0;
      virtual ~ChildIterator() {};
    };
}}
#endif
