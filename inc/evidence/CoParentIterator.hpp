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
						
#ifndef _COPARENTITERATOR_HPP
#define _COPARENTITERATOR_HPP
#include "../misc.hpp"
#include "OcfaIterator.hpp"
#include "CoParent.hpp"
#include <string>

//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better
namespace ocfa {
  namespace evidence {
     //The CoParentIterator is a class that is accessable AND (RE)INITALIZED by
     //ChildIterator::getCoParentIterator() and is used to iterate over references
     //to coparent evidences that were involved in the creation of the child evidence.
    class CoParentIterator:virtual public OcfaIterator {
    public:
      virtual void getCoParent(CoParent **cp)=0;
      virtual ~CoParentIterator() {};
    };
}}
#endif
