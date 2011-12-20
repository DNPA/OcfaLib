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
						
#ifndef _METAITERATOR_HPP
#define _METAITERATOR_HPP
#include "../misc.hpp"
#include "OcfaIterator.hpp"
#include <misc/MetaValue.hpp>
#include <string>

namespace ocfa {
  namespace evidence {
    class MetaIterator:virtual public OcfaIterator {
    public:
	/** Retreive a  MetaVal from a meta*/
      virtual misc::MetaValue *getMetaVal()=0;
      //Retreive a meta value and take over full responsibility for the object
      virtual void fetchMetaVal(misc::MetaValue **metaval)=0;
      /** Retreive the name of the current metadata container */
      virtual std::string getName() const=0;
      virtual ~MetaIterator() {};
    };
}}
#endif
