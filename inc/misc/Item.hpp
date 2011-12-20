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
						
#ifndef _BASEITEM_
#define _BASEITEM_
#include <string>
#include "../OcfaObject.hpp"
namespace ocfa {
  namespace misc {
    /**
     * Class for grouping together the identifiers that together form a unique 
     * reference to an item
     */
    class Item {
    public:
      virtual std::string getCaseID() const=0;
      /** Fetch the evidence source id of the source of the evidence within the case */
      virtual std::string getEvidenceSourceID() const=0;
      /** Fetch the item id of the item within the source */
      virtual std::string getItemID() const=0;
      /** Get a unique id for deriving deriving an evidence from this item */
      virtual size_t getTopEvidenceCount() const=0;
      virtual void incTopEvidenceCount() = 0;
      virtual ~Item() {};
    };
  }
}
#endif
