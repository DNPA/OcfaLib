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
						
#ifndef _SIMPLEITEM_
#define _SIMPLEITEM_
#include <misc/Item.hpp>
#include <string>
#include <OcfaObject.hpp>
namespace ocfa {
  namespace misc {
    /**
     * Class for grouping together the identifiers that together form a unique 
     * reference to an item
     */
    class SimpleItem:public OcfaObject,public Item {
    public:
      std::string getCaseID() const;
      /** Fetch the evidence source id of the source of the evidence within the case */
      std::string getEvidenceSourceID() const;
      /** Fetch the item id of the item within the source */
      std::string getItemID() const;
      /** Get a unique id for deriving deriving an evidence from this item */
      size_t getTopEvidenceCount() const;
      void incTopEvidenceCount();
      SimpleItem(std::string caseID,std::string eid,std::string iid);
    private:
      std::string mCase;
      std::string mSrc;
      std::string mItem;
      size_t mCount;
    };
  }
}
#endif
