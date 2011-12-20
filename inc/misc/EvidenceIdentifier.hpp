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
						
#ifndef _EVIDENCEHANDLE_
#define _EVIDENCEHANDLE_
#include <string>
#include "../OcfaObject.hpp"
#include "ItemIdentifier.hpp"
namespace ocfa {
  namespace misc {
  
    
    /**
     * Class for grouping together the identifiers that together form
     * a unique evidence handle
     * */
    class EvidenceIdentifier : public OcfaObject {
    public:
      /**Constructor*/
      EvidenceIdentifier(std::string caseid, std::string evidencesourceid, std::string itemid, std::string evidenceid);
      /**Constructor using ItemIdentifier*/
      EvidenceIdentifier(ItemIdentifier *item,std::string evidenceid);
      /** fetch the case ID of the investigation*/
      std::string getCaseID() const;
      /** Fetch the evidence source id of the source of the evidence within the case */
      std::string getEvidenceSourceID() const;
      /** Fetch the item id of the item within the source */
      std::string getItemID() const;
      /** Fetch tehe evidence id of the evidence within the item */
      std::string getEvidenceID() const;
    private:
      std::string mCaseID;
      std::string mEvidenceSourceID;
      std::string mItemID;
      std::string mEvidenceID;
    };
  }
}
#endif
