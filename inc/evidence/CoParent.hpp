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
						
#ifndef _COPARENT_HPP
#define _COPARENT_HPP
#include "../misc.hpp"
#include <string>

namespace ocfa {
  namespace evidence {
    /** A class used for the purpose of storing state of the active evidence/job
     * for later usage in derivation of evidences that could only be partialy
     * derived in from an active evidence */
    class CoParent:public OcfaObject {
    public:
       /**Retreive the original 0 based job number from th CpParent*/
      size_t getJobID() const;
       /**Retreive the original EvidenceID from the CpParent*/
      std::string getEvidenceID() const;
       /**Retreive the original itemID from the CpParent*/ 
      std::string getItemID() const;
       /**Retreive the original EvidenceSourceID  from the CpParent*/
      std::string getEvidenceSourceID() const;
      /** Retreive the case id */
      std::string getCaseID() const;
       /**Retreive the name of the relation that the from parent to child */
      std::string getRelName() const;
       /** Set or update the relation name from parent to child for the CoParent */
      void setRelName(std::string inRelName);
    protected:
      CoParent(std::string caseid,std::string itemid,std::string srcid,std::string eid,size_t jobid);
    private:
      std::string mEvidenceID;
      std::string mItemID;
      std::string mEvidenceSourceID;
      std::string mCaseID;
      std::string mRelName;
      size_t mJobID;
    };
  }
}
#endif
