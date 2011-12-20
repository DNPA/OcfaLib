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
						
#include <evidence/CoParent.hpp>
namespace ocfa {
	namespace evidence {
	   CoParent::CoParent(std::string caseid,std::string itemid,std::string srcid,std::string eid,size_t jobid):OcfaObject("CoParent","evidence"),mEvidenceID(eid),mItemID(itemid),mEvidenceSourceID(srcid),mCaseID(caseid),mRelName("child"),mJobID(jobid) {
	   }
           size_t CoParent::getJobID() const {
              return mJobID;
	   }
           /**Retreive the original EvidenceID from the CpParent*/
           std::string CoParent::getEvidenceID() const {
             return mEvidenceID;
	   }
           /**Retreive the original itemID from the CpParent*/
           std::string CoParent::getItemID() const {
             return mItemID;
	   }
	   /**Retreive the original EvidenceSourceID  from the CpParent*/
	   std::string CoParent::getEvidenceSourceID() const {
		return mEvidenceSourceID;
	   }
           /** Retreive the case id */
           std::string CoParent::getCaseID() const {
               return mCaseID;
	   }
	   /**Retreive the name of the relation that the from parent to child */
           std::string CoParent::getRelName() const {
               return mRelName;
	   }
	   /** Set or update the relation name from parent to child for the CoParent */
           void CoParent::setRelName(std::string inRelName){
              mRelName=inRelName;
	   }
	}
}
