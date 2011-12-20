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
						
#ifndef __OCFAEVIDENCEFACTORY_
#define __OCFAEVIDENCEFACTORY_
#include <string>
#include <vector>
#include <map>
#include "../misc.hpp"
#include "Evidence.hpp"
#include "ExtendableEvidence.hpp"

namespace ocfa {
	namespace evidence {
	  
	  /** Factory for creating Evidence objects */
	  class EvidenceFactory:public OcfaObject {
		  public:
			  /** Create a brandnew  Evidence from that is derived from an other Evidence
			   * @param evidenceDataHandle : Handle of the EvidenceStoreEnitity this Evidence
			   *                             is created for.
			   * @param evidenceName : The name of this Evidence
			   * @param digests : The set of digest strings for the content of the EvidenceStoreEntity
			   * @param statmap : A map containing the metadata from the fs library with respect to the 
			   *                  original file the EvidenceStoreEntity was created from 
			   * @param parentevidence : The Evidence object the new Evidence is to be derived from.
			   * @param parentChildRelname : the name of the relationship this evidence has from its parent
			   * */
			  virtual void createEvidence(Evidence **newevidence,misc::OcfaHandle **evidenceDataHandle,
					  		misc::DigestPair *digests,
							misc::Scalar& evidenceName,
							std::map < std::string, misc::MetaValue * > **statmap,
							Evidence *parentevidence,
							std::string parentChildRelname,
							std::vector < CoParent > *coparents= 0
							)=0;
			  /** Create a brandnew  Evidence from that is derived from a ItemHandle
			   * @param evidenceDataHandle : Handle of the EvidenceStoreEnitity this Evidence
			   * 				s created for.
			   * @param evidenceName : The name of this Evidence
			   * @param digests : The set of digest strings for the content of the EvidenceStoreEntity
			   * @param statmap : A map containing the metadata from the fs library with respect to the
			   * 			original file the EvidenceStoreEntity was created from
			   * @param parentitem : The ItemHandle object the new Evidence is to be derived from
			   *
			   * */
			  virtual void createEvidence(Evidence **newevidence,misc::OcfaHandle **evidenceDataHandle,
					  		misc::DigestPair *digests,
							misc::Scalar& evidenceName,
							map < std::string,misc::MetaValue *> **statmap,
							misc::Item *parentitem)=0;
			  /** Create an Evidence from the MemBuf that was fetched earlier from  the repository */
			  virtual void createEvidence(Evidence **newevidence,misc::MemBuf *membuf, 
					  		misc::OcfaHandle **evidenceDataHandle)=0;
			  /** Create a MapEvidence from the MemBuf that was fetched earlier from  the repository */
			  //virtual void createMappedEvidence(MapEvidence **newmapevidence,misc::MemBuf *membuf, 
			  //		  		misc::OcfaHandle **evidenceDataHandle)=0;
			  /** Create a MapEvidence from the MemBuf that was fetched earlier from  the repository */
			  virtual void createExtendableEvidence(ExtendableEvidence **newextendableevidence,misc::MemBuf *membuf,
					  			 misc::OcfaHandle **evidenceDataHandle)=0;
			  /* baptize the factory with the module its ModuleInstance, so it can access the logger and config
			   * in the proper way */
			  virtual void baptize(misc::ModuleInstance *modinstance)=0;
			  static EvidenceFactory *Instance();
			  virtual ~EvidenceFactory(){};
		  protected:
			  EvidenceFactory();
		  private:
			  static EvidenceFactory *_instance;
			  
	  };
	}
}
#endif
