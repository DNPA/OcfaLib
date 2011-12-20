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
						
#include <evidence/EvidenceFactory.hpp>
namespace ocfa {
	namespace evidence {
	  
	  /** Factory for creating Evidence objects */
	  class DomEvidenceFactory:public EvidenceFactory {
		  public:
			  //JCW:CODEREVIEW: Documentatie!
			  void		createEvidence(Evidence **newevidence,misc::OcfaHandle **evidenceDataHandle,
					  		misc::DigestPair *digests,
							misc::Scalar& evidenceName,
							std::map < std::string, misc::MetaValue * > **statmap,
							Evidence *parentevidence,
							std::string parentChildRelname,
							std::vector < CoParent > *coparents
							);
			  void		createEvidence(Evidence **newevidence,misc::OcfaHandle **evidenceDataHandle,
					  		misc::DigestPair *digests,
							misc::Scalar& evidenceName,
							std::map < std::string,misc::MetaValue * > **statmap,
							misc::Item *parentitem);
			  void		createEvidence(Evidence **newevidence,misc::MemBuf *membuf, 
					  		misc::OcfaHandle **evidenceDataHandle);
			  void		createExtendableEvidence(ExtendableEvidence **newextendableevidence,misc::MemBuf *membuf,
					  			 misc::OcfaHandle **evidenceDataHandle);
			  void baptize(misc::ModuleInstance *modinstance);
                          DomEvidenceFactory(const DomEvidenceFactory& ef):EvidenceFactory(ef),mModinstance(0),mMaxParentCount(0) {
                             throw misc::OcfaException("Copying of DomEvidenceFactory not allowed",this);
			  }
			  DomEvidenceFactory();
			  const DomEvidenceFactory& operator=(const DomEvidenceFactory&) {
                             throw misc::OcfaException("Assignment of  DomEvidenceFactory not allowed",this);
			     return *this;
			  }
		private:
			  misc::ModuleInstance *mModinstance;
			  size_t	 mMaxParentCount;
			  
	  };
	}
}
