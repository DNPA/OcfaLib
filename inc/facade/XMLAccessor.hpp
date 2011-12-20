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
						
#ifndef __OCFAACCESSORXML_
#define __OCFAACCESSORXML_
#include "BaseAccessor.hpp"
#include "store/MetaStoreEntity.hpp"
namespace ocfa {

  namespace facade {

    /**
     * Accessor that can be used to access the raw data of the metastoreentity. 
     *
     */
    class XMLAccessor : public BaseAccessor {

    public:
      XMLAccessor(std::string inName, std::string inNamespace);
      /**
       * returns the handle of the xml that is used to describe the evidence.
       */
      ocfa::store::MetaStoreEntity * getMetaXMLStoreHandle() const;
    protected:
      /**
       * overrided the method in OcfaModule.
       */
      virtual ocfa::evidence::Evidence *createEvidenceFromMeta(ocfa::store::MetaStoreEntity *inEntity);
      virtual void updateMetaWithEvidence(ocfa::store::MetaStoreEntity &inMeta, ocfa::evidence::Evidence &inEvidence);
      XMLAccessor(const XMLAccessor& xa):
	      BaseAccessor(xa),
	      mMetaStoreEntity(0)
      {
	      throw misc::OcfaException("No copying allowed of XMLAccessor",this);
      }
      const XMLAccessor& operator=(const XMLAccessor&) {
	      throw misc::OcfaException("No assignment allowed of XMLAccessor",this);
	      return *this;
      }
    private:
      
      ocfa::store::MetaStoreEntity *mMetaStoreEntity;
    };
    
  }
}

#endif
