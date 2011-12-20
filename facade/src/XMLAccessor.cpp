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
						
#include <facade/XMLAccessor.hpp>
using namespace std;
using namespace ocfa::facade;
using namespace ocfa::store;
using namespace ocfa::evidence;
using namespace ocfa::misc;
XMLAccessor::XMLAccessor(string inName, string inNamespace) 
  : BaseAccessor(inName, inNamespace), mMetaStoreEntity(0){

  mMetaStoreEntity = 0;
}

/**
 * stores the MetaStoreentity in mMetaStoreEntity
 *
 */
Evidence *XMLAccessor::createEvidenceFromMeta(MetaStoreEntity *inEntity){

  if (mMetaStoreEntity != 0){

    ocfaLog(misc::LOG_ERR, "XMLAccessor::createEvidenceFromMeta: mMetaStoreEntity != 0");
    throw OcfaException("mMetastoreException was not set to 0", this);
  }
  mMetaStoreEntity = inEntity;
  return BaseAccessor::createEvidenceFromMeta(inEntity);
}

/**
 * Updates the  metastoreentity with the new evidence. Sets the stored metastoreentity to  
 * 0.
 *
 */
void XMLAccessor::updateMetaWithEvidence(MetaStoreEntity &inMeta, Evidence &inEvidence){

  if (mMetaStoreEntity == 0){

    getLogStream(misc::LOG_ERR) << "XMLAccessor::updateMetaWithEvidence Weird, mMetastoreEntity was already 0" << endl;
  }
  mMetaStoreEntity = 0;
  BaseAccessor::updateMetaWithEvidence(inMeta, inEvidence);
}

ocfa::store::MetaStoreEntity *XMLAccessor::getMetaXMLStoreHandle() const {

  return mMetaStoreEntity;
}
