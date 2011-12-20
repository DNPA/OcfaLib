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
						
#include "facade/EvidenceFileAccessor.hpp"
#include "store/AbstractRepository.hpp"
#include "store/EvidenceStoreEntity.hpp"
using namespace ocfa::facade;
using namespace ocfa::store;
using namespace ocfa::misc;
EvidenceFileAccessor::EvidenceFileAccessor(string inName, string inNameSpace) 
  : BaseAccessor(inName, inNameSpace){

}
/**
 * returns the evidencestoreentity represented by the current active evidence.
 * The caller takes ownership over the returned object.
 *
 */
EvidenceStoreEntity *EvidenceFileAccessor::fetchEvidenceStoreObject(){

  OcfaHandle *dataHandle = 0;
  EvidenceStoreEntity *dataEntity = 0;
  checkValidEvidence();
  dataHandle = getEvidence()->getRawDataHandle();
  if (dataHandle != 0){
    
    AbstractRepository::Instance()->createEvidenceStoreEntity(&dataEntity, *dataHandle);
  }
  return dataEntity;
}


    
