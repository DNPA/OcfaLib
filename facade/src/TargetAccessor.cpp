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
						
#include "facade/TargetAccessor.hpp"
#include "store/AbstractRepository.hpp"
#include "evidence/commit_type.hpp"

using namespace ocfa::facade;
using namespace ocfa::evidence;
using namespace ocfa::misc;
using namespace std;
using ocfa::message::Message;
using ocfa::store::MetaStoreEntity;
using ocfa::store::AbstractRepository;
using ocfa::misc::OcfaHandle;
TargetAccessor::TargetAccessor(string inName, string inNamespace, bool forceNoDaemonize) 
  : BaseAccessor(inName, inNamespace, forceNoDaemonize)
  , mTarget(0){
}

/**
 * sets the target to which the evidence will be sent after processing. 
 */
void TargetAccessor::setTarget(string inName, string inNameSpace){


  if (mTarget != 0){

    delete mTarget;
    mTarget =0;
  }
  if (inName != "" || inNameSpace != ""){

    mTarget = new ModuleInstance("localhost", inName, inNameSpace, "DNTCR");
  } 
}

/**
 * adds a new job to the current evidence
 * @param jobInfo informaiton about the new job. 
 * 
 */
void TargetAccessor::addNewJob(JobInfo *inJobInfo){

  // you cannot add new jobs to normal evidences. So we use the extendable evidence.
  ExtendableEvidence *extendableEvidence = dynamic_cast<ExtendableEvidence *>(getEvidence());
  if (extendableEvidence == 0){
    ocfaLog(LOG_ERR, "No extendableEvidence set");
  }
  //extendableEvidence->setGlobalMetaFacades(); // RJM:CODEREVIEW this should be default on tables used by the router.
  					      //    however the (DOM)router must be able set and clear it for individual
					      //    table jumps.
  extendableEvidence->addNewJob(inJobInfo); 
}

//RJM: Proposal:
//ExtendableEvidence *TargetAccessor::getExtendableEvidence() {
//  ExtendableEvidence *rval=dynamic_cast<ExtendableEvidence *>(getEvidence());
//  return rval;
//}

void TargetAccessor::processEvidenceMessage(const Message &inMessage){

  try {
    ocfaLog(LOG_DEBUG, "entering TargetAccessor:processEvidenceMessage");
    MetaStoreEntity *metaEntity;
    JobInfo routerJobInfo(COMMIT_NOT);
    setTarget("", "");
    OcfaHandle handle(inMessage.getContent());
    AbstractRepository::Instance()->createMetaStoreEntity(&metaEntity, handle);
    if (metaEntity == 0){

      throw OcfaException(string("cannot create metastoreentity from ") + inMessage.getContent(), this);
    }
    setEvidence(createEvidenceFromMeta(metaEntity),inMessage.getPriority());
    addNewJob(0);
    getEvidence()->setMutable();
    if (getEvidence() == 0){

      throw OcfaException("Couldn't set Evidence", this);
    }
    processEvidence();
    getEvidence()->getActiveJob()->close();
    updateMetaWithEvidence(*metaEntity, *getEvidence());
    if (mTarget == 0){
      
      ocfaLog(LOG_ERR, string("No target set while processing evidence ") + getEvidenceID());
    }
    else {
      
      Message *reply;
      getMessageBox()->createMessage(&reply, mTarget, Message::ANYCAST, Message::mtEvidence, "request", metaEntity->getHandle(), getDerivePriority(mTarget)); 
      //RJM:CODEREVIEW sugestion: use the folowing instead of the abouve and replace mTarget with an mTargetType string
      //getMessageBox()->createEvidenceMessage(
      //                               &reply,
      //                               metaEntity->getHandle(),
      //                               getDerivePriority(mTarget),
      //                               Message::EVODENCE_REQ,
      //                               mTarget->getName()
      //                              );
      if (reply == 0){
	
	throw OcfaException("Could not create a reply", this);
      }
      getMessageBox()->sendMessage(*reply);
      //delete mTarget;
      setTarget("","");
      delete reply;
    }
    delete metaEntity;
    delete getEvidence();
    setEvidence(0);

    
  } catch (OcfaException &e){
    e.logWhat();
    if (OcfaConfig::Instance()->getValue("failfatal")!= string("false")) {  
      throw OcfaException("OcfaException in processEvidenceMessage",this);
    }
    //logModule(LOG_ERR, string("OcfaException ") + e.what());
  }
}

/**
 * creates an extendable evidence instead of a normal one. 
 */
Evidence  *TargetAccessor::createEvidenceFromMeta(MetaStoreEntity *inMetaEntity){
  
  ocfaLog(LOG_DEBUG, "entering TargetAccessor::createEvidenceFromMeta");
  ExtendableEvidence *activeEvidence;
  OcfaHandle *evidenceDataHandle = 0;
  MemBuf *content = inMetaEntity->contentsAsMemBuf();
  if (content == 0){

    ocfaLog(LOG_ERR, "createEvidenceFromMeta: cannot create content from metastoreentity");
    throw OcfaException("cannot getcontent from metastoreentity");
  }
  getEvidenceFactory()->createExtendableEvidence(&activeEvidence, 
				       content, 
				       &evidenceDataHandle);
  delete content;

  if (activeEvidence == 0){
    
    ocfaLog(LOG_ERR, string("createEvidenceFromMeta: cannot create evidence from ") 
	    + inMetaEntity->getHandle());
    throw OcfaException(string("cannot create evidence from ") + inMetaEntity->getHandle(), this);
  }
  delete evidenceDataHandle;
  return activeEvidence;

}



