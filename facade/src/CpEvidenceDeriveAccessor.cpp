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
						
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "facade/CpEvidenceDeriveAccessor.hpp"
#include "store/EvidenceStoreEntity.hpp"
#include "store/MetaStoreEntity.hpp"
#include "store/AbstractRepository.hpp"

using namespace ocfa::facade;
using namespace ocfa::module;
using namespace ocfa::misc;
using namespace ocfa::evidence;
using namespace std;
using namespace ocfa::store;
//NOTE: this accessor currently copies much of the EvidenceDeriveAccessor,
//      this is bad, both should be refactored to allow for proper derived
//      usage.

/**
 * besides normal initialization, this constructor also takes care that a working
 * directory exists and that it is empty. 
 *
 */
CpEvidenceDeriveAccessor::CpEvidenceDeriveAccessor(string inName, string inNamespace,
   std::string fsmodule,std::map<std::string,std::string> *attributes): 
	EvidenceFileAccessor(inName, inNamespace),
	mTreeWalker(0),
	mpRouter(0)
{
  if (fsmodule == "") {
     mTreeWalker = new EvidenceTreeWalker(this, 0, string("/"), false, "AUTO");
  } else {
     mTreeWalker = new EvidenceTreeWalker(this, 0, fsmodule,false,attributes);
  }
}

CpEvidenceDeriveAccessor::~CpEvidenceDeriveAccessor(){

  if (mTreeWalker != 0){

    delete mTreeWalker;
  }
  if (mpRouter != 0){

    delete mpRouter;
  }
}

/**
 * deives an evidence from the current evidence. 
 *
 */
Evidence *CpEvidenceDeriveAccessor::derive(OcfaContent inContent, ocfa::misc::Scalar evidenceName,
		  std::string parentChildRelationName, 
		 std::vector<ocfa::evidence::CoParent> *inCoParents){
    throw OcfaException("CpEvidenceDeriveAccessor can not derive from OcfaContent object", this);
}


ocfa::evidence::Evidence *CpEvidenceDeriveAccessor::derive(std::string fileName, ocfa::misc::Scalar evidenceName, 
				 std::string parentChildRelationName, 
				 std::vector<ocfa::evidence::CoParent > *inCoParents){


  if (getEvidence() == 0){

    throw OcfaException("No Active Evidence set !", this);
  }
  if (fileName.c_str()[0] != '/') {
    throw OcfaException("CpEvidenceDeriveAccessor requires absolute paths.");
  }
  string filePath = fileName;
  return mTreeWalker->createDerivedEvidence(getEvidence(), filePath, evidenceName, parentChildRelationName, 
					    inCoParents);

}



/**
 * similar to the superclass's submitEvidence except that, in case the
 * router was not given, a stored router will be used.
 *
 */
void CpEvidenceDeriveAccessor::submitEvidence(Evidence *inEvidence, const ocfa::misc::ModuleInstance *inRouter){

  if (inRouter == 0){
    
    if (mpRouter == 0){

      throw OcfaException("Submitting evidence without given router or stored router", this);
    }
    EvidenceFileAccessor::submitEvidence(inEvidence, mpRouter);
  }
  else {

    EvidenceFileAccessor::submitEvidence(inEvidence, inRouter);
  }
}
      
/**
 * Checks whether inDirPath exist or whether it can be created.
 */
void CpEvidenceDeriveAccessor::createOrExist(string inDirPath){

  getLogStream(LOG_DEBUG) << "Looking if dir exists: " << inDirPath << endl;
  DIR *thisdir = opendir(inDirPath.c_str());
  if (thisdir != 0) {
    closedir(thisdir);
  }
  else {
      throw OcfaException("Did does not exist, CpEvidenceDeriveAccessor can not create: " + inDirPath, this);
  }
}

string CpEvidenceDeriveAccessor::getWorkDir(){

  return string("/");

}

void  CpEvidenceDeriveAccessor::processEvidenceMessage(const ocfa::message::Message &inMessage){

  ocfaLog(LOG_DEBUG, "entering CpEvidenceDeriveAccessor::processEvidenceMessage");
  
  if (inMessage.getSender() == 0){

    throw OcfaException("received evidnece message without a sender ?? ", this);
  }
  // JBS might not be necessary to copy all this stuff, I just do it to prevent untraceable
  // memory bugs.
  if (mpRouter != 0){

    delete mpRouter;
  }
  mpRouter = new ModuleInstance(inMessage.getSender());
  EvidenceFileAccessor::processEvidenceMessage(inMessage);
}



