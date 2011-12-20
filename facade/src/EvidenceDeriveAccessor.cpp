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
#include "misc/OcfaException.hpp" 
#include "facade/EvidenceDeriveAccessor.hpp"
#include "store/EvidenceStoreEntity.hpp"
#include "store/MetaStoreEntity.hpp"
#include "store/AbstractRepository.hpp"

using namespace ocfa::facade;
using namespace ocfa::module;
using namespace ocfa::misc;
using namespace ocfa::evidence;
using namespace std;
using namespace ocfa::store;

/**
 * besides normal initialization, this constructor also takes care that a working
 * directory exists and that it is empty. 
 *
 */
EvidenceDeriveAccessor::EvidenceDeriveAccessor(string inName, string inNamespace): 
	EvidenceFileAccessor(inName, inNamespace),
	mWorkDir(""),
	mTreeWalker(0),
	mpRouter(0)
{
  computeWorkDir();
  mTreeWalker = new EvidenceTreeWalker(this, 0, mWorkDir, true, "AUTO");
  if (!mTreeWalker->isEmpty(mWorkDir)){
    ocfaLog(LOG_WARNING, "Workdir was not empty. Will now empty it");
    mTreeWalker->emptyPath(mWorkDir);
  }
}



EvidenceDeriveAccessor::~EvidenceDeriveAccessor(){

  if (mTreeWalker != 0){

    delete mTreeWalker;
  }
  if (mpRouter != 0){

    delete mpRouter;
  }
}

/**
 * creates a workdir that consists of:
 * $(workdirroot)/$(namespace)/$(modulename)/$(instance)
 */ 
void EvidenceDeriveAccessor::computeWorkDir(){

  string workDirRoot;
  ocfaLog(LOG_DEBUG, "constructor: checking/creating workdir");
  workDirRoot = OcfaConfig::Instance()->getValue("workdirroot");
  if (workDirRoot == ""){

    workDirRoot = OcfaConfig::Instance()->getValue("varroot");
    if (workDirRoot == ""){
      //RJM, below can not work, lets throw an exception instead
      throw OcfaException("no varroot found");
      //(RJM) FIXME, /var/ocfa/case should I think be /var/ocfa/$CASE
      //ocfaLog(LOG_WARNING, "no varroot found, falling back to /var/ocfa/case");
      //createOrExist("/var/ocfa");
      //workDirRoot+= "/var/ocfa/case"; 
    }
    createOrExist(workDirRoot);
    workDirRoot+= "/work";
  }
  createOrExist(workDirRoot);

  ModuleInstance *mySelf = getMessageBox()->getModuleInstance();
  mWorkDir = workDirRoot;
  mWorkDir += "/";
  mWorkDir += mySelf->getNameSpace();
  createOrExist(mWorkDir);
  mWorkDir += "/";
  mWorkDir += mySelf->getModuleName();
  createOrExist(mWorkDir);
  mWorkDir += "/";
  mWorkDir += mySelf->getInstanceName();
  createOrExist(mWorkDir);
}

/**
 * deives an evidence from the current evidence. 
 *
 */
Evidence *EvidenceDeriveAccessor::derive(OcfaContent inContent, ocfa::misc::Scalar evidenceName,
		  std::string parentChildRelationName, 
		 std::vector<ocfa::evidence::CoParent> *inCoParents){

  EvidenceStoreEntity *dataEntity;
  
  map<string, MetaValue *>  *statMap;
  Evidence *newEvidence;
  checkValidEvidence();
  if (getEvidence()->getEvidenceIdentifier() == 0){

    ocfaLog(LOG_ERR, "current active Evidence has no valid identifier");
    throw OcfaException("Evidence has no valid identifier", this);
  }
  // create EvidenceStoreEntity from Content.
  AbstractRepository::Instance()->createEvidenceStoreEntity(&dataEntity, inContent);
  
  // create empty statmap and handle. these are taken by 
  // evidenceFactory.
  statMap = new map<string, MetaValue  *>;
  OcfaHandle *handle = new OcfaHandle(dataEntity->getHandle());


  EvidenceFactory::Instance()->createEvidence(&newEvidence, &handle, 
					      dataEntity->getDigestPair(),
					      evidenceName, &statMap,
					      getEvidence(), parentChildRelationName,
					      inCoParents);
  return newEvidence;
}


ocfa::evidence::Evidence *EvidenceDeriveAccessor::derive(std::string fileName, ocfa::misc::Scalar evidenceName, 
				 std::string parentChildRelationName, 
				 std::vector<ocfa::evidence::CoParent > *inCoParents){


  if (getEvidence() == 0){

    throw OcfaException("No Active Evidence set !", this);
  }

  struct stat filestat;
  string absfilePath = fileName;
  string relfilePath = mWorkDir + "/" + fileName;
  string filePath = relfilePath;
  if (stat(filePath.c_str(), &filestat) < 0) {
          filePath = absfilePath;
  }

  if (stat(filePath.c_str(), &filestat) < 0) {
     throw OcfaException(std::string("Unable to derive data, specified path '") + fileName + "' could not be statted, neither as absolute path, or relative to the module working dir '" + mWorkDir + "'.",this);
  }
  return mTreeWalker->createDerivedEvidence(getEvidence(), filePath, evidenceName, parentChildRelationName, 
					    inCoParents);

}



/**
 * similar to the superclass's submitEvidence except that, in case the
 * router was not given, a stored router will be used.
 *
 */
void EvidenceDeriveAccessor::submitEvidence(Evidence *inEvidence, const ocfa::misc::ModuleInstance *inRouter){

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
void EvidenceDeriveAccessor::createOrExist(string inDirPath){

  getLogStream(LOG_DEBUG) << "Trying to create " << inDirPath << endl;
  DIR *thisdir = opendir(inDirPath.c_str());
  if (thisdir != 0) {

    closedir(thisdir);
    
  }
  else {

    if (mkdir(inDirPath.c_str(),0700)!=0){
      
      throw OcfaException("Cannot create " + inDirPath, this);
    }
  }
}

string EvidenceDeriveAccessor::getWorkDir(){

  return mWorkDir;

}

void  EvidenceDeriveAccessor::processEvidenceMessage(const ocfa::message::Message &inMessage){

  ocfaLog(LOG_DEBUG, "entering EvidenceDeriveAccessor::processEvidenceMessage");
  
  if (inMessage.getSender() == 0){

    throw OcfaException("received evidnece message without a sender ?? ", this);
  }
  // JBS might not be necessary to copy all this stuff, I just do it to prevent untraceable
  // memory bugs.
  if (mpRouter != 0){

    delete mpRouter;
  }
  // TODO add error message to Evidence.
  if (!mTreeWalker->isEmpty(mWorkDir)){

    getLogStream(LOG_ERR) << "still rubbish left when processing " << inMessage.getContent() << endl;
    if (OcfaConfig::Instance()->getValue("failfatal") != string("false")){
      
      throw OcfaException(string("Rubbish left after processing: ") +  inMessage.getContent());
    }      
    else {
    
      getLogStream(LOG_WARNING) << "emptying workdir " << endl;
      mTreeWalker->emptyPath(mWorkDir);
    }
  }
  mpRouter = new ModuleInstance(inMessage.getSender());
  EvidenceFileAccessor::processEvidenceMessage(inMessage);

}


EvidenceTreeWalker *EvidenceDeriveAccessor::getTreeWalker(){

  return mTreeWalker;
}


void EvidenceDeriveAccessor::setTreeWalker(EvidenceTreeWalker **inTreeWalker){

  if (mTreeWalker != 0){

    delete mTreeWalker;
  }
  mTreeWalker = *inTreeWalker;
}
