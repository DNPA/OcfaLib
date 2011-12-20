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
						
#include "module/EvidenceTreeWalker.hpp"
#include "module/OcfaModule.hpp"
#include "treegraph/InvalidNode.hpp"
#include "treegraph/TreeGraphModuleLoader.hpp"
#include "treegraph/TreeGraphFactory.hpp"
#include "fs/FileSystemModuleInfo.hpp"
#include "fs/FileSystemModuleInfoFactory.hpp"
#include "treegraph/types.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>

#include "misc/DigestPair.hpp"
#include "misc/OcfaConfig.hpp"

#include "store/AbstractRepository.hpp"
#include <boost/lexical_cast.hpp>
#include "ConcreteWriteFacet.hpp"
using namespace std;
using namespace ocfa::misc;

using ocfa::evidence::Evidence;
using ocfa::evidence::EvidenceFactory;
using ocfa::evidence::CoParent;
using ocfa::store::AbstractRepository;
using ocfa::store::EvidenceStoreEntity;
using ocfa::store::linktype;
using ocfa::store::Filename;
using ocfa::store::hard;
using ocfa::store::soft;

using ocfa::treegraph::FsConnectedNode;
using ocfa::treegraph::TreeGraphModuleLoader;
using ocfa::treegraph::TreeGraphFactory;
using ocfa::treegraph::TreeGraphNode;

namespace ocfa{

  namespace module {
    
    /**
     * Constructor. Initializes the EvidenceTreeWalker and the FileSystem. Also sets the flags depending
     * on the place of the repository and whether the files shoudl be deleted afterwards.
     * @param inModule the module that is used to submit selected evidences (Maybe this should be a messagebox.).
     * @param router the route to which the evidence should be sent. 
     * @param charset the character set that is used to encode the files on the filesystem. Can be set to "auto" to have it
     * set automatically.
     * @param inInitPath A path that is on the filesystem from which new evidence will be extracted.
     * @param inShouldDelete boolean indicating whether the files will be deleted afterwards.
     */  
    EvidenceTreeWalker::EvidenceTreeWalker(OcfaModule *inModule, ModuleInstance *inRouter, 
					   string inInitPath, bool inShouldDelete, string charset):
	    OcfaObject("EvidenceTreeWalker", "module"),
	    module(inModule),
	    router(inRouter),
	    mShouldDelete(inShouldDelete),
	    ncount(TREEWALK_NODE_INTERRUPTION_COUNT) 
    {
      if (module == 0){
	throw OcfaException("No OcfaModule given", this); 
      }
      ocfaLog(LOG_NOTICE, string("calling select and init with path ") + inInitPath + " and charset " + charset);
      ocfa::fs::FileSystemModuleInfo *modinfo=ocfa::fs::FileSystemModuleInfoFactory::findProperModuleInfo(inInitPath, charset);
      if (! TreeGraphModuleLoader::selectAndInit(*modinfo,*modinfo)){
        delete modinfo;
	throw OcfaException("TreeGraphModuleLoader::selectAndInit returned false.", this);
      }
      delete modinfo;
      ocfaLog(LOG_DEBUG, "select and init executed");
    }
    
    // 
    //This version of the constructor does not auto detect but specifies the module to use directly */
    //
     EvidenceTreeWalker::EvidenceTreeWalker(OcfaModule *inModule, ModuleInstance *inRouter,
		     std::string fsmodule, bool ismap ,std::map<std::string,misc::Scalar> *attributes):
	     OcfaObject("EvidenceTreeWalker", "module"),
	     module(inModule),
	     router(inRouter),
	     mShouldDelete(false),
	     ncount(TREEWALK_NODE_INTERRUPTION_COUNT) 
     {
      if (module == 0){
	
	throw OcfaException("No OcfaModule given", this); 
      }
      ocfaLog(LOG_NOTICE, string("calling select and init for module ") + fsmodule);
      TreeGraphModuleLoader::selectAndInit(fsmodule,attributes);
      ocfaLog(LOG_DEBUG, "select and init executed");

      if (ismap) {  
        ocfaLog(LOG_DEBUG, string("root is") +   AbstractRepository::Instance()->getRoot());
      }
     }

    EvidenceTreeWalker::~EvidenceTreeWalker(){
    }

    /**
     * Wrapper around process node. Makes an fsEntity node from the given file and then calles processNode.
     * @param parent the parent of the evidence that should  be creates from inPath
     * @param inPath the path of the file from which an evidence should be created.
     * @param inParentChildRelation the relation between the parent and the new evidence that will be created 
     * @param from the current one.
     */ 
    void EvidenceTreeWalker::processPath(Evidence *parentEvidence, string &inPath, 
					 const string inParentChildRelation, Scalar* inEvidenceName){
      
      TreeGraphNode *node =0;
      TreeGraphFactory *fileSystem = TreeGraphModuleLoader::getFactory();
      ocfaLog(LOG_DEBUG, string("path=") + inPath); 
      misc::EvidenceIdentifier *eidf=parentEvidence->getEvidenceIdentifier();
      std::string basets=eidf->getCaseID() + "-" + eidf->getEvidenceSourceID() + "-" + eidf->getItemID() + "-" + eidf->getEvidenceID();
      fileSystem->createTopNode(inPath, &node,basets);
      ocfaLog(LOG_DEBUG, string("node=") + node->getName()); 
      if (mShouldDelete){

	ocfaLog(LOG_INFO, string("setting unlink for destruct to ") + node->getName());
	node->unlinkOnDestruct();
      }
      processNode(parentEvidence, node, inParentChildRelation, inEvidenceName);
      delete node;
    }

    /**
     * Wrapper around process node. Makes an fsEntity node from the given file and then calles processNode.
     * @param parent the parent of the evidence that should  be creates from inPath
     * @param inPath the path of the file from which an evidence should be created.
     * @param inParentChildRelation the relation between the parent and the new evidence that will be created 
     * @param from the current one.
     */
    void EvidenceTreeWalker::processNode(Evidence *parentEvidence,  TreeGraphNode *inEntity, 
					 const string parentChildRelation, Scalar *inEvidenceName){
      getLogStream(LOG_DEBUG) << "processNode: parent is " << parentEvidence << endl;
      ncount--;
      if (ncount == 0) {
	      ncount=TREEWALK_NODE_INTERRUPTION_COUNT;
      }
      Evidence *newEvidence = 0;
      try {
        newEvidence = 
 	  createEvidenceFromFsEntity(parentEvidence, inEntity, parentChildRelation, inEvidenceName);
      } catch (std::exception &e) {
         getLogStream(LOG_ERR) << "exception occurred while creating evidence from parent: "
		<< parentEvidence->getEvidencePath().asASCII() << " with the name: " << inEvidenceName->asASCII() << std::endl;
         throw;	
      }
      try {
	if (inEntity->hasSubEntities()){
	  processSubEntities(newEvidence, inEntity);
	}
      } catch (OcfaException &e){ 
	if (OcfaConfig::Instance()->getValue("failfatal")!= string("false")) {
                          throw;                  
	}
        e.logWhat();
	getLogStream(LOG_ERR) << "exception occurred while process subentities of " 
			      << newEvidence->getEvidencePath().asASCII() << endl;
	newEvidence->getActiveJob()->addLogLine(LOG_ERR, "Exception occurret while process subentities");
      } catch (std::exception &e) {
         getLogStream(LOG_ERR) << "exception occurred while process subentities of "
             << newEvidence->getEvidencePath().asASCII() << endl;
         throw;
      }
      ocfaLog(LOG_DEBUG, "closing active job");
      // OV; close evidence to be able to get a membuf later 
      newEvidence->getActiveJob()->close();
      ocfaLog(LOG_DEBUG, "submitting evidence");      
      module->submitEvidence(newEvidence, router);
      delete newEvidence;
    }
  

    void EvidenceTreeWalker::processSubEntities(Evidence *inEvidence, TreeGraphNode *inEntity){
      //RJM: TAGRJM1 I would sugest removing the call to resetSubEntityIterator here and moving it to
      //     the location of TAGRJM2. Normaly the sub entity will be new and ready to traverse, only if
      //     (given that I have interpreted the code correctly)
      //     the the folowing exceptional situation is true, this may not be the case:
      //     1) The node represents the direcory or a sub directory within the working dir. 
      //     2) The working dir was found to have 'rubish left' before processing could start.
      //     3) The config parameter 'failfatal' was set to false.
      //     If all 3 of these would be true, the emptyPath would have made the call to resetSubEntityIterator
      //     required. For this reason it is sugested that the resetSubEntityIterator should be moved to to
      //     the end of the emptyPath method instead.
      try {
        inEntity->resetSubEntityIterator();
      
      } catch (OcfaException &e){
	if (OcfaConfig::Instance()->getValue("failfatal")!= string("false")) {
	  throw;
	}
        e.logWhat();    
	getLogStream(LOG_ERR) << "cannot reset Subentity from " << inEvidence->getEvidencePath().asASCII() << endl;
	inEvidence->getActiveJob()->addLogLine(LOG_ERR, "cannot reset subentity");
	return;
      }
      do {
	
	TreeGraphNode *subFsEntity = 0;
        try {
           inEntity->getCurrentSubEntity(&subFsEntity);
        } catch (ocfa::misc::InvalidNodeException &ex) {
           getLogStream(LOG_ERR) << "Cought a InvalidNodeException while processing tree, using an explicit invalid node instead and continuing treewalking" << std::endl;
           subFsEntity=new ocfa::treegraph::InvalidNode();
        }
        if (subFsEntity) { 
	  ocfaLog(LOG_DEBUG, string("processing ") + subFsEntity->getName()); 
	  if (mShouldDelete){
	  
	    ocfaLog(LOG_DEBUG, string("unlinkonDestruct ") + subFsEntity->getName()); 
	    subFsEntity->unlinkOnDestruct();
	  }
	  try {
	      processNode(inEvidence, subFsEntity, inEntity->getCurrentSubEntityRelation());	
	  } catch(OcfaException &e){
	    if (OcfaConfig::Instance()->getValue("failfatal")!= string("false")) {
		            throw ;
            }
            e.logWhat();
	    getLogStream(LOG_ERR) << "Cannot create evidence from " << subFsEntity->getName()
				<< "parent: " << inEvidence->getEvidencePath().asASCII() << endl;
	    inEvidence->getActiveJob()->addLogLine(LOG_ERR, "cannot create evidence from " + subFsEntity->getName());
	  }
	  delete subFsEntity;
        } else {
           getLogStream(LOG_ERR) << "inEntity->getCurrentSubEntity returned NULL for '" << inEntity->getName() << "'" << std::endl;
        }
      } while (inEntity->nextSubEntity());
    }
    
      

						
    
    /**
     * method that creates one evidence from an FsEntity. The newly created evidence will be owned by the calling method.
     * @param the parent of the evidence that will be created. 
     * @param inFsEntity the FsEntity from which an evidence should be made.
     * @return the evidence representing the FsEntity.
     * 
     */
    Evidence *EvidenceTreeWalker::createEvidenceFromFsEntity(Evidence *inParentEvidence, 
							     TreeGraphNode *inFsEntity,
							     const string relation, 
							     Scalar *inEvidenceName, 
							     vector<CoParent > *inCoParents){

      getLogStream(LOG_DEBUG) << "createEvidenceFromFsEntity: parent is " 
			      << inParentEvidence << endl;
      
      Evidence *newEvidence = 0;
      EvidenceStoreEntity *storeEntity = 0;
      
      storeEntity = createStoreEntityFromFsEntity(inFsEntity);
      map< string, misc::MetaValue *> *metaMap = 0;
      inFsEntity->takeMetaMap(&metaMap);
      getLogStream(LOG_DEBUG) << "createEvidenceStoreEntity metamap is " << metaMap << endl; 
      OcfaHandle *storeHandle;
      DigestPair *digestPair;
      if (storeEntity == 0){

	storeHandle = 0;
	digestPair = 0;
      }
      else {
	
	storeHandle = new OcfaHandle(storeEntity->getHandle());      
	digestPair = storeEntity->getDigestPair();
      }

      Scalar scalar(string(""), string(""));
      if (inEvidenceName == 0){
      
	getLogStream(LOG_DEBUG) << "creating name using charset " << TreeGraphModuleLoader::getFactory()->getCharset() << endl;
        try {
	   scalar = Scalar(inFsEntity->getName(), TreeGraphModuleLoader::getFactory()->getCharset());
        } catch (ocfa::misc::ScalarException &ex) {
           getLogStream(LOG_ERR) << "Invalid node name: '" << inFsEntity->getName() << "' is not a valid sequence in charset " << TreeGraphModuleLoader::getFactory()->getCharset() << endl; 
           std::string inv=std::string("OCFA-INVALID-ENCODED-NAME:") + inFsEntity->getName();
           scalar = Scalar(inv,"LATIN1");
        }
      }
      else {
	scalar = *inEvidenceName;
      }
      EvidenceFactory::Instance()->createEvidence(&newEvidence, &storeHandle, 
						  digestPair, 
						  scalar, &metaMap,
						  inParentEvidence, relation, inCoParents);
      if (storeEntity != 0){

	delete storeEntity;
      }
      return newEvidence;
    }

    // TODO Refactor duplicate code

    ocfa::evidence::Evidence *EvidenceTreeWalker::createEvidenceFromFsEntity(ocfa::misc::Item *inParentItem, 
								 ocfa::treegraph::TreeGraphNode *inFsEntity,
								 Scalar *inEvidenceName){
      Evidence *newEvidence = 0;
      EvidenceStoreEntity *storeEntity = 0;
      
      storeEntity = createStoreEntityFromFsEntity(inFsEntity);
      map< string, misc::MetaValue *> *metaMap=0;
      inFsEntity->takeMetaMap(&metaMap);
     
      OcfaHandle *storeHandle;
      DigestPair *digestPair;
      if (storeEntity == 0){

	storeHandle = 0;
	digestPair = 0;
      }
      else {
	
	storeHandle = new OcfaHandle(storeEntity->getHandle());      
	digestPair = storeEntity->getDigestPair();
      }

      Scalar scalar(string(""), string(""));
      if ((inEvidenceName == 0)||(inEvidenceName->asUTF8() == "")){
        getLogStream(LOG_WARNING) << "No valid inEvidenceName, falling back on inFsEntity for name '" << inFsEntity->getName() << "'\n"; 
        try {	
	   scalar = Scalar(inFsEntity->getName());
        } catch (ocfa::misc::ScalarException &ex) {
           getLogStream(LOG_ERR) << "Invalid node name: '" << inFsEntity->getName() << "' is not a valid sequence in charset " << TreeGraphModuleLoader::getFactory()->getCharset() << endl;
           scalar = Scalar("OCFA-INVALID-ENCODED-NAME");
        }
      }
      else {
	scalar = *inEvidenceName;
      }
      if (scalar.asUTF8() == "") {
         throw OcfaException("No valid name found for the top level node",this);
      }
      EvidenceFactory::Instance()->createEvidence(&newEvidence, &storeHandle, 
						  digestPair, 
						  scalar, &metaMap,
						  inParentItem);
      if (storeEntity != 0){

	delete storeEntity;
      }
      return newEvidence;
    }
      
      



    
    
    
    EvidenceStoreEntity *EvidenceTreeWalker::createStoreEntityFromFsEntity(TreeGraphNode *inFsEntity){
      
	EvidenceStoreEntity *storeEntity = 0;

	if (inFsEntity->hasContent()){
          ocfa::misc::DigestPair *dpair=0;
          string filePath = inFsEntity->getHardLinkablePath(AbstractRepository::Instance()->getRoot(),&dpair);
          if (filePath != "") {
             AbstractRepository::Instance()->createEvidenceStoreEntity(&storeEntity, ocfa::store::Filename(filePath), hard);
          } else {
            filePath = inFsEntity->getSoftLinkablePath(&dpair);
            if (filePath != "") {
               AbstractRepository::Instance()->createEvidenceStoreEntity(&storeEntity, ocfa::store::Filename(filePath), soft,&dpair);
            } else {
               AbstractRepository::Instance()->createEmptyEvidenceStoreEntity(&storeEntity);
               off_t entitysize=inFsEntity->getSize();
               storeEntity->openStream(entitysize);
               module::ConcreteWriteFacet writefacet(storeEntity);
               inFsEntity->streamToOutput(writefacet);
               storeEntity->closeStream();
            }
          }
        }
	return storeEntity;	
    }    


    ocfa::evidence::Evidence *EvidenceTreeWalker::createDerivedEvidence(Evidence *inParentEvidence, std::string filePath, 
							ocfa::misc::Scalar evidenceName, 
							std::string parentChildRelationName, 
							std::vector<ocfa::evidence::CoParent > *inCoParents){
    
      TreeGraphNode *node = 0;
      TreeGraphFactory *fileSystem = TreeGraphModuleLoader::getFactory();
      ocfaLog(LOG_DEBUG, string("filepath=") + filePath); 
      misc::EvidenceIdentifier *eidf=inParentEvidence->getEvidenceIdentifier();
      std::string basets=eidf->getCaseID() + "-" + eidf->getEvidenceSourceID() + "-" + eidf->getItemID() + "-" +
eidf->getEvidenceID();

      fileSystem->createTopNode( filePath, &node,basets);
      if (mShouldDelete){
	node->unlinkOnDestruct();
      }
      Evidence *newEvidence  = 
	createEvidenceFromFsEntity(inParentEvidence, node, parentChildRelationName, &evidenceName, inCoParents); 
      if (node->hasSubEntities()){

	processSubEntities(newEvidence, node);
      }
      delete node;
      return newEvidence;
    }    
  
    ocfa::evidence::Evidence *EvidenceTreeWalker::createDerivedEvidence(ocfa::misc::Item *inParentItem, std::string filePath, 
					      ocfa::misc::Scalar evidenceName){
      TreeGraphNode *node = 0;
      TreeGraphFactory *fileSystem = TreeGraphModuleLoader::getFactory();
      ocfaLog(LOG_DEBUG, string("filepath=") + filePath); 
      std::string basets=inParentItem->getCaseID() + "-" + inParentItem->getEvidenceSourceID() + "-" + inParentItem->getItemID() + "-e" + boost::lexical_cast<std::string>(inParentItem->getTopEvidenceCount()+1); 

      fileSystem->createTopNode( filePath, &node,basets);
      if (mShouldDelete){
	node->unlinkOnDestruct();
      }
      Evidence *newEvidence  = 
	createEvidenceFromFsEntity(inParentItem, node, &evidenceName); 
      if (node->hasSubEntities()){
	
	processSubEntities(newEvidence, node);
      }
      
      return newEvidence;
    }     

    bool EvidenceTreeWalker::isEmpty(string inDir){

      TreeGraphNode *node =0;
      bool empty = false;
      TreeGraphFactory *fileSystem = TreeGraphModuleLoader::getFactory();
      ocfaLog(LOG_DEBUG, string("path=") + inDir); 
      fileSystem->createTopNode(inDir, &node,"INVALID");
      ocfaLog(LOG_DEBUG, string("node=") + node->getName()); 
      empty = !(node->hasSubEntities());
      delete node;
      return empty;


    }


    void EvidenceTreeWalker::emptyPath(string inPath){
      
      TreeGraphNode *node =0;
      TreeGraphFactory *fileSystem = TreeGraphModuleLoader::getFactory();
      ocfaLog(LOG_DEBUG, string("path=") + inPath); 
      fileSystem->createTopNode(inPath, &node,"INVALID");
      ocfaLog(LOG_DEBUG, string("node=") + node->getName()); 
      if (node->hasSubEntities()){

	node->resetSubEntityIterator();
	do {

	  TreeGraphNode *subEntity = 0;
	  node->getCurrentSubEntity(&subEntity);
	  delete subEntity;
	} while (node->nextSubEntity());
        //RJM: TAGRJM2: I would sugest resetting the sub entity iterator over here as to avoid having to
        //     call it during normal treewalking activity at TAGRJM1 all the time. Explicitly deteting a tree is
        //     quite exceptional a situation, and we should probably limit the unneeded invocation of this method
        //     for hundreds of thousands upto millions of times by moving it.
      }
      else {
	getLogStream(LOG_ERR) << " EvidenceTreewalker::emptyPath path is already empty" << endl;
      }


    }
    

    bool EvidenceTreeWalker::checkIfSameDevice(std::string first, std::string second) {
       struct stat sres;
       if (lstat(first.c_str(), &sres) == -1) {
          throw OcfaException("Could not stat " + first + " in EvidenceTreeWalker::checkIfSameDevice", 0);
       }
       dev_t pathdev = sres.st_dev;
       if (lstat(second.c_str(), &sres) == -1) {
          throw OcfaException("Could not stat " + second + " in EvidenceTreeWalker::checkIfSameDevice", 0);
       }
       return (pathdev == sres.st_dev);
    }

  }


}


      
