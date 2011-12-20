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
						
#include <libgen.h>
#include"store/AbstractRepository.hpp"
#include"facade/KickstartAccessor.hpp"
#include"module/EvidenceTreeWalker.hpp"
#include "store/AbstractRepository.hpp"
#include"message/Message.hpp"
#include"message/MessageBox.hpp"
#include"treegraph.hpp"

using ocfa::store::AbstractRepository;

namespace ocfa {

  namespace facade {

    KickstartAccessor::KickstartAccessor(string name, string mnamespace): 
	    BaseAccessor(name, mnamespace,true),
	    _router(0)
    {
      _router = new ModuleInstance("localhost", "router", "core", "DNTCR");
    }


    void KickstartAccessor::processEvidence(){

    }



    void KickstartAccessor::TreeGraphKickstart(std::string caseid, std::string sourceid, std::string itemid,std::string inEvidenceName,std::string module, std::map<std::string,misc::Scalar> *attributes, std::string path) {
        ocfa::misc::Item *item = 0;
        ocfa::store::AbstractRepository::Instance()->createItem(&item, caseid, sourceid, itemid);
        ocfa::module::EvidenceTreeWalker *etw = new ocfa::module::EvidenceTreeWalker(this,_router,module,false,attributes);
        Scalar *evName = 0;
      if (inEvidenceName == ""){
        evName = new Scalar(module);
      }
      else {
        evName = new Scalar(inEvidenceName);
      }
      string pcrelation = "undefined";
      ocfa::treegraph::TreeGraphFactory *f = ocfa::treegraph::TreeGraphModuleLoader::getFactory();
      ocfa::treegraph::TreeGraphNode *node;
      std::string timesource=caseid + "-" + sourceid + "-" + itemid + "-e0j0";
      f->createTopNode(path, &node,timesource);
      ocfa::evidence::Evidence *newEvidence = etw->createEvidenceFromFsEntity(item, node, evName);
      if (node->hasSubEntities()){
         etw->processSubEntities(newEvidence, node);
      } 
      submitEvidence(newEvidence, _router);
      delete newEvidence;
      delete node;
      delete evName;
    }

    void KickstartAccessor::KickstartEvidence(string caseid, string sourceid, string itemid, string inEvidenceName,
					string fsmodule, std::map<std::string,misc::Scalar> *attributes, bool 
ismap){

       //FIXME: the KickstartAccessor should not be creating items, this should be a job for the kickstart program.
      //The kickstart program should be able to kickstart multiple evidences for an item !!!

      ocfa::misc::Item *item = 0;
      ocfa::store::AbstractRepository::Instance()->createItem(&item, caseid, sourceid, itemid);

      ocfa::module::EvidenceTreeWalker *etw = new ocfa::module::EvidenceTreeWalker(this,_router,fsmodule,ismap,attributes); 
      ocfaLog(LOG_DEBUG, "Constructed treewalker object");
      Scalar *evName = 0;
      if (inEvidenceName == ""){
	evName = new Scalar(fsmodule);
      }
      else {
	
	evName = new Scalar(inEvidenceName);
      }
      string pcrelation = "direntry";
      ocfa::treegraph::TreeGraphFactory *f = ocfa::treegraph::TreeGraphModuleLoader::getFactory();
      ocfa::treegraph::TreeGraphNode *node;
      f->createTopNode("", &node,"INVALID");
      getLogStream(LOG_DEBUG) << "KickstartEvidence with module" << fsmodule << endl;
      ocfa::evidence::Evidence *newEvidence = etw->createEvidenceFromFsEntity(item, node, evName);
      ocfaLog(LOG_DEBUG, "Starting processnode");
      //etw->processPath(e, suspectpath,pcrelation, s);
      if (node->hasSubEntities()){
	etw->processSubEntities(newEvidence, node);
      }
      getLogStream(LOG_DEBUG) << "submitting " << newEvidence->getEvidencePath().asASCII() << endl;
      submitEvidence(newEvidence, _router);
      delete newEvidence;
      delete node; 
      delete evName;
    }

    void KickstartAccessor::KickstartEvidence(string caseid, string sourceid, string itemid, string suspectpath, string inCharset, string inEvidenceName){

       //FIXME: the KickstartAccessor should not be creating items, this should be a job for the kickstart program.
      //The kickstart program should be able to kickstart multiple evidences for an item !!!

      ocfa::misc::Item *item = 0;
      ocfa::store::AbstractRepository::Instance()->createItem(&item, caseid, sourceid, itemid);

      ocfa::module::EvidenceTreeWalker *etw = new ocfa::module::EvidenceTreeWalker(this, _router, suspectpath, false, inCharset);

      // JBS for now, it is not an encaseexport of a file system. 
      //std::map<std::string,std::string> attributes;
      //attributes["path"]=suspectpath;
      // ocfa::module::EvidenceTreeWalker *etw = new ocfa::module::EvidenceTreeWalker(this, _router, suspectpath, false);
      //      ocfa::module::EvidenceTreeWalker *etw = new ocfa::module::EvidenceTreeWalker(this, _router,"EncaseExportOfFileSystem",true,&attributes); 
      ocfaLog(LOG_DEBUG, "Constructed treewalker object");
      Scalar *evName = 0;
      if (inEvidenceName == ""){

	
	char *fileName = strdup(suspectpath.c_str());
	fileName = basename(fileName);
	evName = new Scalar(fileName);
      }
      else {
	
	evName = new Scalar(inEvidenceName);
      }
      string pcrelation = "direntry";
      ocfa::treegraph::TreeGraphFactory *f = ocfa::treegraph::TreeGraphModuleLoader::getFactory();
      ocfa::treegraph::TreeGraphNode *node = 0;
      f->createTopNode(suspectpath, &node,"INVALID");
      getLogStream(LOG_DEBUG) << "KickstartEvidence: path is " << suspectpath << endl;
      getLogStream(LOG_DEBUG) << "node hard is " << node->getHardLinkablePath(AbstractRepository::Instance()->getRoot()) << endl;
      getLogStream(LOG_DEBUG) << "node soft is " << node->getSoftLinkablePath() << endl;

      ocfa::evidence::Evidence *newEvidence = etw->createEvidenceFromFsEntity(item, node, evName);
      ocfaLog(LOG_DEBUG, "Starting processnode");
      //etw->processPath(e, suspectpath,pcrelation, s);
      if (node->hasSubEntities()){
	etw->processSubEntities(newEvidence, node);
      }
      getLogStream(LOG_DEBUG) << "submitting " << newEvidence->getEvidencePath().asASCII() << endl;
      submitEvidence(newEvidence, _router);
      delete newEvidence;
      delete node; 
      delete evName;
    }



      
    
  

  }

}
