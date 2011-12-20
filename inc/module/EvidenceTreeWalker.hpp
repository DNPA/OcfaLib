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
						
#ifndef EVIDENCETREEWALKER_HPP
#define EVIDENCETREEWALKER_HPP
#define TREEWALK_NODE_INTERRUPTION_COUNT 100
#include <string.h>
#include "../OcfaObject.hpp"
#include "../evidence/Evidence.hpp"
#include "../misc/ModuleInstance.hpp"
#include "../misc/Scalar.hpp"
#include "../treegraph/TreeGraphNode.hpp"
#include "../store/linktype.hpp"
#include "../store/Filename.hpp"
#include "../store/EvidenceStoreEntity.hpp"
/**
 * Helper class that walks through a file tree and submits every file
 * in it.  TODO: Make a isEncase functionality and allos the selection
 * of the fsstat to include the option of encase images.
 * 
 */
namespace ocfa {  
 
  namespace module {

    class OcfaModule;
    
    class EvidenceTreeWalker : public ocfa::OcfaObject {
      
    private:
      /**
       * The module that is needed to send new Evidence to the router.
       */
      ocfa::module::OcfaModule *module;
      /**
       * the router to which the evidences shoudl be sent.
       *
       */
      ocfa::misc::ModuleInstance *router;

      /**
       * Flag describing whether the files that are being processed
       * should be deleted.
       */
      bool mShouldDelete;

      /**
       * A number indicating if interuptions should be processed
       */
      size_t ncount;
    protected:
      EvidenceTreeWalker(const EvidenceTreeWalker& etw):
	      OcfaObject(etw),
	      module(0),
	      router(0),
	      mShouldDelete(false),
	      ncount(0)
      {
          throw misc::OcfaException("No copying allowed of EvidenceTreeWalker",this);
      }
      const EvidenceTreeWalker& operator=(const EvidenceTreeWalker&) {
	  throw misc::OcfaException("No assignment allowed of EvidenceTreeWalker",this);
	  return *this;
      }
      /**
        * This method tries to determine if two paths reside on the same device. This is to be used in conjunction with
        * directory tree modules only.
        *
        */
       static bool checkIfSameDevice(std::string firstpath,std::string secondpath);

    public:

      /**
       * Constructor. Initializes the EvidenceTreeWalker and the FileSystem. Also sets the flags depending
       * on the place of the repository and whether the files shoudl be deleted afterwards.
       * @param inModule the module that is used to submit selected evidences (Maybe this should be a messagebox.).
       */
      EvidenceTreeWalker(OcfaModule *inModule, ocfa::misc::ModuleInstance *inRouter, std::string inInitPath, 
			 bool inShouldDelete, std::string charSet = "AUTO");

       /* 
	* The constructor but now specifying what fs module to use and with what attributes 
	*/
      EvidenceTreeWalker(OcfaModule *inModule, misc::ModuleInstance *inRouter,
		     std::string fsmodule, bool ismap ,std::map<std::string,misc::Scalar> *attributes=0);


      virtual ~EvidenceTreeWalker();
      /**
       * Wrapper around process node. Makes an fsEntity node from the given file and then calles processNode.
       * @param parent the parent of the evidence that should  be creates from inPath
       * @param inPath the path of the file or directory from which an evidence should be created.
       * @param inParentChildRelation the relation between the parent and the new evidence that will be created 
       * @param from the current one.
       */
      virtual void processPath(ocfa::evidence::Evidence *parent, std::string &inPath, std::string inParentChildRelation, 
		       ocfa::misc::Scalar *inEvidenceName = 0);
      

      /**
       * recursive method that processes a directory tree. It will submit alle entries as evidences.
       * @param parent the parent evidence of the entity from which an evidence should be created. Might be 0 to 
       * indicate that the current fsEntity is the top evidence.
       * @param inFsEntity the Fs entity from which an entity must be made and from whom other fsEntities might be found.
       * @param inParentChildRelation the relation between the parent and the child.
       */
      virtual void processNode(ocfa::evidence::Evidence *parent, ocfa::treegraph::TreeGraphNode *inFsEntity, 
		       const std::string inParentChildRelation, ocfa::misc::Scalar *inEvidenceName = 0);
      
      /**
       * method that creates one evidence from an FsEntity. The newly created evidence will be owned by the calling method.
       * @param the parent of the evidence that will be created. 
       * @param inFsEntity the FsEntity from which an evidence should be made.
       * @return the evidence representing the FsEntity.
       * 
       */
      virtual ocfa::evidence::Evidence *createEvidenceFromFsEntity(ocfa::evidence::Evidence *inParent, 
								   ocfa::treegraph::TreeGraphNode *inFsEntity, 
								   const std::string inRelation, 
								   ocfa::misc::Scalar *inEvidenceName = 0,
								   std::vector<ocfa::evidence::CoParent > *coParents = 0);

      virtual ocfa::evidence::Evidence *createEvidenceFromFsEntity(ocfa::misc::Item *inParent, 
								   ocfa::treegraph::TreeGraphNode *inFsEntity,
								   ocfa::misc::Scalar *inEvidenceName = 0);



      /**
       * creates a evidencestoreentity from an FsEntity. The newly
       * created evidence will be owned by the calling method.
       * 
       * @param inFsEntity the entity from which the evidnecestoreentity should be created.
       * @param digestPair the digestpair that will be filled with the digest of inFsEntity if it exists.
       * 
       * @return an evidnecestorentity representing the content of
       * fsEntity. Can be 0 if the fsentity has no content (e.g. a
       * directory)
       *
       */
      virtual ocfa::store::EvidenceStoreEntity *createStoreEntityFromFsEntity(ocfa::treegraph::TreeGraphNode *inFsEntity);      
      

      /**
       * derived a new evidence from the parent one.  The caller is reponsible for the derived evidence.
       *
       */
      virtual ocfa::evidence::Evidence *createDerivedEvidence(ocfa::evidence::Evidence *inParentEvidence, std::string fileName, 
					       ocfa::misc::Scalar evidenceName, 
					       std::string parentChildRelationName ="undefined", 
					       std::vector<ocfa::evidence::CoParent > *inCoParents = 0);

      /**
       * derived a new evidence from the parent one.  The caller is reponsible for the derived evidence.
       *
       */
      virtual ocfa::evidence::Evidence *createDerivedEvidence(ocfa::misc::Item *inParentItem, std::string fileName, 
					       ocfa::misc::Scalar evidenceName);


      /**
       * checks whether directory is empty.
       *
       */
      bool isEmpty(std::string inDir);

      /**
       * empties a path. The path should point to a directory. All
       * entries in the directory are removed. The directory itself
       * will exist.
       *
       */
      void emptyPath(std::string inPath);
    
      void processSubEntities(ocfa::evidence::Evidence *inEvidence, ocfa::treegraph::TreeGraphNode *inEntity);

    };
  }
}
#endif
