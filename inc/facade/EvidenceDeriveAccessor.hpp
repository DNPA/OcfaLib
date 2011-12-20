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
						
#ifndef __OCFAACCESSORDERIVE_
#define __OCFAACCESSORDERIVE_
#include "EvidenceFileAccessor.hpp"
#include "evidence/Evidence.hpp"
#include "module/EvidenceTreeWalker.hpp"
namespace ocfa {

  namespace facade {
    
    class EvidenceDeriveAccessor : public EvidenceFileAccessor {
      
    public:
      EvidenceDeriveAccessor(std::string inName, std::string inNamespace);
      virtual ~EvidenceDeriveAccessor();


      /**
       * derives a new evidence from a file. The calles takes responsbility for the new evidence.
       * @param fileName the path to the new file.
       * @param evidenceName the name of the file in the evidence.
       * @param parentChildRelationName the name of the relationship between the new evidence and its parent. 
       *        The relationtype will be check by the ocfa.xsd and will genereate an exception if not found.
       */
      ocfa::evidence::Evidence *derive(std::string fileName, ocfa::misc::Scalar evidenceName, 
		       std::string parentChildRelationName ="undefined", 
		       std::vector<ocfa::evidence::CoParent > *inCoParents = 0);


      /**
       * Derives new Evidence from OcfaContent. The calles takes responsibility for the new evidence.
       * @param inContent content of the new evidence.
       * @param evidenceName the name of the file in the evidence.
       * @param parentChildRelationName the name of the relationship between the new evidence and its parent. 
       *        The relationtype will be check by the ocfa.xsd and will genereate an exception if not found.
       *
       */
      ocfa::evidence::Evidence *derive(ocfa::misc::OcfaContent inContent, ocfa::misc::Scalar evidenceName, 
		       std::string parentChildRelationName = "undefined", 
		       std::vector<ocfa::evidence::CoParent > *inCoParents = 0);


      /**
       * submits the evidence to the router.
       *
       */      
      virtual void submitEvidence(ocfa::evidence::Evidence *inEvidence, 
			  const ocfa::misc::ModuleInstance *inRouter = 0);
      std::string getWorkDir(); 

      /**
       * overloads its super class to allow the mpRouter to be set.
       *
       */
      virtual void processEvidenceMessage(const ocfa::message::Message &message);

    protected:
      /**
       * finds and/or created the working directory which can be used to store derived Evidences befor
       * they are committed into the repositorty
       */
      void computeWorkDir();

      /**
       * helper method that assures inDirPath exists.
       */
      void createOrExist(std::string inDirPath);
      EvidenceDeriveAccessor(const EvidenceDeriveAccessor& eda):
	      EvidenceFileAccessor(eda),
	      mWorkDir(""),
	      mTreeWalker(0),
	      mpRouter(0)
      {
         throw misc::OcfaException("No copying allowed of EvidenceDeriveAccessor",this);
      }
      const EvidenceDeriveAccessor& operator=(const EvidenceDeriveAccessor&) {
         throw misc::OcfaException("No assignment allowed of EvidenceDeriveAccessor",this);
	 return *this;
      }

      /**
       * retrieves the treewalker. 
       */
      virtual ocfa::module::EvidenceTreeWalker *getTreeWalker();
      

      /**
       * sets the treewalker. the EvidenceDeriveAccessor assumes responsability 
       * over the object.
       */
      virtual void setTreeWalker(ocfa::module::EvidenceTreeWalker **treeWalker);
     private:
      /**
       * working directory of the 
       */
      std::string mWorkDir;
      ocfa::module::EvidenceTreeWalker *mTreeWalker;
     protected:
      misc::ModuleInstance *mpRouter;
    };
  }
}
#endif
