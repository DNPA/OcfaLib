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
						
#ifndef __OCFAACCESSORDERIVECP_
#define __OCFAACCESSORDERIVECP_
#include "EvidenceFileAccessor.hpp"
#include "evidence/Evidence.hpp"
#include "module/EvidenceTreeWalker.hpp"
namespace ocfa {

  namespace facade {
    
    class CpEvidenceDeriveAccessor : public EvidenceFileAccessor {
      
    public:
      CpEvidenceDeriveAccessor(std::string inName, std::string inNamespace,std::string fsmodule="",std::map<std::string,std::string> *attributes=0);
      virtual ~CpEvidenceDeriveAccessor();


      /**
       * derives a new evidence from a file. The calles takes responsbility for the new evidence.
       * @param fileName the path to the new file.
       * @param evidenceName the name of the file in the evidence.
       * @param parentChildRelationName the name of the relationship between the new evidence and its parent. 
       */
      ocfa::evidence::Evidence *derive(std::string fileName, ocfa::misc::Scalar evidenceName, 
		       std::string parentChildRelationName ="undefined", 
		       std::vector<ocfa::evidence::CoParent > *inCoParents = 0);


      /**
       * Derives new Evidence from OcfaContent. The calles takes responsibility for the new evidence.
       * @param inContent content of the new evidence.
       * @param evidenceName the name of the file in the evidence.
       * @param parentChildRelationName the name of the relationship between the new evidence and its parent. 
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

      /**
       * Set an other fs module for derivation of evidence.
       */
    
    protected:
      /**
       * helper method that assures inDirPath exists.
       */
      void createOrExist(std::string inDirPath);
      CpEvidenceDeriveAccessor(const CpEvidenceDeriveAccessor& eda):
	      EvidenceFileAccessor(eda),
	      mTreeWalker(0),
	      mpRouter(0)
      {
         throw OcfaException("No copying allowed of CpEvidenceDeriveAccessor",this);
      }
      const CpEvidenceDeriveAccessor& operator=(const CpEvidenceDeriveAccessor&) {
         throw OcfaException("No assignment allowed of CpEvidenceDeriveAccessor",this);
	 return *this;
      }
    private:
      /**
       * working directory of the 
       */
      ocfa::module::EvidenceTreeWalker *mTreeWalker;
      ModuleInstance *mpRouter;
    };
  }
}
#endif
