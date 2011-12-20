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
						
#include <sys/types.h>
#include <sys/stat.h>
#include "ConcreteEvidenceStoreEntity.hpp"
#include "misc/syslog_level.hpp"
#include "store/AbstractRepository.hpp"
#include <string>

#include <errno.h>
#include "string.h"


namespace ocfa {
  namespace store {
    using namespace std;
    using namespace ocfa::misc;
    

    std::string ConcreteEvidenceStoreEntity::TABLE_NAME = "evidencestoreentity";
    ConcreteEvidenceStoreEntity::ConcreteEvidenceStoreEntity(string root): ConcreteStoreEntity(root) {
     
    }

    ConcreteEvidenceStoreEntity::~ConcreteEvidenceStoreEntity(){      
    }
    

    void ConcreteEvidenceStoreEntity::setPermissions(int fd){
      
      if (fchmod(fd, S_IRUSR | S_IRGRP) != 0){
	 string msg(strerror(errno));
         throw OcfaException(string("chmod failed: ")+msg);
      }
      
    }

    string ConcreteEvidenceStoreEntity::tableName(){ 
      return TABLE_NAME; 
    }

    ocfa::misc::OcfaHandle ConcreteEvidenceStoreEntity::getHandle(){
      return d_handle;
    }

    void ConcreteEvidenceStoreEntity::closeStream(){

      ConcreteStoreEntity::closeStream();
      ocfaLog(LOG_INFO, "Calling setHandle"); 
      AbstractRepository::Instance()->setHandle(*this);


    }


    DigestPair *ConcreteEvidenceStoreEntity::getDigestPair(){

      if (d_digest == 0){

	ocfaLog(LOG_WARNING, 
		string("computing a digest. It was already computed and stored in ")
		+ "the corresponding metastoreentity. Inefficient!");
	calcDigest(d_root + getStoreName());
      }
      return d_digest; 
      
    }


  }
}
