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
						
#include "store/EvidenceStoreEntity.hpp"
#include "ConcreteStoreEntity.hpp"
#ifndef DEFINED_CONCRETEEVIDENCESTOREENTITY_HPP 
#define DEFINED_CONCRETEEVIDENCESTOREENTITY_HPP

namespace ocfa {
  namespace store {
    // EvidenceStoreEntity class encapsulates suspect data files
    class ConcreteEvidenceStoreEntity: public EvidenceStoreEntity, protected ConcreteStoreEntity {
    public:
       
      /**
       * Creates a EvidenceStoreEntity. Normally you do not use this method directly but cal;
       * AbstractRepository 
       * @param root the directory where the evidencestoreentity should be placed in.
       */
      ConcreteEvidenceStoreEntity(string root);
      virtual ~ConcreteEvidenceStoreEntity();

      /**
       * Returns the handle to the entity. The handle can be used
       * later to recreated the entity. An exception is thrown if no
       * handle exists.
       * 
       * @return the handle tot the entity.
       */
      virtual ocfa::misc::OcfaHandle getHandle();
      virtual void closeStream();
     /**
       * returns the digestpair of the storeentity. The storeentity 
       * has ownership over the digestpair. 
       * @return the digestpair 
       *
       */
      ocfa::misc::DigestPair *getDigestPair();

      /**
       * the name of the table in which references to
       * evidencestoreentities should be placed.
       */
      static string TABLE_NAME;
    protected:
      virtual string tableName();
      virtual void setPermissions(int fd);
    };
  }
}

#endif
