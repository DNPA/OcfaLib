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
						
#ifndef INCLUDED_PGBLOBREPOSITORY_HPP
#define INCLUDED_PGBLOBREPOSITORY_HPP
#include "BlobMetaStoreEntity.hpp"
#include "PgRepository.hpp"

namespace ocfa {

  namespace store {

    class PgBlobRepository: public PgRepository {
    public:

      /**
       * initializes PgRepsository and creates a connection to a postgresdatabase.
       *
       */
      PgBlobRepository(string root);
      ~PgBlobRepository();
  
      virtual void commitMetaChange(MetaStoreEntity *blobmeta);

    protected:

      void StoreMetadata(OcfaHandle &handle, BlobMetaStoreEntity &blobmeta);
      void getBlobMetaStoreEntity(const OcfaHandle &handle, BlobMetaStoreEntity &blobmeta); 
      virtual misc::OcfaHandle createHandle(StoreEntity &st);
      virtual void getStoreEntity(OcfaHandle & h, StoreEntity &st);
      virtual void getMetaStoreEntity(OcfaHandle & h, MetaStoreEntity **se);
      virtual MetaStoreEntity *constructMetaEntity(string d_root = "");
      void prepareInsertMetaData();
      void prepareInsertEvidence();
      void prepareUpdateMetaData();
      void prepareSelectMetaData();


    };
  }

}

#endif
