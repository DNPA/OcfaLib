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
						
#include "SimpleRepository.hpp"
#include <libpq-fe.h>
#include <vector>
#include<map>
#ifndef ERRCODE_UNIQUE_VIOLATION
 #define ERRCODE_UNIQUE_VIOLATION "23505"
#endif

#ifndef INCLUDED_PGREPOSITORY_HPP
#define INCLUDED_PGREPOSITORY_HPP

namespace ocfa {

  namespace store {
    #define CONNECTINFO_STRING_LENGTH        1024
    #define LIMIT_STR_LENGTH                 32

    class PgRepository:public SimpleRepository {
    public:

      /**
       * initializes PgRepsository and creates a connection to a postgresdatabase.
       *
       */
      PgRepository(string root);
      ~PgRepository();
      // helper message that returns the errormessage when an error occurred in the database.
      string ErrorMessage();
      /*JCW:CODEREVIEW: overbodig?
      virtual bool dropStoreEntity(misc::OcfaHandle &h);
      */

     /**
       * Retrieves all metastoreentities that were suspended.
       *
       * @param suspended: Empty vector that will be filled with
       * handles to suspedned metastoreentities.
       * @param count the maximum amount of suspended metaentities that should be retrieved. 0 means
       *  every.
       * @return the actual amount of retrieved suspended metaentities.
       */
      virtual unsigned int getSuspendedMetaEntities(vector<OcfaHandle > &suspended, unsigned int count = 0);
      
      /**
       * Returns all metastoreentities 
       *
       * @param suspended: Empty vector that will be filled with
       * handles to metastoreentities.
       * @param count the maximum amount of suspended metaentities that should be retrieved. 0 means
       *  every.
       * @return the actual amount of retrieved  metaentities.
       */
      virtual unsigned int getMetaEntities(vector<OcfaHandle > &metas, unsigned int count = 0);

     /**
       * Retrieves all evidencestoreentities 
       *
       * @param evidences: Empty vector that will be filled with
       * handles to metastoreentities.
       * @param count the maximum amount of suspended metaentities that should be retrieved. 0 means
       *  every.
       * @return the actual amount of retrieved  metaentities.
       */
      virtual unsigned int getEvidenceEntities(vector<OcfaHandle > &evidences, unsigned int count = 0);

      /**
       * sets the handle of a store entity to a newly created one.
       *
       */
      virtual void setHandle(StoreEntity &se);

      /**
       * checks whether the metastoreentity has a corresponding evidencestorehandle.
       */
       virtual bool hasEvidenceStoreHandle(ocfa::store::MetaStoreEntity &inMeta);

      /**
       * fills a vector of metadataHandles for every metastoreentity that refers to
       * the given EvidenceStoreEntity
       */
      virtual void fillMetaDataHandles(std::vector<ocfa::misc::OcfaHandle> &outMetaDataHandles, 
				       ocfa::store::EvidenceStoreEntity &inDataHandle);
     /**
       * returns the evidencstoreentity that belongs to a certain metadatahandle. Throws an ocfaexception
       * if one does not exist.
       *
       */
      virtual ocfa::misc::OcfaHandle getEvidenceStoreHandle(ocfa::store::MetaStoreEntity &inMeta);

     /**
       * Suspends a metastoreentity.
       * 
       * @param h handle to the metastoreentity that will be
       * suspended.
       *
       */     
      virtual void suspendMetaEntity(OcfaHandle h);
     /**
       * Unsuspends a metastoreentity.
       * @param h the handle to the metastoreentity that will be unsuspended.
       */
      virtual void unsuspendMetaEntity(OcfaHandle h);
      /**
       * creates an Item used for kickstarting. Should throw an
       * exception if the item already exists.
       * @param **item the item that is being created. The caller assumes responsibility for the newly
       *    created item.
       * @param inCaseId the case id of the item.
       * @param inSourceId the sourceId of the Item
       * @param inItem id the item name of the item to be created.
       */
      virtual void createItem(Item **item, string nCaseId, string inSourceId, string inItemId);

      virtual void commitMetaChange(MetaStoreEntity *meta) = 0;


    protected:

      /**
       * Sets a link between the data and the metadata by filling the metadatainfo table, 
       * so that it can be retrieved.
       * @param inDataHanlde the handel to the EvidenceDataStoreEntity. If the handle is empty it 
       * is considered to be not present.
       */
      virtual void setMetaDataInfo(const OcfaHandle &inMetaHandle, EvidenceIdentifier &inIdentifier, 
				   const OcfaHandle &inDataHandle);

      /**
       * virtual that creates a shiny new handle that can be assigned to that storeentity. Inserts 
       * a the reference to the storeentity into the postgres database. Throws an exception if errors occur.
       * @param st the storeentity that gets a nice new handle.
       *
       */
      virtual misc::OcfaHandle createHandle(StoreEntity &st) = 0;
      /**
       * method called by the constructor of a storeentity. Gets the file belonging to the handle h and puts it in
       * st.
       * @param h the handle from which the storeentity should be initialize.d
       * @param st the storeentity that shoudl be initialized.
       */
      virtual void getStoreEntity(OcfaHandle & h, StoreEntity &st) = 0;
      virtual void getMetaStoreEntity(OcfaHandle & h, MetaStoreEntity **st) = 0;
      virtual MetaStoreEntity *constructMetaEntity(string d_root = "") = 0;
      /**
       * returns the first count entities from the tablename. used by getMetaEntities and getEvidenceEntities.
       * @param entities. the vector containin
       */
      unsigned int getEntities(vector<OcfaHandle> &entities, unsigned int count, std::string inTableName);
      std::string getSerialItemId(std::string inCaseId, std::string inSourceId, 
					   std::string inItemId);
      void throwDatabaseException(std::string command, PGresult *inResult);  
      std::string getCachedItemId(std::string inCaseId, std::string inSourceId, std::string inItemId); 
      PGconn *d_connection;
    private:
      std::map<std::string, std::string> _itemidmap;
    };
  }

}

#endif
