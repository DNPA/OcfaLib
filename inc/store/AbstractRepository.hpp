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
						
#include <stdio.h>
#include <time.h>
#include <string>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <libgen.h>
#include <dlfcn.h>
#include <sys/types.h>
#include "../misc.hpp"
#include "../OcfaObject.hpp"
#include "MetaStoreEntity.hpp"
#include "StoreEntity.hpp"
#include "EvidenceStoreEntity.hpp"
#include "linktype.hpp"

#ifndef INCLUDED_ABSTRACTREPOSITORY_HPP
#define INCLUDED_ABSTRACTREPOSITORY_HPP


using namespace std;
//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better
namespace ocfa {
  /**
   * This part of the API holds abstracts the implementation of data storage for the users and evidence API. */
  using namespace misc;
  namespace store {
    int version();
    int mainversion();
    int subversion();

    const int API_VERSION = 1;
    const int MAXFILESPERDIR = 1024;

/**
 * Repository; static Class shared by all entities within a process holding all data.
 *
 * Only StoreEntities have access to the Repository.
 * StoreEnties can ask the repository to be stored by supplying *this.
 */

   
    class AbstractRepository: public OcfaObject {
    public:


      /**
       * Returns an instance of an abstract repository.
       * @param concrete repository. 
       */
      static AbstractRepository *Instance();
      /**
       * Retrieves all metastoreentities that were suspended.
       *
       * @param suspended: Empty vector that will be filled with
       * handles to suspedned metastoreentities.
       * @param count the maximum amount of suspended metaentities that should be retrieved. 0 means
       *  every.
       * @return the actual amount of retrieved suspended metaentities.
       */
      virtual unsigned int getSuspendedMetaEntities(vector<OcfaHandle > &suspended, unsigned int count = 0) = 0;


      /**
       * Returns all metastoreentities 
       *
       * @param suspended: Empty vector that will be filled with
       * handles to metastoreentities.
       * @param count the maximum amount of suspended metaentities that should be retrieved. 0 means
       *  every.
       * @return the actual amount of retrieved  metaentities.
       */
      virtual unsigned int getMetaEntities(vector<OcfaHandle > &metas, unsigned int count = 0) = 0;



      /**
       * Retrieves all evidencestoreentities 
       *
       * @param evidences: Empty vector that will be filled with
       * handles to metastoreentities.
       * @param count the maximum amount of suspended metaentities that should be retrieved. 0 means
       *  every.
       * @return the actual amount of retrieved  metaentities.
       */
      virtual unsigned int getEvidenceEntities(vector<OcfaHandle > &evidences, unsigned int count = 0) = 0;

      /* JCW:CODEREVIEW: Niet gebruikt?
      virtual bool dropStoreEntity(OcfaHandle &h) =0; 
      */
      
      /**
       * Suspends a metastoreentity.
       * 
       * @param h handle to the metastoreentity that will be
       * suspended.
       *
       */
      virtual void suspendMetaEntity(OcfaHandle h) = 0;

      /**
       * Unsuspends a metastoreentity.
       * @param h the handle to the metastoreentity that will be unsuspended.
       */
      virtual void  unsuspendMetaEntity(OcfaHandle h) = 0;
      // MetastoreEntties are only derived from memory
      //      virtual void createMetaStoreEntity(MetaStoreEntity **ms, const Filename & file, linktype lt, EvidenceStoreEntity *inDataEntity,  ocfa::misc::EvidenceIdentifier &inId) = 0;

      /**
       * Derives a MetaStoreEntity from some content.
       * 
       * @param **ms pointer to pointer to a metastoreentity. The
       * pointer will be set to a newly created metastoreentity. The caller takes reponsibility
       * for the newly created entity.
       * @param buf the content with which the newly created metastoreentity will be filled.
       * @param len The length of buf.
       * @param inDataEntity. The dataentity about which the metastoreentity has metadata.
       *
       */  
      virtual void createMetaStoreEntity(MetaStoreEntity **ms, const unsigned char *buf,
					 unsigned int len, ocfa::misc::EvidenceIdentifier &inId, 
					 ocfa::misc::OcfaHandle *inDataHandle = 0) = 0;

      /**
       * Derives a MetaStoreEntity from some content.
       * 
       * @param **ms pointer to pointer to a metastoreentity. The
       * pointer will be set to a newly created metastoreentity.
       * @param content the content with which the newly created metastoreentity will be filled.
       * @param inDataEntity. The dataentity about which the metastoreentity has metadata.
       *
       */
      virtual void createMetaStoreEntity(MetaStoreEntity **ms, const OcfaContent &content,
					 ocfa::misc::EvidenceIdentifier &inId, 
					 ocfa::misc::OcfaHandle *inDataEntity = 0) = 0;

      /**
       * Derives a EvidenceStoreEntity from a file.
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       * @param file the file whose content will be encapsulated by the evidencestoreentity.
       * @param lt. Soft or hard. Indicates the whether the storage contains only a reference to 
       * the entity (soft) or should contain a copy or hard reference to the data.
       *
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **es, const Filename & file, linktype lt,ocfa::misc::DigestPair** dp=0) = 0;

      /**
       * Creates an EvidenceStoreEntity from an OcfaContent.
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       * @param content contents of the file.
       *
       */
       virtual void createEvidenceStoreEntity(EvidenceStoreEntity **es, const OcfaContent & content) = 0;

      /**
       * Creates an EvidenceStoreEntity from an OcfaContent.
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       * @param content contents of the file.
       *
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **es, unsigned int len, const char *buf) = 0;

      /**
       * Creates an empty  EvidenceStoreEntity.
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       *
       */
      virtual void createEmptyEvidenceStoreEntity(EvidenceStoreEntity **es) = 0;


      /**
       * Creates an new EvidenceStoreEntity by pointing to another
       * evidencestore entity and a list of fragments which together
       * represents a new entity.
       * @param newDataEntity the newly created EvidenceStroeEntity.
       * @param oldDataEntity the old EvidenceStoreEntity.
       * @param fragmentList the list of fragments, each describing an offset and a size, which represent the new
       *    entity.
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **newDataEntity, EvidenceStoreEntity &parentEntity, 
					     ocfa::misc::FragmentList &inFragmentList) = 0;

      /**
       * Creates an empty MetaStoreEntity.
       * 
       * @param **ms pointer to pointer to a MetaStoreEntity. The
       * pointer will be set to a newly created MetaStoreEntity. The
       * caller takes reponsibility for the newly created entity..  Is
       * removed because it is not possible to create an empty
       * metastorentity when you already have an Evidenceidentifier.
       */
      //   virtual void createEmptyMetaStoreEntity(MetaStoreEntity **ms, EvidenceStoreEntity *inDataEntity = 0, EvidenceIdentifier &inId) = 0;



      
      /**
       * reCreates an EvidenceStoreEntity from a handle
       *
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       * @param h handle to an existing evidencestoreentity.
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **me, OcfaHandle h) = 0;
 

      /**
       * reCreates an MetaStoreEntity from a handle
       *
       * @param **ms pointer to pointer to a MetaStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       */
     virtual void createMetaStoreEntity(MetaStoreEntity **me, OcfaHandle h) = 0;


      /**
       * sets the handle for a storeentity. 
       *
       */
      /* JCW:CODEREVIEW: Moet deze functie in de interface? Komt nergens buiten de store voor*/
      virtual void setHandle(StoreEntity &se) = 0;

      /**
       * returns the root of the repository. All paths in
       * storeentities are relative to this path.
       *
       */
      virtual std::string getRoot() = 0;

      
      /**
       * returns the evidencstoreentity that belongs to a certain metadatahandle. Throws an ocfaexception
       * if one does not exist.
       *
       */
      virtual OcfaHandle getEvidenceStoreHandle(MetaStoreEntity &metaStoreEntity) = 0;
      
      /**
       * checks whether the metastoreentity has a corresponding evidencestorehandle.
       */
      virtual bool hasEvidenceStoreHandle(MetaStoreEntity &metaStoreEntity) = 0;

      /**
       * fills a vector of metadataHandles for every metastoreentity that refers to 
       *
       */
      virtual void fillMetaDataHandles(vector<OcfaHandle> &outMetaDataHandles, 
				      EvidenceStoreEntity &inEvidenceStoreEntity)=0;

      
      /**
       * Tells the abstractrepository thta it is in a certain module instance.
       */
      /*JCW:CODEREVIEW: wordt niet gebruikt
      virtual bool baptise(const misc::ModuleInstance &mi) = 0;
      */


      /**
       * creates an Item used for kickstarting. Should throw an
       * exception if the item already exists.
       *
       */
      virtual void createItem(Item **item, string nCaseId, string inSourceId, string inItemId) = 0;


      virtual ~AbstractRepository(){};
    protected:
      AbstractRepository(): OcfaObject("AbstractRepository", "store"){};
      static AbstractRepository *_instance;
    };

    

  }
}

 
#endif
