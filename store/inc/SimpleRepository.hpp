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
						
#include <time.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <libgen.h>
#include <sys/types.h>
#include "store/AbstractRepository.hpp"

#ifndef INCLUDED_SIMPLE_REPOSITORY
#define INCLUDED_SIMPLE_REPOSITORY


using namespace std;
//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better
namespace ocfa {
  /**
   * This part of the API holds abstracts the implementation of data storage for the users and evidence API. */
  namespace store {
    /**
     * SimpleRepository; class which implements a lot of methods from
     * AbstractRepository. The database details are left to a further derived implementation.
     *  
     *
     */    
    class SimpleRepository: public AbstractRepository {
    public:

      SimpleRepository(string root);
      virtual ~SimpleRepository();
 

 
      /**
       * recreates an evidencestoreentity from a handle.
       * @param  @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity.
       * @param h handle to an existing evidencestoreentity.
       * 
       */
      virtual void createEvidenceStoreEntity( EvidenceStoreEntity **me, OcfaHandle h);


      /**
       * Retrieves an existing metastoreentity from a handle.
       * @param **me the  pointer to pointer to a MetaStoreEntity. The
       * pointer will be set to a newly created MetaStoreEntity. The caller takes reponsibility
       * for the newly created entity.
       * @param h handle to an existing Metastoreentity.

       *
       */
      virtual void createMetaStoreEntity(MetaStoreEntity **me, OcfaHandle h);

      /**
       * Derives a MetaStoreEntity from some content.
       * 
       * @param **ms pointer to pointer to a metastoreentity. The
       * pointer will be set to a newly created metastoreentity.
       * @param content the content with which the newly created metastoreentity will be filled.
       * @param inDataEntity. The dataentity about which the metastoreentity has metadata.
       *
       */
      virtual void createMetaStoreEntity(MetaStoreEntity **ms, const OcfaContent & content,
					 ocfa::misc::EvidenceIdentifier &inId,
					 ocfa::misc::OcfaHandle *OcfaHandle = 0);

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
      virtual void createMetaStoreEntity(MetaStoreEntity **estore, const unsigned char *buf,
					 unsigned int len, ocfa::misc::EvidenceIdentifier &inIdentifier,
					 ocfa::misc::OcfaHandle *inDataHandle  = 0); 



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
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **es, const Filename & file, linktype lt,ocfa::misc::DigestPair **);

      /**
       * Creates an EvidenceStoreEntity from an OcfaContent.
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       * @param content contents of the file.
       *
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **es, const OcfaContent & content);


      /**
       * Creates an EvidenceStoreEntity from an OcfaContent.
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       * @param buf the buffer of the file.
       * @param len length of the buffer (buffer is not 0-terminated..
       *
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **es,  unsigned int len, const char *buf);
      /**
       * Creates an new EvidenceStoreEntity by pointing to another
       * evidencestore entity and a list of fragments which together
       * represents a new entity.
       * @param newDataEntity the newly created EvidenceStroeEntity.
       * @param oldDataEntity the old EvidenceStoreEntity.
       * @param fragmentList the list of fragments, each describing an offset and a size, which represent the new
       *    entity.
       * Throws an OcfaException, because it is not implemented.
       */
      virtual void createEvidenceStoreEntity(EvidenceStoreEntity **newDataEntity, EvidenceStoreEntity &parentEntity, 
					     ocfa::misc::FragmentList &inFragmentList);
      /**
       * Creates an empty EvidenceStoreEntity. It is possible to write to it using openstream. 
       * 
       * 
       * @param **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity..
       *
       */
      virtual void createEmptyEvidenceStoreEntity(EvidenceStoreEntity **es);
      
      

      /**
       * sets the handle for a storeentity. This is used by 
       * evidenstorentities themselves to set the handle once they are in a permanent space in 
       * repository tree. This is important for the EvidenceStoreEntity because it will set the handle once
       * the initial stream is closed.
       *
       */
      virtual void setHandle(StoreEntity &se) = 0;
 
      /**
       * Provides the repository with the name of the module. Not used at this moment.
       */
      /* JCW:codereview: wordt niet gebruikt
      
      virtual bool baptise(const misc::ModuleInstance &mi);
      */
      
          /**
       * returns the root of the repository. All paths in
       * storeentities are relative to this path.
       *
       */  
      virtual std::string getRoot(){ return d_root;} 
    
       
  protected:

      /**
       * creates root dir if necessary and sets needed permissions.
       *
       */

      /**
       * virtual that creates a shiny new handle that can be assigned to an metastoeentity.
       *
       */
      virtual misc::OcfaHandle createHandle(StoreEntity &st) = 0;
      virtual void getStoreEntity(OcfaHandle & h, StoreEntity &st) = 0;
      virtual void getMetaStoreEntity(OcfaHandle &h, MetaStoreEntity **mse) = 0;
      virtual MetaStoreEntity *constructMetaEntity(string d_root = "") = 0;
      void setLogger(ocfa::OcfaLogger *logger);
      /**
       * Sets a link between the data and the metadata, so that it can be retrieved
       * @param inDataHanlde the handel to the EvidenceDataStoreEntity. If the handle is empty it 
       * is considered to be not present.
       */
      virtual void setMetaDataInfo(const OcfaHandle &inMetaHandle, EvidenceIdentifier &inIdentifier, const OcfaHandle &inDataHandle) = 0;
      
      /**
       * Copy constructor
       * Not permitted!
       */
      SimpleRepository(const SimpleRepository& sr):
	      AbstractRepository(sr),
	      d_starttime(0),
	      d_root(""),
	      d_config(0),
	      d_ocfagroup(0),
	      d_dirmode(0)
      {
         throw OcfaException("SimpleRepository may not be copied",this);
      }
      
      /**
       * Assignment constructor
       * Not permitted!
       */
      const SimpleRepository& operator=(const SimpleRepository&) {
         throw OcfaException("SimpleRepository may not be assigned",this);
	 return *this;
      }
      
      
      
      time_t d_starttime;
      string d_root;

      OcfaConfig *d_config;
      gid_t d_ocfagroup;
      mode_t d_dirmode;

    };

  }
}
#endif
