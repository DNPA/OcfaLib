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
						
#include <fs.hpp>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <regex.h>
#include <fcntl.h>
#include <list>
#include <grp.h>
#include "errno.h"
#include "string.h"
#include <pwd.h>
#include "ConcreteStoreEntity.hpp"
//#include "FileMetaStoreEntity.hpp"
#include "ConcreteEvidenceStoreEntity.hpp"
#include "SimpleRepository.hpp"


using namespace std;

namespace ocfa {
  namespace store {

    SimpleRepository::SimpleRepository(string szRepositoryRoot):
	    AbstractRepository(),
	    d_starttime(time(0)),
            d_root(szRepositoryRoot),
	    // JCW:CODEREVIEW: d_root(ocfa::misc::OcfaConfig::Instance()->getValue("repository")),
	    d_config(0),
	    d_ocfagroup(0),
	    d_dirmode(0700)
    {

    umask(0006); // Need to set umask becource unique filename creation without it is dangerous !!
    if (d_root == ""){ 
      throw OcfaException("You repository appears no to have been set in your ocfa configuration file ", this);
    }
    
    struct group *ocfagr=getgrnam("ocfa");
    if (ocfagr != 0) {
      ocfaLog(LOG_NOTICE, "There is an ocfaGroup");
      d_ocfagroup=ocfagr->gr_gid;
 
	
      d_dirmode = 0770;

      // tell the store-entities about the ocfagroup
      ConcreteStoreEntity::OcfaGroup = d_ocfagroup; 
	
      } else {
	//d_logger->syslog(evidence::LOG_NOTICE) << "SimpleRepository::SimpleRepository warning, no group ocfa found, assuming single user setup\n";
	ocfaLog(LOG_NOTICE, "warning, no group ocfa found, assuming single user setup");
        d_ocfagroup=static_cast<gid_t>(-1); // This may seem strange, but the chown call expects -1 as 
				// special value for 'dont change', although the gid_t argument
				// is unsigned under Linux.
      }
      // we don't care whether this succeeds or not, for the moment.
      mkdir(d_root.c_str(), d_dirmode);
      chown(d_root.c_str(),static_cast<uid_t>(-1),d_ocfagroup);
    }

    SimpleRepository::~SimpleRepository(){

    }

 
    /**
     * Creates an epty EvidenceStoreEntity.
     * 
     * @param **ms pointer to pointer to a EvidenceStoreEntity. The
     * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
     * for the newly created entity..
     *
     * the newly created evidencestoreentity does not have a
     * handle. This is only set after a stream is opened and closed
     * (when there is data in the evidencestoreentity.)
     * 
     */
    void SimpleRepository::createEmptyEvidenceStoreEntity(EvidenceStoreEntity **es){
      *es = new ConcreteEvidenceStoreEntity(d_root);
    }
   


    /**
     * Retrieves an existing metastoreentity from a handle.
     * @param **me the  pointer to pointer to a MetaStoreEntity. The
     * pointer will be set to a newly created MetaStoreEntity. The caller takes reponsibility
     * for the newly created entity.
     * @param h handle to an existing Metastoreentity.
     *
     * Creates a MetaStoreEntity, then calles getStoreEntity to set the data in the entity based upon the handle.
     */
    void SimpleRepository::createMetaStoreEntity(MetaStoreEntity **me, OcfaHandle h) {

      ocfaLog(LOG_DEBUG, "entering createMetaStoreEntity");
      getLogStream(LOG_DEBUG) << "handle is " << h << endl;
      if (h == "") throw OcfaException("getMetaStoreEntity called with empty handle",this);
      //*me = new FileMetaStoreEntity(d_root);
      getMetaStoreEntity(h, me);

    }
      /**
       * recreates an evidencestoreentity from a handle.
       * @param  **ms pointer to pointer to a EvidenceStoreEntity. The
       * pointer will be set to a newly created EvideceStoreEntity. The caller takes reponsibility
       * for the newly created entity.
       * @param h handle to an existing evidencestoreentity.
       * Creates a EvidenceStoreEntity, then calles getStoreEntity to set the data in the entity based upon the handle.
       * 
       */

    void SimpleRepository::createEvidenceStoreEntity(EvidenceStoreEntity **me, OcfaHandle h) {
      
      ocfaLog(LOG_DEBUG, "entering createEvidenceStoreEntity");
      if (h == "") throw OcfaException("getEvidenceStoreEntity called with empty handle",this);
      
      *me = new ConcreteEvidenceStoreEntity(d_root);
      getStoreEntity(h, **me);

    }

    
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
     * The storeentity is created and the handle is set. The handle is set by the storeentity self
     * during setLink.
     */
    void SimpleRepository::createEvidenceStoreEntity(EvidenceStoreEntity **estore,  const Filename &linkname, store::linktype lt,ocfa::misc::DigestPair **dp){

      // JBS sanity check, we do not accept funny paths.
      if (linkname[0] != '/' || linkname.find("/../") != string::npos){

	throw OcfaException(string("Attempt to add a relative path to repository: ") + linkname, this);
      }
      // we may link but still need to calculate hash
      ocfaLog(LOG_DEBUG, "Creating evidenceStoreEntity from name " + linkname);
      *estore = new ConcreteEvidenceStoreEntity(d_root);
      ocfaLog(LOG_DEBUG, "evidenceStoreEntity created");
      if (lt == hard){
	
	ocfaLog(LOG_DEBUG, "Creating hardlink ");	
	(*estore)->setHardLink(linkname,dp);
      }
      else {	

	ocfaLog(LOG_DEBUG, "Creating softlink ");
	(*estore)->setSoftLink(linkname,dp);
      }
    }
	 

    /**
     * Derives a MetaStoreEntity from some content.
     * 
     * @param **ms pointer to pointer to a metastoreentity. The
     * pointer will be set to a newly created metastoreentity.
     * @param content the content with which the newly created metastoreentity will be filled.
     * @param inDataEntity. The dataentity about which the metastoreentity has metadata.
     * 
     * simple calles createMetaStoreentity with the appropriate parameters.
     */
    void SimpleRepository::createMetaStoreEntity(MetaStoreEntity **estore, const OcfaContent & content, 
						 EvidenceIdentifier &inIdentifier, 
						 OcfaHandle *inDataHandle) {
    
      createMetaStoreEntity(estore, reinterpret_cast<const unsigned char *> (content.c_str()), content.length(), inIdentifier, inDataHandle);
    }


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
       * writes the data to a metastoreentity and then sets the handle
       * (contrary to evidencestoreentities, the handle is not
       * automatically set when the stream is closed)
       */
    void SimpleRepository::createMetaStoreEntity(MetaStoreEntity **estore, const unsigned char *buf,
						 unsigned int len, EvidenceIdentifier &inIdentifier,
						 OcfaHandle *inDataHandle) {
      OcfaHandle usedHandle("");
      *estore = constructMetaEntity(d_root); //new FileMetaStoreEntity(d_root);
      (*estore)->openStream();
      (*estore)->writeStream(reinterpret_cast<const char *>(buf), len);
      (*estore)->closeStream();
      if (inDataHandle != 0){

	usedHandle = *inDataHandle;
      }
      getLogStream(LOG_DEBUG) << "createMetaStoreEntity: setting handle for " << *estore << endl;
      setHandle(**estore);
      getLogStream(LOG_DEBUG) << "createMetaStoreEntity: handle set to " << (*estore)->getHandle() << endl;

      setMetaDataInfo((*estore)->getHandle(), inIdentifier, usedHandle);
      
    }
    
    /**
     * Simple wrapper around the createEvidenceStoreeneity with a buffer.
     *
     */
    void SimpleRepository::createEvidenceStoreEntity(EvidenceStoreEntity **estore, const OcfaContent &content ) {
     
      createEvidenceStoreEntity(estore, content.length(), content.c_str());
    }

    /**
     * creates an empty evidencestoreentity writes to it and closes
     * it. When it is closed the evidencestoreentity calls for a
     * createHandle of the repository (this is not nice, but
     * unavoidable because the handle can only be created after the
     * data has been written into the evidencestoreentity and it is possible for a user to create an
     * empty evidencestoreeentity.
     *
     */
    void SimpleRepository::createEvidenceStoreEntity(EvidenceStoreEntity **estore,unsigned int len, const char *buf) {
      
      ocfaLog(LOG_DEBUG, string("enteringcreateEvidenceStoreEntity: "));

      createEmptyEvidenceStoreEntity(estore);
      (*estore)->openStream();
      (*estore)->writeStream(buf, len);
      (*estore)->closeStream();
      ocfaLog(LOG_DEBUG, string("createEvidenceStoreEntity: handle is now ") + (*estore)->getHandle());
    }


    /**
     * Not implemented yet.
     */
    void SimpleRepository::createEvidenceStoreEntity(EvidenceStoreEntity **, 
						     EvidenceStoreEntity &, 
						     ocfa::misc::FragmentList &){
      
      throw OcfaException("createEvidenceStoreEntity, with fragmentlist not implemented yet", 
			  this);      
    }
    
  }
}
