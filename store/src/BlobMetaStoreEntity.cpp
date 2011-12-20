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
						
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sstream>
#include <errno.h>
#include "string.h"
//#include "store/AbstractRepository.hpp"
#include "PgBlobRepository.hpp"
#include "BlobMetaStoreEntity.hpp"
#include "misc/OcfaException.hpp"


namespace ocfa {
  namespace store {
    using namespace std;
    
    const int max_buffer_length = 1 * 1024 * 1024;


    BlobMetaStoreEntity::BlobMetaStoreEntity(): 
      OcfaObject("BlobMetaStoreEntity", "store"), d_handle(""), d_contentsbuf("") 
	
    {
      ocfaLog(ocfa::misc::LOG_DEBUG,"BlobMetaStoreEntity constructor");
	    //d_repostype = ocfa::misc::OcfaConfig::Instance()->getValue("repositorytype");
    }

    BlobMetaStoreEntity::~BlobMetaStoreEntity(){
      ocfaLog(ocfa::misc::LOG_DEBUG,"BlobMetaStoreEntity destructor");
    }

    void BlobMetaStoreEntity::initDigest(){
    
    }

    void BlobMetaStoreEntity::openStream(off_t datasize){
      d_contentsbuf = "";
    }

    void BlobMetaStoreEntity::writeStream(const char *buf, unsigned int len){
      d_contentsbuf.append(buf, len);
    }

    void BlobMetaStoreEntity::closeStream(){
  
    }

  
    void BlobMetaStoreEntity::setHandle(ocfa::misc::OcfaHandle handle){
      if (handle == ""){
	throw OcfaException("Attempt to set empty handle");
      }
      if ((d_handle != "") and ( handle != d_handle)){
        throw OcfaException("Attempt to change non empry handle");
      }
      d_handle = handle;
    }

    
     // set hardlink to target based on SHA1 of target
    // if target needs to be 'moved into repository', the user should delete the target himself
    // returns name of link
    string BlobMetaStoreEntity::setHardLink(const string &,ocfa::misc::DigestPair **){
	return "";
      }
      
      // set softlink to target based on SHA1 of target
      // returns name of softlink
      string BlobMetaStoreEntity::setSoftLink(const string &,ocfa::misc::DigestPair **){
	return "";
    }

    /**
     * 
     * returns the path relative to the repository.
     *
     */
    Filename BlobMetaStoreEntity::getStoreName() const {

      return Filename("");
    }

    void BlobMetaStoreEntity::setStoreName(ocfa::store::Filename&){

    }

    unsigned char *BlobMetaStoreEntity::contentsAsBuf(size_t){
      //FIXME: the const_cast should be removed.
      return reinterpret_cast<unsigned char *>(const_cast<char *>(d_contentsbuf.c_str()));
    }

    ocfa::misc::MemBuf *BlobMetaStoreEntity::contentsAsMemBuf(size_t ){
      //FIXME: we should somehow lose this dangerous const_cast construct.
      return new ocfa::misc::MemBuf(reinterpret_cast<unsigned char *>(const_cast<char *>(d_contentsbuf.c_str())), d_contentsbuf.size());
    }

    void BlobMetaStoreEntity::updateContent(char const *buf, unsigned int ){
      d_contentsbuf = string(buf);
      PgRepository *store = dynamic_cast<PgRepository *>(AbstractRepository::Instance());
      if (store){
        if (d_handle == ""){
	  throw OcfaException("Handle empty");
	}
        store->commitMetaChange(this);
      } else {
	// throw blabla
      }
    }

    /**
     * returns the absolute filepath for this file.
     *
     */
    Filename BlobMetaStoreEntity::getAsFilePath() const {

      return Filename("");
    }

    misc::OcfaHandle BlobMetaStoreEntity::getHandle(){
      return d_handle;
    }

    std::string BlobMetaStoreEntity::contentsAsString(size_t ){
      return d_contentsbuf;
    }
    /**
     * 
     * Size has been changed from the original so that lstat is used instead of fsstat. This
     * is done because of the new fsstat and because I'd rather not want a dependency between fsstat and
     * the store.
     *
     */
    off_t BlobMetaStoreEntity::size() const {
       
      return d_contentsbuf.size();
      
    }

    /**
     * reads a maximum of count bytes into buffer. 
     * @param buffer the buffer into which the bytes should be read. It should be at
     * least count bytes large.
     * @param count the maximum amount of bytes to be read into the buffer.
     */
    size_t BlobMetaStoreEntity::read(void *buffer, size_t count) {

      // TODO get contents from db
      
      // copy contens to buffer
      strncpy(reinterpret_cast<char *>(buffer), d_contentsbuf.c_str(), count); 
      return strlen(reinterpret_cast<char *>(buffer));  
    }	  

    /**
     * returns an input stream from the storeentity.
     * Difference with 0.3
     * 1. Everytime a new stream is created (wasn't sure if needed).
     *
     */
    std::istream *BlobMetaStoreEntity::getAsIstream()  {
      // TODO (probably: read contentsbuf from db)
      
      return new std::istringstream(d_contentsbuf.c_str());
    }

    std::string BlobMetaStoreEntity::tableName(){
      return "metastoreentity";
    }

    void BlobMetaStoreEntity::setContent(const std::string &buf){
      d_contentsbuf = buf;
    }

    /**
     * sets the digestpair of a storeentity.
     *
     */
    void BlobMetaStoreEntity::setDigestPair(ocfa::misc::DigestPair **){
      
    }
  }
}



