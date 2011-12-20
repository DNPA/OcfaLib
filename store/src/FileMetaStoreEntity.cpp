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
						
#include "FileMetaStoreEntity.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "string.h"

using namespace ocfa::misc;
namespace ocfa {

  namespace store {
    using namespace std;

    string FileMetaStoreEntity::TABLE_NAME = "metastoreentity";
    //FileMetaStoreEntity::FileMetaStoreEntity(){
    //  
    // }
    FileMetaStoreEntity::~FileMetaStoreEntity(){
      
    }

    FileMetaStoreEntity::FileMetaStoreEntity(const string inRoot): ConcreteStoreEntity(inRoot){
    }

    void FileMetaStoreEntity::setPermissions(int fd){
      
      if (fchmod(fd, S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP) != 0){
	string msg(strerror(errno));
	throw OcfaException(string("chmod failed: ")+msg);
      }
      
    }

    ocfa::misc::OcfaHandle FileMetaStoreEntity::getHandle(){
      return d_handle;
    }

    string FileMetaStoreEntity::tableName(){
      return TABLE_NAME;
    }

    /**
     * replaces the current content of the metastoreentity with the new content
     * specified in the arguments.
     *
     */
    void FileMetaStoreEntity::updateContent(const char *buf, unsigned int length){

      int fd = open(getAsFilePath().c_str(), (O_WRONLY | O_TRUNC));
      if (fd == -1){

	throw OcfaException(string("cannot open ") + getAsFilePath() 
			    + " for writing", this);
      }
      write(fd, buf, length); //FIXME: we should check for return values.
      close(fd);
    }
    
      
    /**
     * returns the content as a unsigned char.
     *
     */
    unsigned char *FileMetaStoreEntity::contentsAsBuf(size_t MaxContSize)  {
      //if (d_valid == false) throw OcfaException("StoreEntity::contentsAsBuf() on invalid entity",this);
       size_t sz=this->size();
       if(sz > MaxContSize) {
          throw OcfaException("trying to read a ridiculously large FileMetaStoreEntity", this);
       }
       //if (static_cast<off_t>(sz) != static_cast<off_t>(this->size())) 
       //   throw OcfaException("StoreEntity size exceeds size_t capacity",this);
       unsigned char *buffer=static_cast<unsigned char *>(malloc(sz));
       if (buffer == 0) {
          throw OcfaException("Unable to allocate memory for contentsAsBuf",this);
       }
       
       size_t result = this->read(static_cast<void *>(buffer),sz);
       close(d_fd);
       d_fd = -1;
       if (sz != result)
       {
          free(buffer);

          getLogStream(LOG_ERR) << "Read result was " << result << " while size was " << sz << endl;
          throw OcfaException("Problem with amounth read from storentity, not size !",this);
       }
       return buffer;
    }
    

    /**
     * returns the contents as a string.
     */
    string FileMetaStoreEntity::contentsAsString(size_t MaxContSize)  {
      
       off_t fileSize = size();
       off_t msize=MaxContSize;
       if (fileSize > msize){
	
          throw OcfaException("trying to read a ridiculously large FileMetaStoreEntity", this);
       } 
       char *buf = static_cast<char *>(malloc((fileSize + 1)));
       read(buf, fileSize);
       close(d_fd);
       d_fd = -1;
       buf[fileSize] = '\0';
      // ocfaLog(LOG_DEBUG, string("casting " + buf + 
       string rval(static_cast<char *>(buf));
       free(buf);
       if (rval.size() != static_cast<size_t>(fileSize)) {
		
          int stringSize = rval.size();
          int bufferSize = this->size();
          getLogStream(LOG_ERR) << "string size is " << stringSize << endl;
          getLogStream(LOG_ERR) << "Buffer size is " << bufferSize << endl;
          throw OcfaException("Size problem while casting content buffer to a string",this);
       }
       return rval;
    }

    /**
     * returns the contents of a storeentity as a Membuf. The caller is respondible for disposing of
     * the membuf
     * 
     *
     */
    MemBuf *FileMetaStoreEntity::contentsAsMemBuf(size_t MaxContSize){

       getLogStream(LOG_DEBUG) << "<< entering contents as Membuf " << endl; 
       unsigned char *buf = contentsAsBuf(MaxContSize);
       MemBuf *membuf = new MemBuf(&buf, size());
       if (membuf == 0){

          throw OcfaException("membuf not created", this);
       }

       return membuf;
    }
    
    
    
    

  }

}
