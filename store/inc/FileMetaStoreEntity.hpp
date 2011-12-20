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
						
#include "store/MetaStoreEntity.hpp"
#include "ConcreteStoreEntity.hpp"
#ifndef INCLUDED_FILEMETASTOREENTITY_HPP
#define INCLUDED_FILEMETASTOREENTITY_HPP  

namespace ocfa {
  namespace store {
    
    class FileMetaStoreEntity:public MetaStoreEntity, protected ConcreteStoreEntity {
    public:
       
       //JCW:CODEREVIEW: Maximum content size is 100MB
       #define MAX_CONTENT_SIZE 104857600
       /**
        * Returns the content as a String. The buffer is allocated within the method
        */
       string contentsAsString(size_t MaxContSize=MAX_CONTENT_SIZE) ;
       
      /**
       * Returns the contents as a unsigned buffer. the buffer is allocated within the
       * method. The caller is reponsible for deleting the pointer. 
       */
       unsigned char *contentsAsBuf(size_t MaxContSize=MAX_CONTENT_SIZE) ;


      /**
        * returns the contents of the metastoreentity as a Membuf. The
        * caller is responsible for deleting the object.
        *
        *
       */
       ocfa::misc::MemBuf *contentsAsMemBuf(size_t MaxContSize=MAX_CONTENT_SIZE);
       
       
      //      MetaStoreEntity();
      FileMetaStoreEntity(const std::string inRoot);
      ~FileMetaStoreEntity();
      virtual ocfa::misc::OcfaHandle getHandle();
      virtual string tableName();
    
     /**
      * replaces the current content of the metastoreentity with the new content 
      * specified in the arguments.
      *
      */
      virtual void updateContent(const char *buf, unsigned int length);

      static std::string TABLE_NAME;
    protected:
      virtual void setPermissions(int fd);
    private:
    };
  }
}
#endif 
