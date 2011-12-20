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
						
#include "StoreEntity.hpp"
#ifndef INCLUDED_METASTOREENTITY_HPP
#define INCLUDED_METASTOREENTITY_HPP  

namespace ocfa {
  namespace store {
    
    class MetaStoreEntity:public virtual StoreEntity {
    public:
       
      //JCW:CODEREVIEW: Maximum content size is 100MB
#define MAX_CONTENT_SIZE 104857600

      virtual ~MetaStoreEntity();
      /**
       * Returns the content as a String. The buffer is allocated within the method
       */
      virtual string contentsAsString(size_t MaxContSize=MAX_CONTENT_SIZE) = 0;
       
      /**
       * Returns the contents as a unsigned buffer. the buffer is allocated within the
       * method. The caller is reponsible for deleting the pointer. 
       */
      virtual unsigned char *contentsAsBuf(size_t MaxContSize=MAX_CONTENT_SIZE) = 0;


      /**
       * returns the contents of the metastoreentity as a Membuf. The
       * caller is responsible for deleting the object.
       *
       *
       virtual */
      virtual ocfa::misc::MemBuf *contentsAsMemBuf(size_t MaxContSize=MAX_CONTENT_SIZE) = 0;
       
      /**
       * replaces the current content of the metastoreentity with the new content 
       * specified in the arguments.
       *
       */
      virtual void updateContent(const char *buf, unsigned int length) = 0;

    };
  }
}
#endif 
