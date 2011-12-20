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
						

#ifndef INCLUDED_BLOBMETASTOREENTITY_HPP
#define INCLUDED_BLOBMETASTOREENTITY_HPP  

#include "store/MetaStoreEntity.hpp"

namespace ocfa {
  namespace store {
    
    class BlobMetaStoreEntity: public MetaStoreEntity, protected OcfaObject {
    public:

      BlobMetaStoreEntity();
      virtual ~BlobMetaStoreEntity();
      //JCW:CODEREVIEW: Maximum content size is 100MB
#define MAX_CONTENT_SIZE 104857600
      void setContent(const std::string &buf);
      /**
       * Returns the content as a String. The buffer is allocated within the method
       */
      virtual string contentsAsString(size_t MaxContSize=MAX_CONTENT_SIZE);
       
      /**
       * Returns the contents as a unsigned buffer. the buffer is allocated within the
       * method. The caller is reponsible for deleting the pointer. 
       */
      virtual unsigned char *contentsAsBuf(size_t MaxContSize=MAX_CONTENT_SIZE);


      /**
       * returns the contents of the metastoreentity as a Membuf. The
       * caller is responsible for deleting the object.
       *
       *
       virtual */
      virtual ocfa::misc::MemBuf *contentsAsMemBuf(size_t MaxContSize=MAX_CONTENT_SIZE);
       
      /**
       * replaces the current content of the metastoreentity with the new content 
       * specified in the arguments.
       *
       */
      virtual void updateContent(const char *buf, unsigned int length);


      virtual Filename getAsFilePath() const;
      virtual Filename getStoreName() const;

      /**
       * sets the storename of a storeentity. This s
       *
       */
      virtual void setStoreName(Filename &f);
      /**
       * opens a stream to write to the storeentity. Old content, if
       * it exists will be erased.
       *
       */
      virtual void openStream(off_t datasize=0);
      /**
       * closes the stream
       */
      virtual void closeStream();
      virtual void writeStream(const char *buf, unsigned int len);
      // create a soft link p'ointing to target. The name of the link will be the sha of the target.
      virtual string setSoftLink(const string &target,ocfa::misc::DigestPair **);
      virtual string setHardLink(const string &target,ocfa::misc::DigestPair **);

      virtual void setHandle(ocfa::misc::OcfaHandle handle);

      virtual size_t read(void *buffer, size_t count);


      virtual off_t size() const;

      virtual void initDigest();
      virtual ocfa::misc::OcfaHandle getHandle();
      virtual string tableName();
      virtual std::istream *getAsIstream();

      /**
       * sets the digestpair. The caller loses the ownerschip over the
       * given digestpair.
       * This method should normally be called by the repsitory self.
       *
       */
      virtual void setDigestPair(misc::DigestPair **inDigestPair);

    protected:
      ocfa::misc::OcfaHandle d_handle;
      string d_contentsbuf;
    };
  }
}
#endif 
