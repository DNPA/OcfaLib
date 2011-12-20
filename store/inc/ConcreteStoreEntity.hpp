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
						
#include "store/StoreEntity.hpp"
#ifndef INCLUDED_CONCRETESTOREENTITY
#define INCLUDED_CONCRETESTOREENTITY  

namespace ocfa {
  namespace store {

    class ConcreteStoreEntity: public virtual StoreEntity, protected OcfaObject {
    public:
      ConcreteStoreEntity(string root); 
      virtual ~ConcreteStoreEntity();
      
      Filename getAsFilePath() const;
      virtual Filename getStoreName() const;

      /**
       * sets the storename of a storeentity. This s
       *
       */
      void setStoreName(Filename &f){d_storename = f;};
      /**
       * opens a stream to write to the storeentity. Old content, if
       * it exists will be erased.
       *
       */
      void openStream(off_t datasize=0);
      /**
       * closes the stream 
       */
      virtual void closeStream();
      void writeStream(const char *buf, unsigned int len);
      // create a soft link p'ointing to target. The name of the link will be the sha of the target.
      string setSoftLink(const string &target,ocfa::misc::DigestPair **dp);
      string setHardLink(const string &target,ocfa::misc::DigestPair **dp);

      void setHandle(ocfa::misc::OcfaHandle handle);

      size_t read(void *buffer, size_t count) ;

      static gid_t OcfaGroup;
      off_t size() const;
 
      void initDigest();
      ocfa::misc::OcfaHandle getHandle(); // something like ; " select handle from " + TableName() + " where ... ".  
      virtual string tableName() = 0;
      std::istream *getAsIstream();
 
      /**
       * sets the digestpair. The caller loses the ownerschip over the
       * given digestpair.
       * This method should normally be called by the repsitory self.
       *
       */
      void setDigestPair(misc::DigestPair **inDigestPair);
   protected:
      bool calcDigest(string target);
      void getTmpFd();
      string renameToSHA1();
      string d_root;
      bool createFile();
      string setLink(const string &target, linktype lt,ocfa::misc::DigestPair **);
      string splitSHA1(const string &SHA1, vector<string> &dirs, string &filename);
      string createPath(const vector<string> &dirs) const;
      virtual void setPermissions(int fd) = 0;

      // StoreEntities are created by the SimpleRepository and not by users of
      // the storeentities
      // StoreEntity(); // usage: if an empty storeentity is required to add content to through the *Stream methods
      //StoreEntity(const string filename); 
      void Instantiate(ocfa::misc::OcfaHandle h); // select repname from + TableName() + ...
      ConcreteStoreEntity(const ConcreteStoreEntity& ): StoreEntity(),
	      OcfaObject("ConcreteStoreEntity","store"),
	      d_root(""),
	      d_digest(0),
	      d_fd(0),
	      d_opened(false),
	      d_handle(""),
	      d_storename(""),
              d_needsTailwrite(false) 
      {
          throw misc::OcfaException("Copy of ConcreteStoreEntity is not allowed",this);
      }
      const ConcreteStoreEntity& operator=(const ConcreteStoreEntity&) {
         throw misc::OcfaException("Assignment of ConcreteStoreEntity is not allowed",this);
	 return *this;
      }
      ocfa::misc::DigestPair *d_digest;
      int d_fd;
      bool d_opened;
      ocfa::misc::OcfaHandle d_handle;
      /**
       * points to a path of this storeentity relative to 
       *
       */
      string d_storename;
      bool d_needsTailwrite;
      size_t d_writecount;
      size_t d_sparsecount;
    };
  }
}
#endif 
