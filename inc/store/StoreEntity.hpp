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
						
#include "../misc.hpp"
#include "linktype.hpp"
#include "../OcfaObject.hpp"
#include "Filename.hpp"
#ifndef INCLUDED_STOREENTITY_HPP
#define INCLUDED_STOREENTITY_HPP

namespace ocfa {
  namespace store {

    class StoreEntity {
    public:
      virtual ~StoreEntity() {};
      virtual Filename getAsFilePath() const = 0;
      virtual Filename getStoreName() const = 0;

      /**
       * sets the storename of a storeentity. This s
       *
       */
      virtual void setStoreName(Filename &f) = 0;
      /**
       * opens a stream to write to the storeentity. Old content, if
       * it exists will be erased.
       *
       */
      virtual void openStream(off_t entitysize=0) = 0;
      /**
       * closes the stream 
       */
      virtual void closeStream() = 0;
      virtual void writeStream(const char *buf, unsigned int len) = 0;
      // create a soft link p'ointing to target. The name of the link will be the sha of the target.
      virtual string setSoftLink(const string &target,ocfa::misc::DigestPair **dp=NULL) =0;
      virtual string setHardLink(const string &target,ocfa::misc::DigestPair **dp=NULL) = 0;

      virtual void setHandle(ocfa::misc::OcfaHandle handle) = 0;

      virtual size_t read(void *buffer, size_t count) = 0;

      
      virtual off_t size() const = 0;
 
      virtual void initDigest() = 0;
      virtual ocfa::misc::OcfaHandle getHandle() = 0;
      virtual string tableName() = 0;
      virtual std::istream *getAsIstream() = 0;
 
      /**
       * sets the digestpair. The caller loses the ownerschip over the
       * given digestpair.
       * This method should normally be called by the repsitory self.
       *
       */
      virtual void setDigestPair(misc::DigestPair **inDigestPair) = 0;
 
    };
  }
}
#endif 
