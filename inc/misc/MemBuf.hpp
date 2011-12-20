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
						
#ifndef _MEMBUF_
#define _MEMBUF_
#include "OcfaException.hpp"
#include "../OcfaObject.hpp"
namespace ocfa {
  namespace misc {
    /** A basic memory buffer object class */
    class MemBuf: public OcfaObject {
    public:
      /**Constructor*/
      MemBuf(unsigned char *membuf,size_t bufsize);
      MemBuf(unsigned char **membuf,size_t bufsize);
      MemBuf(std::string s);
      /**
       * copy constructor
       *
       */
      MemBuf(const MemBuf &orig);
      /**Destructor, will free the memory buffer !! */
      ~MemBuf();
      /**Fetch the pointer to the memory buffer */
      unsigned char *getPointer() const;
      /** Fetch the size of the memory buffer */
      size_t getSize() const;
      operator std::string();
    private:
      const MemBuf& operator=(const MemBuf&) {
         throw OcfaException("No invocation of operator= allowed for MemBuf",this);
	 return *this;
      }
      unsigned char 		*mMembuf;
      size_t	    		mSize;
      bool			mDoDelete;
    };
  }
}
#endif
