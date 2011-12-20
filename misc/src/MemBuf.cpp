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
						
#include <misc/MemBuf.hpp>
#include <stdlib.h>
#include <string.h>

namespace ocfa { 
  namespace misc {
    MemBuf::MemBuf(unsigned char *membuf,size_t bufsize):OcfaObject("MemBuf","ocfa"),mMembuf(membuf),mSize(bufsize),mDoDelete(false){
    }
    MemBuf::MemBuf(unsigned char **membuf,size_t bufsize):OcfaObject("MemBuf","ocfa"),mMembuf(*membuf),mSize(bufsize),mDoDelete(true){
      *membuf=0; //show the caller that we have taken over controll of the membuf
      mDoDelete=true;
    }
    MemBuf::~MemBuf() {
      if (mDoDelete)
          free(mMembuf);
      mMembuf=0;
      mSize=0;
    }

    MemBuf::MemBuf(const MemBuf &orig) : OcfaObject("MemBuf", "ocfa"),mMembuf(0),mSize(0),mDoDelete(false){
      mMembuf = static_cast<unsigned char *>(malloc(orig.getSize() * sizeof(unsigned char)));
      if (mMembuf) {
         mDoDelete=true;
         memcpy(mMembuf, orig.getPointer(), orig.getSize());
         mSize = orig.getSize();
      }
    }
    unsigned char *MemBuf::getPointer() const {
      return mMembuf;
    }
    size_t MemBuf::getSize() const {
      return mSize;
    }
    MemBuf::MemBuf(std::string s):OcfaObject("MemBuf","ocfa"),mMembuf(0),mSize(s.size()),mDoDelete(true) {
       mMembuf = static_cast<unsigned char *>(malloc(mSize * sizeof(unsigned char)));
       if (mMembuf == 0) 
          throw OcfaException("Memory allocation error",this);
       memcpy(mMembuf, s.c_str(), mSize); 
       return;
    }
    MemBuf::operator std::string(){
       std::string rval(reinterpret_cast<const char *>(mMembuf),mSize);
       return rval;
    }
  }
}
