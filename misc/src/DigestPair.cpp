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
						
#include <misc/DigestPair.hpp>
#include <misc/OcfaException.hpp>
using namespace std;
namespace ocfa {
  namespace misc {

    DigestPair::DigestPair():OcfaObject("DigestPair","ocfa"),valid(false),mSHA1(""),mMD5(""){}
    DigestPair::DigestPair(string sha1,string md5):OcfaObject("DigestPair","ocfa"),valid(true),mSHA1(sha1),mMD5(md5){}
    void DigestPair::update(const char *,size_t) {
      throw OcfaException("DigestPair baseclass does not implement update()",this);
    }
    void DigestPair::final(){
      throw OcfaException("DigestPair baseclass does not implement final()",this);
    }
    string DigestPair::getSHA1() const{
      if (valid == false ) throw OcfaException("DigestPair not in a valid state yet to request SHA1",this);
      return mSHA1;
    }
    string DigestPair::getMD5() const{
      if (valid == false ) throw OcfaException("DigestPair not in a valid state yet to request MD5",this);
      return mMD5;
    }
  }
}
