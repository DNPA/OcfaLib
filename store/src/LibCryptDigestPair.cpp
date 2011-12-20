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
						
#include <LibCryptDigestPair.hpp>
namespace ocfa {
  LibCryptDigestPair::LibCryptDigestPair():mCtxMD5(),mCtxSHA1() {
      updateTypeName("LibCryptDigestPair");
      EVP_DigestInit(&mCtxMD5, EVP_md5());
      EVP_DigestInit(&mCtxSHA1, EVP_sha1());
  }
  void LibCryptDigestPair::update(const char *buf,size_t size){
     EVP_DigestUpdate(&mCtxMD5, buf, size);
     EVP_DigestUpdate(&mCtxSHA1,buf, size);
  }
  void LibCryptDigestPair::final() {
    int i;
    unsigned int md5l, sha1l;
    unsigned char md5Buffer[EVP_MAX_MD_SIZE];
    unsigned char sha1Buffer[EVP_MAX_MD_SIZE];
    EVP_DigestFinal(&mCtxMD5,  md5Buffer, &md5l);
    EVP_DigestFinal(&mCtxSHA1, sha1Buffer, &sha1l);
    char md5Bufferasc[EVP_MAX_MD_SIZE * 2 + 1];
    for (i = 0; i < 16; i++) {
      sprintf((md5Bufferasc + (i * 2)), "%.2x", md5Buffer[i]);
    }
    mMD5=std::string(md5Bufferasc);
    char sha1Bufferasc[EVP_MAX_MD_SIZE * 2 + 1];
    for (i = 0; i < 20; i++) {
      sprintf((sha1Bufferasc + (i * 2)), "%.2x", sha1Buffer[i]); 
    }
    mSHA1=std::string(sha1Bufferasc);
    valid=true;
  }
}
