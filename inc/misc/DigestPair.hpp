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
						
#ifndef __DIGESTPAIR__
  #define __DIGESTPAIR__
#include <string>
#include "../OcfaObject.hpp"

namespace ocfa {

  namespace misc {
    /** Class used to hold handles to store entities*/
    class DigestPair:public OcfaObject {
	      public:
		      /** Constructor for DigestPair from known digests */
		      DigestPair(std::string sha1,std::string md5);
		      /** If the digestpair is LibCryptDigestPair created by the DigestPair factory, the folowing
		       * method is used to update the unfinished digestpair*/
		      virtual void update(const char * buffer,size_t size);
		      /** If the digestpair is LibCryptDigestPair created by the DigestPair factory, the folowin
		       * method is used to finalize digestpair initialisation */
		      virtual void final();
		      /** Fetch the SHA1 digest */
		      std::string getSHA1() const;
		      /** fetch the MD% digest */
		      std::string getMD5() const;
	      protected:
		      DigestPair();
		      bool valid;
		      std::string mSHA1;
		      std::string mMD5;
    };
  } 
}
#endif
