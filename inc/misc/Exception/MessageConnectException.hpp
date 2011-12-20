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
						
#ifndef __MESSAGECONNECTEXCEPTION_HPP__
#define __MESSAGECONNECTEXCEPTION_HPP__
#include "../OcfaException.hpp"


namespace ocfa { 
  namespace misc {
    /**** CLASS MessageConnectException *********************************************/
    class MessageConnectException: public OcfaException {
    public:
      MessageConnectException(string msgstr, const OcfaObject * throwmaster):OcfaException(msgstr,throwmaster){}
      MessageConnectException(string msgstr):OcfaException(msgstr){}
    }; /* end class MessageConnectException*/
  } /*end ocfa namespace*/
}
#endif
  
