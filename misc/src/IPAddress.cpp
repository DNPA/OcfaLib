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
						
#include<misc/IPAddress.hpp>
#include <misc/OcfaConfig.hpp>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>

namespace ocfa {
  namespace misc {
    std::string IPAddress::Value(){
      if (_value == ""){
        std::string myip=OcfaConfig::Instance()->getValue("hostip");
        if (myip != "") {
           _value=myip;
        } else {
	  long hostid=gethostid();
	  short *hid=reinterpret_cast<short *>(&hostid);
	  short hs=hid[0];
	  hid[0]=hid[1];
	  hid[1]=hs;
	  struct in_addr inad;
	  inad.s_addr=hostid;
	  _value = inet_ntoa(inad);
        }
      }
      return _value;
    }
 
    std::string IPAddress::_value = "";
  }
}


