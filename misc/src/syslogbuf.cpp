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
						
#include <syslog.h>
#include <string.h>
//#include "syslogbuf.hpp"
#include "GlobalMutex.hpp"
#include "syslogbuf.hpp"
namespace ocfa {
  namespace misc {
	  syslogbuf::syslogbuf():index(0),priority(0) {
             setp(0,0);
	     setg(0,0,0);
	     priority=0;
	     strcpy(data,"Undefined:");
	     index=strlen(data);
	  }
	  void syslogbuf::conf(int prio,const char *pfix) {
	     index=0;
             strncpy(prefix,pfix,128);
	     strncpy(data,prefix,128);
	     data[127]=0;
	     index=strlen(data);
	     priority=prio;
	  }
	  int syslogbuf::overflow(int c) {
             setp(0,0);
	     if (c != char_traits<char>::eof()) {
	       data[index]=c;
	       index++;
	     }
	     if ((c == '\n') || (index == 255) || (c == char_traits<char>::eof())) {
                data[index]=0;
	        {
		  GlobalMutex automutex();
                  syslog(priority,"%s",data);
	        }
		strncpy(data,prefix,128);
		data[127]=0;
		index=strlen(data);
	     } 
	     if (c != char_traits<char>::eof()) return 0;
	     return c;
	  }
	  int syslogbuf::underflow() {
             setg(0,0,0);
	     return char_traits<char>::eof();
	  }
  }
}
