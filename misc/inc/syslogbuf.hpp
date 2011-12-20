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
						
#ifndef SYSLOGBUF_HPP
#define SYSLOGBUF_HPP
#include <iostream>
using namespace std;
namespace ocfa {
	namespace misc {
          class syslogbuf : public streambuf {
	     public:
               syslogbuf();
	       int overflow(int=char_traits<char>::eof());
	       int underflow();
	       void conf(int prio,const char *prefix);
	     private:
	       char data[256];
	       char prefix[256];
	       size_t index;
	       int priority;
	  };
	}
}
#endif
