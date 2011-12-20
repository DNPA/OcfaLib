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
						
#ifndef _LOGITERATOR_HPP
#define _LOGITERATOR_HPP
#include "../misc.hpp"
#include "OcfaIterator.hpp"
#include <string>

//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better
namespace ocfa {
  namespace evidence {
    /**LogIterator class used to iterate over LogLines within a single Job */
    class LogIterator:virtual public OcfaIterator {
    public:
      /**Retreive the DateTime info from the current logline
       *
       * Please note that the pointer returned will remain valid only 
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the LogIterator or its
       * JobIterator*/
	   virtual  misc::DateTime *getTime()=0;
      /**Retreive the syslog level of the current logline */
	   virtual  misc::syslog_level getPrio() const =0;
      /**Retreive the value of the current logline*/
	   virtual  std::string getLine() const =0;
	   virtual ~LogIterator() {};
    };
}}
#endif
