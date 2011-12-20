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
						
#ifndef _STOREDATAMASK_
#define _STOREDATAMASK_
#include <string>
#include "../OcfaObject.hpp"
#include "Fragment.hpp"
namespace ocfa {
  namespace misc {
    /**
     * Class for holding lookup information for store data that is located within other store data  
     * at one or more ofsets.
     */
    class FragmentList {
    public:
      /** get the size of all the data */
      virtual size_t getCumulativeSize() const=0;
      /** method for requesting the number of OffsetSize objects that are required and available */
      virtual size_t getFragmentCount() const=0;
      /** method used to reset the getOffsetSize function call to start at the begining */
      virtual void reset() const=0;
      /** Method for fetching the parameters of the next continious block of data */
      virtual Fragment *getNextFragment()=0;
      virtual ~FragmentList() {};
    };
  }
}
#endif
