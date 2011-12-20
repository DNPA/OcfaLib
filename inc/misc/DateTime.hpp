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
						
#ifndef H_OCFA_DATETIME
#define H_OCFA_DATETIME
#include "../OcfaObject.hpp"
using namespace std;
namespace ocfa {
  namespace misc {
    /**
     * Helper class to store and retreive Date/Time information in Scalars
     */
    class DateTime:public OcfaObject {
    public:
      /**Constructor for DateTime
       * @param val The time_t value for the DateTime.
       * @param timesourceref A (close to) unique reference to a source of time information that is
       * assumed to be driftless within itself, and can be used for timeline analysis by adding
       * ofset information to the analysis database */
      DateTime(long int val, string timesourceref);
      /** Destructor for DateTime
       * */
      ~DateTime();
      /**Add an integer value to a DateTime
      * */
    DateTime operator+(int arg);
       /**Retreive the time_t value of the DayTime */
    long int getTime() const;
    operator long int() const {return getTime();}
    
       /** Retreive the TimeSourceRef */
    string getTimeSourceRef() const;
    static std::string translate(long int val);
    static long int translate(std::string iso8601);
  private:
    long int time;		//The time only has a one second precission.
    string sourceref;		//It is assumed that DateTimes with the same sourceref can blindly be used
    //in timeline analysis. Timeline analysis between different sourcerefs could
    //take place if information is gathered on the preciseness of the timesource.
    };
  }
}
#endif
