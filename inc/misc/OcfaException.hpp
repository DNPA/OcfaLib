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
						
#ifndef __OCFAEXCEPTION_HPP__
  #define __OCFAEXCEPTION_HPP__
#include "../OcfaObject.hpp"


namespace ocfa { 
  namespace misc {
    /**** CLASS OCFA Exception *********************************************/
    class OcfaException {
    public:
      /** Constructor for OcfaException 
       *  The OcfaObject throwing the OcfaException should use this
       *  as throwmaster argument */
      OcfaException(std::string msgstr, const OcfaObject * throwmaster);
      /** Constructor for OcfaException as thrown by non OcfaObject */
      OcfaException(std::string msgstr);
      /** retreive the what information from the OcfaException*/
      virtual const char *what() const;
      /** Log the what data using syslog **/
      virtual void logWhat() const;
      /** Retreive a reference to trowing opject, that we could use to
       * query for information */
      virtual const OcfaObject *getOcfaObject() const;
      OcfaException(const OcfaException&):thrower(0),msg("hmm") {throw(std::string("hmm"));}
      virtual ~OcfaException(){}
    private:
      const OcfaException& operator=(const OcfaException&) {throw(std::string("hmm"));return *this;}
      void saveStackTrace();
      const OcfaObject *thrower;
      std::string msg;
    }; /* end class OcfaException*/
  } /*end ocfa namespace*/
}
#endif
  
