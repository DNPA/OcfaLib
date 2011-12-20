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
						
#ifndef _OCFA_ERROR_HANDLER_
#define _OCFA_ERROR_HANDLER_
#include <OcfaObject.hpp>
#include <xercesc/sax/ErrorHandler.hpp>
#include <xercesc/sax2/DefaultHandler.hpp>
#include <xercesc/sax/SAXParseException.hpp>
namespace ocfa {
 namespace message { 
  class OcfaErrorHandler:public OcfaObject, public xercesc::DefaultHandler {
  public:
    OcfaErrorHandler(bool twarn = true, bool terr = true);
  protected:
    void error(const xercesc::SAXParseException & e);
    void warning(const xercesc::SAXParseException & e);
    void fatalError(const xercesc::SAXParseException & e);
    bool throwerr;
    bool throwwarn;
  };
  }
}
#endif
