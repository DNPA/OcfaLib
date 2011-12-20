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
#include <DomHelper.hpp>						
#include <OcfaErrorHandler.hpp>
#include <xercesc/sax/SAXException.hpp>
#include <xercesc/util/XMLString.hpp>
#include <misc/OcfaException.hpp>
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace message {
    OcfaErrorHandler::OcfaErrorHandler(bool twarn, bool terr)
	    :OcfaObject("OcfaErrorHandler","evidence"),
	    throwerr(terr),
	    throwwarn(twarn)
    {
    }
    void OcfaErrorHandler::error(const xercesc::SAXParseException & e){
        if (throwerr) throw InvalidXMLException(message::DomHelper::transcode(e.getMessage()),this);
    }
    void OcfaErrorHandler::warning(const xercesc::SAXParseException & e){
        if (throwwarn) throw InvalidXMLException(message::DomHelper::transcode(e.getMessage()),this);
    }
    void OcfaErrorHandler::fatalError(const xercesc::SAXParseException & e){
        throw InvalidXMLException(message::DomHelper::transcode(e.getMessage()),this);
    }
  }
}
