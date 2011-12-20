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

#ifndef INCLUDED_OCFAWRAPPERSERIALIZER_H
#define INCLUDED_OCFAWRAPPERSERIALIZER_H
#include <string>
#include <misc.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include "OcfaErrorHandler.hpp"
#include "message/Message.hpp"
#include "message/Serialize.hpp"
#include "MessageWrapper.hpp"

namespace ocfa {

  namespace message {
    class XMLWrapperConverter: public OcfaObject {
       public:
          class XMLMessageConverterImpl: public XMLMessageConverter {
	    public:
             XMLMessageConverterImpl(XMLWrapperConverter &xmlWC):mXmlWC(xmlWC){}
             std::string operator()(Message *message);
	     Message *operator()(std::string xml);
	    private:
	     XMLWrapperConverter &mXmlWC;
	  };
          class DomDocRaiiClass {
               xercesc::DOMDocument *mDomDoc;
             public:
               DomDocRaiiClass(xercesc::DOMDocument *doc):mDomDoc(doc){}
               ~DomDocRaiiClass(){delete mDomDoc;}
               xercesc::DOMDocument * operator()() {return mDomDoc;}
          };
          XMLWrapperConverter();
	  std::string operator()(MessageWrapper *wrapper);
	  MessageWrapper *operator()(std::string xml);
	  ~XMLWrapperConverter();
	  operator XMLMessageConverter & () { return mMessageConverter; }
       private:
          void fillDomMessage(xercesc::DOMElement *message,Message *msg,xercesc::DOMDocument *domDoc);
          misc::ModuleInstance *getModInstance(xercesc::DOMElement *sender);
	  misc::ModuleInstance *getModTypeInstance(xercesc::DOMElement *sender);
          Message *getMessage(xercesc::DOMElement *message);
          xercesc::DOMImplementation * mDomImpl;
	  xercesc::XercesDOMParser * mDomParser;
          ocfa::message::OcfaErrorHandler * mErrorHandler;
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
	  xercesc::DOMLSSerializer * mDomWriter;
#else
          xercesc::DOMWriter * mDomWriter;
#endif
	  xercesc::MemBufInputSource     * mInputSource;
	  XMLMessageConverterImpl mMessageConverter;
          static bool sInitialized;
    };
    static XMLWrapperConverter serializeMessageWrapper;
  }

}

#endif
