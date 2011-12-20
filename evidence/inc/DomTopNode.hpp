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
						
#ifndef __OCFADOMTOPNODE_
#define __OCFADOMTOPNODE_
#include <OcfaErrorHandler.hpp>
#include <OcfaObject.hpp>
#include <misc/OcfaException.hpp>
#include <misc/MemBuf.hpp>
#include <defines.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
namespace ocfa {
  namespace evidence {
    //This class is the base class of the DomEvidence. It takes care of much of the xerces global stuff
    class DomTopNode:public OcfaObject {
    public:
        DomTopNode(std::string name);
        DomTopNode(misc::MemBuf * membuf);
        virtual ~DomTopNode();
	misc::MemBuf * asMemBuf();
	DomTopNode(const DomTopNode& de):OcfaObject(de),mDomDoc(0),mDomNode(0),mMemBuf(0),mFormTarget(0) {
				throw ocfa::misc::OcfaException("Copying of DomTopNode not allowed",this);
			}
       const DomTopNode& operator=(const DomTopNode&) {
          throw ocfa::misc::OcfaException("Assignment of DomTopNode not allowed",this);
	  return *this;
       }
    protected:
      //methods for setting and getting top level attributes.
       void     setAttr(std::string name, std::string val);
       std::string   getAttr(std::string name) const;
       xercesc::DOMDocument * getDOMDoc() { return mDomDoc;}
       xercesc::DOMElement * getTopNode() {return mDomNode;}
    private:
       xercesc::DOMDocument           * mDomDoc;     //The DOMDocument of the XML document
       xercesc::DOMElement            * mDomNode;    //The top DOM node of the xml document.
       misc::MemBuf                   * mMemBuf;             //Used to keep controll of the XML MemBuf
       xercesc::MemBufFormatTarget    * mFormTarget;        //Xerces MemBufFormatTarget for exporting domtree to xml
    public:  
      //Some public static stuff for working with xerces stuff we hold as static protected members. 
      static xercesc::DOMImplementation * getImpl();
      static xercesc::XercesDOMParser * getDomParser();
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
      static xercesc::DOMLSSerializer * getDomWriter();
#else
      static xercesc::DOMWriter * getDomWriter();
#endif
    private:
      static void init_if_needed();
      static void initDOMImplementation();
      static void initDOMParser();
      static void initDOMWriter();
      static xercesc::DOMImplementation * mDomImpl;
      static xercesc::XercesDOMParser * mDomParser;
      static OcfaErrorHandler * mErrorHandler;
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
      static xercesc::DOMLSSerializer * mDomWriter;
#else
      static xercesc::DOMWriter * mDomWriter;
#endif
      static xercesc::MemBufInputSource     * mInputSource;
    };
}}
#endif
