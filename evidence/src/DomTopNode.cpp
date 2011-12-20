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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <DomTopNode.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <OcfaErrorHandler.hpp>
#include <sys/time.h>
#include <DomHelper.hpp>
using namespace xercesc;
using namespace std;
using namespace ocfa::misc;
namespace ocfa
{
  namespace evidence
  {
      OcfaErrorHandler   *DomTopNode::mErrorHandler=0;
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
      DOMLSSerializer	 *DomTopNode::mDomWriter=0;
#else
      DOMWriter          *DomTopNode::mDomWriter=0;
#endif
      DOMImplementation  *DomTopNode::mDomImpl=0;
      XercesDOMParser    *DomTopNode::mDomParser=0;
      MemBufInputSource  *DomTopNode::mInputSource=0;

      void DomTopNode::initDOMImplementation() {
           //Creating the static DOMImplementation 
	   XMLCh tempStr[OXMLNAMEBUFSIZE];
	   XMLString::transcode("LS", tempStr, OXMLNAMESIZE);
	   mDomImpl = DOMImplementationRegistry::getDOMImplementation(tempStr);
	   if (mDomImpl == 0) {
                   throw OcfaException("Could not get DOMImplementation in DomTopNode::init_if_needed",0);
	   }
      }
      void DomTopNode::initDOMParser() {
	   //Creating the static DOMParser
	   try {
                   mDomParser = new XercesDOMParser();
           } catch (const XMLException & toCatch) {
                OcfaLogger::Instance()->syslog(LOG_CRIT) << "DomTopNode XMLException:" <<  DomHelper::transcode(toCatch.getMessage()) << std::endl;
                throw OcfaException("XML exception cougth while creating a new XercesDOMParser", 0);
           } catch (const DOMException & toCatch) {
                OcfaLogger::Instance()->syslog(LOG_CRIT) << "DomTopNode DOMException:" <<  DomHelper::transcode(toCatch.getMessage()) << std::endl;
                throw OcfaException("DOM exception cougth while creating a new XercesDOMParser", 0);
           } catch (const SAXException & toCatch) {
                OcfaLogger::Instance()->syslog(LOG_CRIT) << "DomTopNode SAXException:" <<  DomHelper::transcode(toCatch.getMessage()) << std::endl;
                throw OcfaException("SAX exception cougth while creating a new XercesDOMParser", 0);
           } catch (OcfaException &e) {
                     e.logWhat();
                     throw OcfaException("Unexpected OcfaException while creating a new XercesDOMParser",0);
	   } catch (...) {
                   throw OcfaException("Unknown and unexpected exception while creating new XercesDOMParser",0);
	   }
                //Configuring the static DOMParser
           try {
                if (misc::OcfaConfig::Instance()->getValue("schemacheck") !=string("false")) {
                   mErrorHandler = new OcfaErrorHandler();
	           mDomParser->setValidationScheme(XercesDOMParser::Val_Always);
	           mDomParser->setDoSchema(true);
	           mDomParser->setValidationConstraintFatal(true);
	           mDomParser->setValidationSchemaFullChecking(true);
	           string schemadir=misc::OcfaConfig::Instance()->getValue("schemadir");
	           if (schemadir == "") {
                      schemadir=misc::OcfaConfig::Instance()->getValue("ocfaroot") + "/schema";
	           }
		   struct stat schemastat;
		   if (stat(schemadir.c_str(),&schemastat) != 0)
		       throw OcfaException("Schema directory does not exist or is not accesable",0);
		   if (! (S_ISDIR(schemastat.st_mode)))
		       throw OcfaException("Schema directory path does not refer to a directory",0);
                   //Note, this is not sufficiently generic, but as we only have one type of DomTopNode this should be ok
	           mDomParser->setExternalNoNamespaceSchemaLocation((schemadir + "/ocfa.xsd").c_str());
                   if (stat((schemadir + "/ocfa.xsd").c_str(),&schemastat) != 0)
			   throw OcfaException("Schema file ocfa.xsd does not exist or is not accesable",0);
		   if (! (S_ISREG(schemastat.st_mode)))
			   throw OcfaException("Schema file path does not refer to a regular file",0);
	           mDomParser->setDoNamespaces(false);
	           mDomParser->useCachedGrammarInParse(true);
	           mDomParser->cacheGrammarFromParse(true);
	        }
	        else {
                   mErrorHandler = new OcfaErrorHandler(false,false);
	           mDomParser->setValidationScheme(XercesDOMParser::Val_Never);
	           mDomParser->setDoSchema(false);
                   mDomParser->setValidationConstraintFatal(false);
	           mDomParser->setValidationSchemaFullChecking(false);
	           mDomParser->setDoNamespaces(false);
	           mDomParser->useCachedGrammarInParse(false);
	           mDomParser->cacheGrammarFromParse(false);
	        }
                mDomParser->setErrorHandler(mErrorHandler);
                XMLCh *scannerName = DomHelper::transcode("SGXMLScanner");
                mDomParser->useScanner(scannerName);
	        XMLString::release(&scannerName);

           } catch (const XMLException & toCatch) {
                OcfaLogger::Instance()->syslog(LOG_CRIT) << "DomTopNode XMLException:" <<  DomHelper::transcode(toCatch.getMessage()) << std::endl;
                throw OcfaException("XML exception cougth while configuring newly created XercesDOMParser", 0);
           } catch (const DOMException & toCatch) {
                OcfaLogger::Instance()->syslog(LOG_CRIT) << "DomTopNode DOMException:" <<  DomHelper::transcode(toCatch.getMessage()) << std::endl;
                throw OcfaException("DOM exception cougth while configuring newly created XercesDOMParser", 0);
           } catch (const SAXException & toCatch) {
                OcfaLogger::Instance()->syslog(LOG_CRIT) << "DomTopNode SAXException:" <<  DomHelper::transcode(toCatch.getMessage()) << std::endl;
                throw OcfaException("SAX exception cougth while configuring newly created XercesDOMParser", 0);
           } catch (OcfaException &e) {
                     e.logWhat();
                     throw OcfaException("Unexpected OcfaException while configuring newly created XercesDOMParser",0);
	   } catch (...) {
                  throw OcfaException("Problem configuring newly created XercesDOMParser",0);	
	   }
      }
      void DomTopNode::initDOMWriter() {
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
            mDomWriter= (static_cast<DOMImplementationLS *>( getImpl())->createLSSerializer() );
#else
            mDomWriter= (static_cast<DOMImplementationLS *>( getImpl())->createDOMWriter() );
#endif
	    if (mDomWriter == 0) {
               throw OcfaException("Could not get DOMWriter from Implementation",0);
	    }
	    if (misc::OcfaConfig::Instance()->getValue("prettyprint") ==string("false")) {
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)                
		mDomWriter->getDomConfig()->setParameter(XMLUni::fgDOMWRTFormatPrettyPrint, false);
#else
                mDomWriter->setFeature(XMLUni::fgDOMWRTFormatPrettyPrint, false);
#endif
	    } else {
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
                mDomWriter->getDomConfig()->setParameter(XMLUni::fgDOMWRTFormatPrettyPrint, true);
#else
                mDomWriter->setFeature(XMLUni::fgDOMWRTFormatPrettyPrint, true);
#endif
	    }           
      }      

      void DomTopNode::init_if_needed() {
            if (!(mDomImpl)) {
                XMLPlatformUtils::Initialize();
                initDOMImplementation();
                initDOMParser();
                initDOMWriter();
		mInputSource=new MemBufInputSource(0,0,"dummy");
            }	    
      }
      
      DOMImplementation  *DomTopNode::getImpl(){
        init_if_needed();
	return mDomImpl;
      }
      
      XercesDOMParser    *DomTopNode::getDomParser(){
        init_if_needed();
	return mDomParser;
      }
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
      DOMLSSerializer	 *DomTopNode::getDomWriter() {
#else 
      DOMWriter          *DomTopNode::getDomWriter() {
#endif
     	      init_if_needed();
	 return mDomWriter;
      }
      
      void DomTopNode::setAttr(string name, string val) {
	      if (mDomNode == NULL) {
                 throw OcfaException("getAttr called with mDomNode=NULL",this);
	      }
	      DomHelper::getInstance()->setAttribute(mDomNode,name,val);
      }
      
      string DomTopNode::getAttr(string name) const {
	      if (mDomNode == NULL) {
		  throw OcfaException("getAttr called with mDomNode=NULL",this);
	      }
	      return DomHelper::getInstance()->getAttribute(mDomNode,name);
      }
      
      /** Get the MetaMemBuf representation of the DOM tree */
      misc::MemBuf 			*DomTopNode::asMemBuf(){
	 if (mMemBuf) {
		 delete mMemBuf; 
		 mMemBuf=0; 
		 delete mFormTarget;
	 }
	 mFormTarget = new MemBufFormatTarget(); 
         try {
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
	    DOMLSOutput *theOutput = (static_cast<DOMImplementationLS *>( getImpl())->createLSOutput() );
	    theOutput->setByteStream(mFormTarget);
            getDomWriter()->write(mDomNode,theOutput);
#else
            getDomWriter()->writeNode(mFormTarget, *mDomNode); 
#endif
	 } catch(const XMLException & toCatch) {
		throw OcfaException("XMLExeption while writing domtree to membuf",this);
	 } catch(const DOMException & toCatch) { 
                throw OcfaException("DOMExeption while writing domtree to membuf",this);
	 } catch(...) {
                throw OcfaException("Unknown Exeption while writing domtree to membuf",this);
	 }
         mMemBuf=new MemBuf(const_cast<unsigned char *>(mFormTarget->getRawBuffer()),mFormTarget->getLen());
	 return mMemBuf;
      }
      
      DomTopNode::DomTopNode(std::string name):
	      OcfaObject("DomTopNode","evidence"),
	      mDomDoc(0),
	      mDomNode(0),
              mMemBuf(0),
	      mFormTarget(0)
      {
	   init_if_needed();
	   updateTypeName("DomTopNode");
	   ocfaLog(LOG_DEBUG,"Fetching implementation");
	   XMLCh tempStr[OXMLNAMESIZE];
	   XMLString::transcode(name.c_str(), tempStr, OXMLNAMESIZE);
	   ocfaLog(LOG_DEBUG,"Creating domdoc");
	   mDomDoc = getImpl()->createDocument(0, tempStr, 0);
	   if (mDomDoc == 0) {
              throw OcfaException("Unable to create a brand new domtree from implementation",0);
	   }
	   ocfaLog(LOG_DEBUG,"Fetching root dom node");
	   mDomNode = mDomDoc->getDocumentElement(); 
	   if (mDomNode == 0) {
              throw OcfaException("Unable to get root element from DOMDocument", 0);
	   }
	   ocfaLog(LOG_DEBUG,"Setting some arguments");
	   string schemadir=misc::OcfaConfig::Instance()->getValue("schemadir");
	   if (schemadir == "") {
	           schemadir=misc::OcfaConfig::Instance()->getValue("ocfaroot") + "/schema";
	   }
	   struct stat schemadirstat;
	   if (stat(schemadir.c_str(),&schemadirstat) != 0)
		     throw OcfaException("Schema directory does not exist or is not accesable",0);
	   if (! (S_ISDIR(schemadirstat.st_mode)))
		     throw OcfaException("Schema directory path does not refer to a directory",0);
	   setAttr("xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance");
	   setAttr("xsi:noNamespaceSchemaLocation",string("ocfa.xsd"));
	   ocfaLog(LOG_DEBUG,"Done constructing");
      }
      
      DomTopNode::DomTopNode(misc::MemBuf *membuf):
	      OcfaObject("DomTopNode","evidence"),
	      mDomDoc(0),
	      mDomNode(0),
	      mMemBuf(0),
	      mFormTarget(0)
      {
	   init_if_needed();
	   mInputSource->resetMemBufInputSource(static_cast<const XMLByte*>(membuf->getPointer()),membuf->getSize());
	   //MemBufInputSource *inputsource=new MemBufInputSource(static_cast<const XMLByte*>(membuf->getPointer()),membuf->getSize(),"dummy");
           try {
	         getDomParser()->parse(*mInputSource);
	   } catch (const XMLException & toCatch) {
                throw OcfaException("XML exception cougth while parsing input", 0);
	   } catch (const DOMException & toCatch) {
                throw OcfaException("DOM exception cougth while parsing input", 0);
	   } catch (const SAXException & toCatch) {
		throw OcfaException("SAX exception cougth while parsing input", 0);
	   } catch (OcfaException &e) {
		     e.logWhat();
		     throw OcfaException("Parse error while parsing xml",0);
	   } catch(...) {
                throw OcfaException("Unexpected exception cougth while parsing input", 0); 
	   }
	   mDomDoc=getDomParser()->adoptDocument();
	   if (mDomDoc == 0) {
	        throw OcfaException("Unable to get DOMDocument from parser", 0);
	   }
	   mDomNode = mDomDoc->getDocumentElement();
	   if (mDomNode == 0) {
                throw OcfaException("Unable to get root element from DOMDocument", 0);
	   }
	   return;
      } 
      
      DomTopNode::~DomTopNode(){
	 ocfaLog(LOG_DEBUG,"Starting destructor");
	 if (mMemBuf) {delete mMemBuf;mMemBuf=0;delete mFormTarget;}
	 ocfaLog(LOG_DEBUG,"mMemBuf processed");
	 if (mDomDoc) {delete mDomDoc;mDomDoc=0;}
	 ocfaLog(LOG_DEBUG,"Done destructor");
      }
  }
}
