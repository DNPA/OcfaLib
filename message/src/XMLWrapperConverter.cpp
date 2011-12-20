#include "XMLWrapperConverter.hpp"
#include <xercesc/util/XMLString.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <misc.hpp>
#include "OcfaErrorHandler.hpp"
#include "DomHelper.hpp"
using namespace xercesc;
using namespace ocfa;
using namespace ocfa::misc;

namespace ocfa {
  namespace message {
     #define OXMLNAMESIZE 20
     #define OXMLNAMEBUFSIZE OXMLNAMESIZE+1
     bool XMLWrapperConverter::sInitialized = false;
     XMLWrapperConverter::XMLWrapperConverter():OcfaObject("XMLWrapperConverter","message"),
                                                mDomImpl(0),
						mDomParser(0),
						mErrorHandler(0),
						mDomWriter(0),
						mInputSource(0),
						mMessageConverter(*this)
     {
       try {
           misc::OcfaConfig::Instance(); //This line makes config constructor exceptions fire early.
           if (sInitialized == false) {
              XMLPlatformUtils::Initialize();
              sInitialized = true;
           }
           XMLCh tempStr[OXMLNAMEBUFSIZE];
	   XMLString::transcode("LS", tempStr, OXMLNAMESIZE);
	   mDomImpl = DOMImplementationRegistry::getDOMImplementation(tempStr);
	   if (mDomImpl == 0) {
	      throw OcfaException("Could not get DOMImplementation in XMLWrapperConverter constructor",0);
	   }
	   try {
                   mDomParser = new XercesDOMParser();
	   } catch (...) {
                   throw OcfaException("Problem creating a new XercesDOMParser",0);
	   }
                //Configuring the static DOMParser
           try {
                if (misc::OcfaConfig::Instance()->getValue("msgschemacheck") !=string("false")) {
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
                XMLCh scannerName[OXMLNAMESIZE];
	        XMLString::transcode("SGXMLScanner", scannerName, OXMLNAMESIZE);
                mDomParser->useScanner(scannerName);
	   } catch (...) {
                  throw OcfaException("Problem configuring newly created XercesDOMParser",0);	
	   }
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
	   mDomWriter= (static_cast<DOMImplementationLS *>( mDomImpl )->createLSSerializer() );
#else
	   mDomWriter= (static_cast<DOMImplementationLS *>(mDomImpl)->createDOMWriter() );
#endif
	   if (mDomWriter == 0) {
               throw OcfaException("Could not get DOMWriter from Implementation",0);
	   }
	   if (misc::OcfaConfig::Instance()->getValue("msgprettyprint") ==string("false")) {
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
           mInputSource=new MemBufInputSource(0,0,"dummy");
       } catch (OcfaException &e) {
           std::cerr << "Error in static initialization: " << e.what() << std::endl;
           exit(1);
       } catch (...) {
           std::cerr << "Error in static initialization: Unexpected exception type cought." << std::endl; 
       }
     }







     XMLWrapperConverter::~XMLWrapperConverter() {
        //FIXME: this will be a memory leak unless we put it somewhere in a singleton.
     }


    std::string XMLWrapperConverter::XMLMessageConverterImpl::operator()(Message *msg) {
           XMLCh tempStr[OXMLNAMESIZE];
	   XMLString::transcode("message", tempStr, OXMLNAMESIZE);
           xercesc::DOMDocument *domDoc = mXmlWC.mDomImpl->createDocument(0, tempStr, 0);
	   if (domDoc == 0) {
              throw OcfaException("XMLMessageConverter:: Unable to create a brand new domtree from implementation",0);
	   }
	   xercesc::DOMElement *message = domDoc->getDocumentElement(); 
	   if (message == 0) {
              throw OcfaException("XMLMessageConverter::Unable to get root element from DOMDocument", 0);
	   }
	   string schemadir=misc::OcfaConfig::Instance()->getValue("schemadir");
	   if (schemadir == "") {
	           schemadir=misc::OcfaConfig::Instance()->getValue("ocfaroot") + "/schema";
	   }
	   DomHelper::getInstance()->setAttribute(message,"xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance");
	   DomHelper::getInstance()->setAttribute(message,"xsi:noNamespaceSchemaLocation",string("ocfa.xsd"));
           mXmlWC.fillDomMessage(message,msg,domDoc);
	   MemBufFormatTarget *formTarget = new MemBufFormatTarget();
	   try {
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
             XMLCh tempStr[100];
	     XMLString::transcode("Core", tempStr, 99);    
             DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(tempStr);
             DOMLSOutput *theOutput = (static_cast<DOMImplementationLS *>(impl)->createLSOutput() );
             theOutput->setByteStream(formTarget);
             mXmlWC.mDomWriter->write(message,theOutput);
#else
             mXmlWC.mDomWriter->writeNode(formTarget, *message);
#endif
	   } 
	   catch(const XMLException & toCatch) {
	        throw OcfaException("XMLMessageConverter::XMLExeption while writing domtree to membuf",0);
	   } 
	   catch(const DOMException & toCatch) { 
	        throw OcfaException("XMLMessageConverter::DOMExeption while writing domtree to membuf",0);
	   } 
	   catch(...) {
	        throw OcfaException("XMLMessageConverter::Unknown Exeption while writing domtree to membuf",0);
	   }
           misc::MemBuf mrval(const_cast<unsigned char *>(formTarget->getRawBuffer()),formTarget->getLen());
           std::string rval=mrval;
           delete formTarget;
           delete domDoc;
           return rval;
    }


    std::string XMLWrapperConverter::operator()(MessageWrapper *wrapper) {
           XMLCh tempStr[OXMLNAMESIZE];
	   XMLString::transcode("l2wrapper", tempStr, OXMLNAMESIZE);
	   xercesc::DOMDocument *domDoc = mDomImpl->createDocument(0, tempStr, 0);
	   if (domDoc == 0) {
              throw OcfaException("Unable to create a brand new domtree from implementation",this);
	   }
	   xercesc::DOMElement *domNode = domDoc->getDocumentElement(); 
	   if (domNode == 0) {
              throw OcfaException("Unable to get root element from DOMDocument", this);
	   }
	   string schemadir=misc::OcfaConfig::Instance()->getValue("schemadir");
	   if (schemadir == "") {
	           schemadir=misc::OcfaConfig::Instance()->getValue("ocfaroot") + "/schema";
	   }
	   DomHelper::getInstance()->setAttribute(domNode,"xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance");
	   DomHelper::getInstance()->setAttribute(domNode,"xsi:noNamespaceSchemaLocation",string("ocfa.xsd"));
	   ocfa::misc::Scalar anycastid(wrapper->getAnyCastID());
	   DomHelper::getInstance()->setAttribute(domNode,"id",anycastid.asASCII());
	   switch(wrapper->getType()) {
             case MessageWrapper::mwTask:	         
                 DomHelper::getInstance()->setAttribute(domNode,"type",string("task"));
		 break;
	     case MessageWrapper::mwTaskProgress:
                 DomHelper::getInstance()->setAttribute(domNode,"type",string("progress"));
		 break;
	     case MessageWrapper::mwUser:
                 DomHelper::getInstance()->setAttribute(domNode,"type",string("user"));
		 break;
	     case MessageWrapper::mwInternalConnect:
	         DomHelper::getInstance()->setAttribute(domNode,"type",string("internalconnect"));
		 break;
	     case MessageWrapper::mwInternalDisconnect:
	         DomHelper::getInstance()->setAttribute(domNode,"type",string("internaldisconnect"));
	         break;
	   }
	   ocfa::message::Message *msg=wrapper->getPayLoad();
           if (msg) {
	      DOMElement *message =0;
              DomHelper::getInstance()->createElement(&message,domDoc,"message");
	      domNode->appendChild(message);
              fillDomMessage(message,msg,domDoc);
	   }
	   MemBufFormatTarget *formTarget = new MemBufFormatTarget();
	   try {
#if defined (XERCESC_INCLUDE_GUARD_DOMLSSERIALIZER_HPP)
	     XMLCh tempStr[100];
	     XMLString::transcode("Core", tempStr, 99);
	     DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(tempStr);
	     DOMLSOutput *theOutput = (static_cast<DOMImplementationLS *>(impl)->createLSOutput() );
	     theOutput->setByteStream(formTarget);
	     mDomWriter->write(domNode,theOutput);
#else
	     mDomWriter->writeNode(formTarget, *domNode);
#endif
	   } 
	   catch(const XMLException & toCatch) {
	        throw OcfaException("XMLExeption while writing domtree to membuf",this);
	   } 
	   catch(const DOMException & toCatch) { 
	        throw OcfaException("DOMExeption while writing domtree to membuf",this);
	   } 
	   catch(...) {
	        throw OcfaException("Unknown Exeption while writing domtree to membuf",this);
	   }
           misc::MemBuf mrval(const_cast<unsigned char *>(formTarget->getRawBuffer()),formTarget->getLen());
           std::string rval=mrval;
           delete formTarget;
           delete domDoc;
           return rval;
     }

     Message *XMLWrapperConverter::XMLMessageConverterImpl::operator()(std::string str) {
        misc::MemBuf buf(str);
        try {
           mXmlWC.mInputSource->resetMemBufInputSource(static_cast<const XMLByte*>(buf.getPointer()),buf.getSize());
	   mXmlWC.mDomParser->parse(*( mXmlWC.mInputSource));
           DomDocRaiiClass domDoc(mXmlWC.mDomParser->adoptDocument());
           if (domDoc() == 0) {
              throw OcfaException("Unable to get DOMDocument from parser", 0);
           }
           DOMElement *message = domDoc()->getDocumentElement();
           if (message == 0) {
              throw OcfaException("Unable to get root element from DOMDocument", 0);
           }
           return mXmlWC.getMessage(message);
        } 
	catch (InvalidXMLException &e) {
          e.logWhat();
          throw InvalidXMLException(str);
        } 
	catch(...) {
	  throw OcfaException(std::string("Unexpected exception cougth while parsing input :") + str , 0); 
	}
     }
 
     MessageWrapper *XMLWrapperConverter::operator()(std::string str) {
        misc::MemBuf buf(str);
        try {
          mInputSource->resetMemBufInputSource(static_cast<const XMLByte*>(buf.getPointer()),buf.getSize());
	  mDomParser->parse(*mInputSource);
          DomDocRaiiClass domDoc(mDomParser->adoptDocument()); 
          if (domDoc() == 0) {
             throw OcfaException("Unable to get DOMDocument from parser", 0);
          }
          DOMElement *l2message = domDoc()->getDocumentElement();
          if (l2message == 0) {
             throw OcfaException("Unable to get root element from DOMDocument", 0);
          }
          DOMNodeList *messages = DomHelper::getInstance()->getElementsByTagName(l2message,"message");
	  Message *msg=0;
	  if (messages) {
            XMLSize_t lsize = messages->getLength();
            if (lsize > 0) {
              DOMElement *message = dynamic_cast < DOMElement * >(messages->item(0));
              if (message == 0) {
	         throw OcfaException("Unable to cast message element from XML doc into a DOMElement",this); 
              }
	      msg=getMessage(message);
	    }
	  }
          misc::Scalar anycastid(DomHelper::getInstance()->getAttribute(l2message,"id"));
	  unsigned long msgid=anycastid.asInt();
	  std::string l2type=DomHelper::getInstance()->getAttribute(l2message,"type");
	  message::MessageWrapper::mwType typ=MessageWrapper::mwTask;
	  if (l2type == "task") {
            typ=MessageWrapper::mwTask;
	  } else if (l2type == "progress") {
            typ=MessageWrapper::mwTaskProgress;
	  } else if (l2type == "user") {
            typ=MessageWrapper::mwUser;
	  } else if (l2type == "internaldisconnect") {
            typ=MessageWrapper::mwInternalDisconnect;
	  } else if (l2type == "internalconnect") {
            typ=MessageWrapper::mwInternalConnect;
	  } else {
	   getLogStream(LOG_ERR) << "Undefined layer 2 message type \"" << l2type << "\"\n";
           throw OcfaException("Undefined layer 2 message type used.",0);
	  }
	  MessageWrapper *rval=new MessageWrapper(typ,msg);
	  rval->setAnyCastID(msgid);
          return rval;	
        }
        catch (InvalidXMLException &e) {
          e.logWhat();
          throw InvalidXMLException(str);
        }
        catch(...) {
          throw OcfaException(std::string("Unexpected exception cougth while parsing input :") + str, 0);
        }
     }


     ModuleInstance *XMLWrapperConverter::getModInstance(DOMElement *instance) {
        std::string host=DomHelper::getInstance()->getAttribute(instance,"host");
	std::string inst= DomHelper::getInstance()->getAttribute(instance,"instance");
	std::string ns= DomHelper::getInstance()->getAttribute(instance,"namespace");
	std::string module= DomHelper::getInstance()->getAttribute(instance,"module");
	misc::ModuleInstance *rval=new misc::ModuleInstance(host,module,ns,inst);
	return rval;
     }
     ModuleInstance *XMLWrapperConverter::getModTypeInstance(DOMElement *instance) {
        std::string ns= DomHelper::getInstance()->getAttribute(instance,"namespace");
	std::string module= DomHelper::getInstance()->getAttribute(instance,"module");
	misc::ModuleInstance *rval=new misc::ModuleInstance("*",module,ns,"*");
        return rval;
     }



     Message *XMLWrapperConverter::getMessage(DOMElement *message) {
       misc::Scalar prioscalar(DomHelper::getInstance()->getAttribute(message,"prio"));
       int prio=prioscalar.asInt();
       DOMNodeList *senders = DomHelper::getInstance()->getElementsByTagName(message,"sender");
       if ((senders == 0)||(senders->getLength()<1)) {
          throw OcfaException("No sender tag found in message",this);
       }
       DOMElement *sender=dynamic_cast < DOMElement * >(senders->item(0));
       ModuleInstance *senderinstance=getModInstance(sender);
       DOMNodeList *casts =  DomHelper::getInstance()->getElementsByTagName(message,"broadcast");
       Message::CastType ctyp=Message::BROADCAST;
       ModuleInstance *receiverinstance=0;
       if ((casts == 0)|| (casts->getLength()<1)) { 
          casts =  DomHelper::getInstance()->getElementsByTagName(message,"anycast");
	  if ((casts == 0)|| (casts->getLength()<1)) {
             casts =  DomHelper::getInstance()->getElementsByTagName(message,"multicast");
              if ((casts == 0)|| (casts->getLength()<1)) {
                 casts =  DomHelper::getInstance()->getElementsByTagName(message,"unicast");
		 if ((casts == 0)|| (casts->getLength()<1)) {
                    throw OcfaException("No valis receiver/cast tag found in message",this);
		 } 
                 ctyp=Message::UNICAST;
	      } else {
                 ctyp=Message::MULTICAST;
	      }
	  } else {
	     ctyp=Message::ANYCAST;
             //anycast
	  }
       }
       DOMElement *cast=dynamic_cast < DOMElement * >(casts->item(0));
       switch(ctyp) {
         case Message::UNICAST:
	    receiverinstance=getModInstance(cast);
	    break;
	 case Message::MULTICAST:
	 case Message::ANYCAST:
	    receiverinstance=getModTypeInstance(cast);
	 case Message::BROADCAST:
	    break;
       }
       DOMNodeList *payloads=DomHelper::getInstance()->getElementsByTagName(message,"evidence");
       Message::MessageType typ=Message::mtSubscribe;
       if ((payloads == 0)||(payloads->getLength()<1)) {
         payloads=DomHelper::getInstance()->getElementsByTagName(message,"subscribe");
         if ((payloads == 0)||(payloads->getLength()<1)) { 
           payloads=DomHelper::getInstance()->getElementsByTagName(message,"unsubscribe");
	   if ((payloads == 0)||(payloads->getLength()<1)) {
             payloads=DomHelper::getInstance()->getElementsByTagName(message,"halt");
	     if ((payloads == 0)||(payloads->getLength()<1)) {
               payloads=DomHelper::getInstance()->getElementsByTagName(message,"eoc");
	       if ((payloads == 0)||(payloads->getLength()<1)) {
                  payloads=DomHelper::getInstance()->getElementsByTagName(message,"moduleinstance");
		  if ((payloads == 0)||(payloads->getLength()<1)) {
                    payloads=DomHelper::getInstance()->getElementsByTagName(message,"heartbeat");
		    if ((payloads == 0)||(payloads->getLength()<1)) {
                       payloads=DomHelper::getInstance()->getElementsByTagName(message,"disconnect");
		       if ((payloads == 0)||(payloads->getLength()<1)) {
                         payloads=DomHelper::getInstance()->getElementsByTagName(message,"progress");
			 if ((payloads == 0)||(payloads->getLength()<1)) {
                            payloads=DomHelper::getInstance()->getElementsByTagName(message,"system");
			    if ((payloads == 0)||(payloads->getLength()<1)) {
                              payloads=DomHelper::getInstance()->getElementsByTagName(message,"system");
			      if ((payloads == 0)||(payloads->getLength()<1)) {
                                 throw OcfaException("No valid payload tag found in message",this);
			      } else {
                                 typ= Message::mtRecover;
			      }
			    } else {
                               typ= Message::mtSystem;
			    }
			 } else {
                            typ=Message::mtTaskProgress;
			 }
		       } else {
                         typ=Message::mtModuleDisconnect;
		       }
		    } else {
                       typ=Message::mtHeartBeat;
		    }
		  } else {
                    typ=Message::mtModuleInstance;
		  }
	       } else {
                  typ=Message::mtEOC;
	       }
	     } else {
               typ=Message::mtHalt;
	     }
	   } else {
             typ=Message::mtUnsubscribe;
	   }
	 } else {
           typ=Message::mtSubscribe;
	 }
       } else {
         typ=Message::mtEvidence;
       }
       DOMElement *payload=dynamic_cast < DOMElement * >(payloads->item(0));
       std::string subject=DomHelper::getInstance()->getAttribute(payload,"subject");
       const XMLCh *xcontent=static_cast<const XMLCh *>( payload->getTextContent() );
       char *tcontent=DomHelper::transcode(xcontent);
       std::string content(tcontent);
       XMLString::release(&tcontent);
       message::ConcreteMessage *rval=new ConcreteMessage(senderinstance,receiverinstance,ctyp,typ,subject,content,prio); 
       delete senderinstance;
       delete receiverinstance;
       return rval;
     }
             
     void  XMLWrapperConverter::fillDomMessage(DOMElement *message,Message *msg,DOMDocument *domDoc){
              ocfa::misc::Scalar prio(msg->getPriority());
              DomHelper::getInstance()->setAttribute(message,"prio",prio.asASCII());
	      DOMElement *sender=0;
	      DomHelper::getInstance()->createElement(&sender,domDoc,"sender");
	      message->appendChild(sender);
	      ModuleInstance *snd=msg->getSender();
	      DomHelper::getInstance()->setAttribute(sender,"host",snd->getHostname());
              DomHelper::getInstance()->setAttribute(sender,"instance",snd->getInstanceName());
	      DomHelper::getInstance()->setAttribute(sender,"namespace",snd->getNameSpace());
	      DomHelper::getInstance()->setAttribute(sender,"module",snd->getModuleName());
	      DOMElement *cast=0;
	      switch (msg->getCastType()) {
                case Message::BROADCAST:
		   DomHelper::getInstance()->createElement(&cast,domDoc,"broadcast");
		   break;
		case Message::MULTICAST:
		   DomHelper::getInstance()->createElement(&cast,domDoc,"multicast");
		   break;
		case Message::ANYCAST:
		   DomHelper::getInstance()->createElement(&cast,domDoc,"anycast");
		   break;
		case Message::UNICAST:
		   DomHelper::getInstance()->createElement(&cast,domDoc,"unicast");
		   break;
	      }
              message->appendChild(cast);
	      ModuleInstance *recv=msg->getReceiver();
	      switch (msg->getCastType()) {
                  case Message::UNICAST:
                       DomHelper::getInstance()->setAttribute(cast,"host",recv->getHostname());
		       DomHelper::getInstance()->setAttribute(cast,"instance",recv->getInstanceName());
		  case Message::ANYCAST:
		  case Message::MULTICAST:
                       DomHelper::getInstance()->setAttribute(cast,"namespace",recv->getNameSpace());
		       DomHelper::getInstance()->setAttribute(cast,"module",recv->getModuleName());
                  case Message::BROADCAST:
		     break;
	      }
              DOMElement *payload=0;
	      switch (msg->getType()) {
                 case Message::mtSubscribe:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"subscribe");
		    break;
		 case Message::mtUnsubscribe:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"unsubscribe");
		    break;
		 case Message::mtHalt:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"halt");
		    break;
		 case Message::mtEOC:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"eoc");
		    break;
		 case Message::mtModuleInstance:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"moduleinstance");
		    break;
		 case Message::mtEvidence:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"evidence");
		    break;
		 case Message::mtHeartBeat:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"heartbeat");
		    break;
		 case Message::mtModuleDisconnect:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"disconnect");
		    break;
		 case Message::mtTaskProgress:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"progress");
		    break;
		 case Message::mtSystem:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"system");
		    break;
		 case Message::mtRecover:
		    DomHelper::getInstance()->createElement(&payload,domDoc,"recover");
		    break;
	      }
              message->appendChild(payload);
              DomHelper::getInstance()->setAttribute(payload,"subject",msg->getSubject());
	      XMLCh *argval;
	      argval = DomHelper::transcode(msg->getContent().c_str());
	      payload->appendChild(domDoc->createTextNode(argval));
	      XMLString::release(&argval);
     }
     XMLMessageConverter &getMessageConverter(){
        return serializeMessageWrapper; 
     }
  }
}

