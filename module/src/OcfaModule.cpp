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
						
#include <sstream>
#include <boost/lexical_cast.hpp>
#include "module/OcfaModule.hpp"
#include "misc/MemBuf.hpp"
#include "misc/OcfaException.hpp"
#include "store/MetaStoreEntity.hpp"
#include "misc/ModuleInstance.hpp"
#include "store/AbstractRepository.hpp"
using namespace ocfa::evidence;
using namespace ocfa::message;
using namespace ocfa::misc;
using ocfa::store::MetaStoreEntity;
using ocfa::store::AbstractRepository;
using namespace std;

namespace ocfa {
  
  namespace module {
    OcfaModule::OcfaModule(): 
	    OcfaObject("OcfaModule", "module"),
	    mpStop(false),
	    mGroup("ocfa"),
	    mpEvidenceFactory(0),
	    mpActiveEvidence(0),
	    mpMessageBox(0)
    {
    }

   OcfaModule::OcfaModule(const OcfaModule &)
     : OcfaObject("OcfaModule", "module"),
	    mGroup("ocfa"),
	    mpEvidenceFactory(0),
	    mpActiveEvidence(0),
	    mpMessageBox(0){

      throw OcfaException("cannot use copy constuctor");
    }

    OcfaModule::~OcfaModule(){
        ocfaLog(LOG_DEBUG, "~OcfaModule() called, deleting MessageBox");
	delete mpMessageBox;
	mpMessageBox = 0;
	ocfaLog(LOG_DEBUG, "Deleted MessageBox");
    }

   
     /**
       * dispatches the message. 
       *
       */    
   void OcfaModule::handleMessage(const Message *message){
      
      if (message == 0){
	throw OcfaException("OcfaModule::handleMessage called without a message", this);
      }
      std::string contextstring=std::string("T:") + 
          boost::lexical_cast<std::string>(static_cast<int>(message->getType())) +
          std::string(".C:") + 
          message->getContent();
      OcfaLogger::Instance()->setcontext(contextstring); 
      dispatchMessage(*message);
      ocfaLog(LOG_DEBUG, "Setting message to DONE ! ");
      mpMessageBox->messageDone(message); 
      ocfaLog(LOG_DEBUG, "Message set to Done");
      OcfaLogger::Instance()->clearcontext();
    }
    
    //void OcfaModule::msgSend(msg_type type, string subtype, MsgStoreEntity *content,
    //			 prio_type priority){
    //}
    
    /**
     * dispatches the message according to message type.
     */
    void OcfaModule::dispatchMessage(const Message &message){

      getLogStream(LOG_INFO) << "dispatching message with type " << static_cast<int>(message.getType())
			     << " and content " << message.getContent() << endl; 
      ocfaLog(LOG_DEBUG, "entering dispatch message");
      switch (message.getType()){	
	
      case Message::mtEvidence:
	processEvidenceMessage(message);
	break;
	// two kinds, the kind that are send by the architecture and the 
	// kind that are sent by a user. (like logging).
      case Message::mtHeartBeat:
	processHeartBeatMessage(message);
	break;
      case Message::mtHalt:
	getLogStream(LOG_NOTICE) << "received message to stop" << endl;
	mpStop = true;
	break;
      case Message::mtSystem:
	processSystemMessage(message);
	break;
	//following message types will nog be handles for now.
      case::Message::mtSubscribe:
      case::Message::mtUnsubscribe:
      case::Message::mtModuleInstance:
      case::Message::mtModuleDisconnect:
      case::Message::mtTaskProgress:
      case::Message::mtRecover:
	  break;
      case::Message::mtEOC:
	  //(RJM) FIXME: it seems that a module SHOULD handle mtEOC
      default:
	getLogStream(LOG_WARNING) << "MessageType not handled" << static_cast<int>(message.getType()) << endl;
      }
      
    }

    // should be filled in.
    void OcfaModule::processHeartBeatMessage(const Message &){
    }

    void OcfaModule::processSystemMessage(const Message &inMessage){

      if (inMessage.getSubject() == "SetLogLevel"){
	string prefix;
	string logLevelString;
	istringstream contentStream(inMessage.getContent());
	contentStream >> prefix;
	contentStream >> logLevelString;
	if (prefix == "all"){
	  OcfaLogger::Instance()->setLevel(logLevelString);
	}
	else {
	  OcfaLogger::Instance()->setLevel(logLevelString, prefix);
	}
      }
    }


    /**
     *
     *
     */
      /**
       * Helper method that returns a handle to the
       * evidencestoreentity that is linked to a metastoreentity. This
       * method doesnot need to be overridden.
       * @param inMetaEntity the metastorentity which possibly is connected to an evidencestoreentity.
       * @return  the handle to an the evidencestoreentity linked to the metastoreentity. If the 
       *   metastoreentity is not linked to an evidencestoreentity the return value is 0. The caller takes responsbility over
       * the returned value if not 0. 
       *
       */
    OcfaHandle * OcfaModule::createDataHandleFromMeta(MetaStoreEntity *inMetaEntity){

      getLogStream(LOG_DEBUG) << "entering createdatahandle" << endl;
      OcfaHandle *newHandle;
      if (inMetaEntity == 0){
	  
	  throw OcfaException("Could not create StoreEntity", this);
      } 
      
      newHandle = 0;
      if (AbstractRepository::Instance()->hasEvidenceStoreHandle(*inMetaEntity)){
	
	newHandle = 
	  new OcfaHandle(AbstractRepository::Instance()->getEvidenceStoreHandle(*inMetaEntity));
      }      
      getLogStream(LOG_DEBUG) << "exiting createDataHandleFromMeta with handle " 
			      << newHandle << endl;
      return newHandle;
    }
 
    Evidence *OcfaModule::createEvidenceFromMeta(MetaStoreEntity *inMetaStoreEntity){

	Evidence *activeEvidence;
	getLogStream(LOG_DEBUG) << "creating datahandle from Meta" << endl;
	OcfaHandle *evidenceDataHandle = 0;
	getLogStream(LOG_DEBUG) << "created" << endl;
	MemBuf *membuf =inMetaStoreEntity->contentsAsMemBuf(); 
	if (!membuf){
           throw OcfaException("contentsAsMemBuf returned 0");
	}
	getLogStream(LOG_DEBUG)<<  "creating evidence from " 
	  << membuf->getPointer()  << endl;
	getEvidenceFactory()->createEvidence(&activeEvidence, 
					     membuf, 
					     &evidenceDataHandle);
	
	if (activeEvidence == 0){

	  ocfaLog(LOG_ERR, string("createEvidenceFromMeta: cannot create evidence from ") 
		  + inMetaStoreEntity->getHandle());
	  throw OcfaException(string("cannot create evidence from ") + inMetaStoreEntity->getHandle(), this);
	}
	delete membuf;
	delete evidenceDataHandle;
	return activeEvidence;
    }


    void OcfaModule::updateMetaWithEvidence(MetaStoreEntity &inMeta, Evidence &inEvidence){

      MemBuf *allMembuf =  inEvidence.asMemBuf();
      try {
      inMeta.updateContent(reinterpret_cast<const char *>(allMembuf->getPointer()), allMembuf->getSize());
      } catch (OcfaException &e){
        getLogStream(LOG_ERR) << e.what() << endl;
      }
      //delete allMembuf;
    }


    /**
     * processes an evidence message.
     */
    void OcfaModule::processEvidenceMessage(const Message &message){

      ocfaLog(LOG_DEBUG, "Entering OcfaModule::processEvidenceMessage");
      try {
	//create an evidence from the message.
	MetaStoreEntity *metaEntity;
	ModuleInstance sender(message.getSender());
	getLogStream(LOG_INFO) << " received message with content " << 
	  message.getContent() << endl;
	AbstractRepository::Instance()
	  ->createMetaStoreEntity(&metaEntity, OcfaHandle(message.getContent()));
	if (metaEntity == 0){

	  throw OcfaException(string("no Meta could be created from ") + message.getContent());
	}
	getLogStream(LOG_DEBUG) << "setting evidence from" << metaEntity << endl;

	setEvidence(createEvidenceFromMeta(metaEntity),message.getPriority());

	// set evidence mutable.
	getEvidence()->setMutable();

	// call the pure virtual process message now that the active evidence is set.
	ocfaLog(LOG_DEBUG, "sCalling processEvidence.");
	try {
	  processEvidence();

	} catch (OcfaException &e){
          e.logWhat();
          if (getEvidence()->getEvidenceName().getType() == ocfa::misc::Scalar::SCL_STRING){
	    if (getEvidence()->getEvidenceName().fitsInASCII()){
	        logModule(LOG_ERR, string("Could not process ") + getEvidence()->getEvidenceName().asASCII() + ": " + e.what());	
	    }
          } else {
	        logModule(LOG_ERR, string("Could not process evidence (name lookup failed) ") + e.what());
	  }
	  if (OcfaConfig::Instance()->getValue("failfatal")!= string("false")) {
	      throw OcfaException("OcfaException in processEvidenceMessage",this);
	  }    

	  logEvidence(LOG_ERR, string("an error has occurred ") + e.what());
	}
	//
	// close the activeJob
	ocfaLog(LOG_DEBUG, "closing active JOb");
	getEvidence()->getActiveJob()->close();
	
	ocfaLog(LOG_DEBUG, "closed active Job");
	// update the metastoreentity with the changed evidence.
	updateMetaWithEvidence(*metaEntity, *getEvidence());


	// send the reply.
	Message *reply;
	getLogStream(LOG_DEBUG) << "creating reply with messageBox" << mpMessageBox 
				<< "and handle " << metaEntity->getHandle() << endl;
	
	mpMessageBox->createMessage(&reply, &sender, Message::ANYCAST, Message::mtEvidence, string("answer"), metaEntity->getHandle(), getDerivePriority(&sender));
	//RJM:CODEREVIEW sugestion: use the folowing instead of the abouve and replace sender with senderType string
	//getMessageBox()->createEvidenceMessage(
	//                               &reply,
	//                               metaEntity->getHandle(),
	//                               getDerivePriority(&sender)
	//                               Message::EVODENCE_ANS,
	//                               sender.getName()
	//                              );
	if (reply == 0){

	  throw OcfaException("Could not create a reply", this);
	}
	//reply->setReceiver(sender);
	ocfaLog(LOG_DEBUG, "sending reply");
	getMessageBox()->sendMessage(*reply);
	delete metaEntity;
	delete getEvidence();
	delete reply;
	setEvidence(0);
	
      } catch (OcfaException &e){
        e.logWhat();
	if (OcfaConfig::Instance()->getValue("failfatal")!= string("false")) {
		          throw OcfaException("OcfaException in processEvidenceMessage",this);
        }	    

	logModule(LOG_ERR, string("OcfaException ") + e.what());
      }
    }
    
    
    
    void OcfaModule::setEvidence(Evidence *inEvidence,int priority){
      getLogStream(LOG_DEBUG) << "Incomming evidence, prio=" << priority << endl; 
      mpActiveEvidence = inEvidence;
      mpActivePriority=priority;
      
    }

    int OcfaModule::getDerivePriority(const ocfa::misc::ModuleInstance *minst) const {
        if (mpActiveEvidence == 0) {
	    getLogStream(LOG_DEBUG) << "Outgoing evidence prio=" << MSG_EVIDENCE_LOWPRIO << endl;
            return MSG_EVIDENCE_LOWPRIO;
	} else {
	   if (minst->getModuleName() == "router") {
	       getLogStream(LOG_DEBUG) << "Outgoing evidence prio=" << mpActivePriority << endl;
               return mpActivePriority;
	   }
           if (mpActivePriority == MSG_EVIDENCE_HIGHPRIO) {
	      getLogStream(LOG_DEBUG) << "Outgoing evidence prio=" << MSG_EVIDENCE_HIGHPRIO << endl;
              return MSG_EVIDENCE_HIGHPRIO;
	   } else {
	      getLogStream(LOG_DEBUG) << "Outgoing evidence prio=" << mpActivePriority-1 << endl;
	      return mpActivePriority-1;	  
	   }
	}
    }
    
    void OcfaModule::logEvidence(syslog_level inLevel, string inMessage ){
      
      getEvidence()->getActiveJob()->addLogLine(inLevel, inMessage);
     }
    
    void OcfaModule::logModule(syslog_level inLevel, string inMessage ){
      
      OcfaLogger::Instance()->syslog(inLevel, "module.general") << inMessage << endl;
    }

    Evidence *OcfaModule::getEvidence() const {

      return mpActiveEvidence;
    }

    MessageBox *OcfaModule::getMessageBox(){

      return mpMessageBox;
    }


    /**
     * creates a new metastoreentity representing that evidence, then sends it to the router.
     *
     */
    void OcfaModule::submitEvidence(Evidence *inEvidence, const ModuleInstance *inRouter){
 
      MetaStoreEntity *metaEntity;
      Message *message;

      ocfaLog(LOG_DEBUG, "SubmitEvidence:Creating metaEntity for submit");

      if (!inEvidence->getActiveJob()->isClosed()){

	inEvidence->getActiveJob()->close();
      }

      AbstractRepository::Instance()->createMetaStoreEntity(&metaEntity, inEvidence->asMemBuf()->getPointer(), 
							    inEvidence->asMemBuf()->getSize(), 
							    *(inEvidence->getEvidenceIdentifier()), 
							    inEvidence->getRawDataHandle());
      ocfaLog(LOG_DEBUG, "Preparing message"); 
      mpMessageBox->createMessage(&message, inRouter, ocfa::message::Message::ANYCAST, 
				     ocfa::message::Message::mtEvidence, string("newevidence"), 
				     string(metaEntity->getHandle()), getDerivePriority(inRouter));
      
     //RJM:CODEREVIEW sugestion: use the folowing instead of the abouve and replace inRouter with an "router" string
     //getMessageBox()->createEvidenceMessage(
     //                               &reply,
     //                               string(metaEntity->getHandle()),
     //                               getDerivePriority(inRouter)
     //                              );
      if (message == 0){

	throw OcfaException("message not created", this);
      }
      if (inRouter == 0){

	throw OcfaException("trying to send to 0  router", this);
      }
      ocfaLog(LOG_DEBUG, "sending message to " + inRouter->getInstanceURI());
      mpMessageBox->sendMessage(*message);
      delete metaEntity;
      delete message;
    }


    EvidenceFactory *OcfaModule::getEvidenceFactory(){

      return mpEvidenceFactory;
    }


    void OcfaModule::setEvidenceFactory(EvidenceFactory *inFactory){

      mpEvidenceFactory = inFactory;
    }

    void OcfaModule::setMessageBox(MessageBox *inBox){

      mpMessageBox = inBox;
    }


    /**
     * creates messagebox and mesagefactory, and baptizes everything. 
     */
    void OcfaModule::initialize(string inName, string inNamespace){

      setMessageBox(MessageBox::createInstance(inName, inNamespace));

      // baptize stuff, so that every relevant object now knows what
      // module it is in.
      if (getMessageBox() == 0){
          throw OcfaException("mpMessageBox is 0", this);
      }
      ModuleInstance *moduleInstance = getMessageBox()->getModuleInstance();
      if (moduleInstance == 0) {
	ocfaLog(LOG_ERR, "cannot get a module instance from messagebox");
	throw OcfaException("cannot get a module instance from messageBox ", this);
      }
      OcfaConfig::Instance()->baptize(moduleInstance);
      OcfaLogger::Instance()->baptize(moduleInstance);
      EvidenceFactory::Instance()->baptize(moduleInstance);
      getLogStream(LOG_DEBUG) << "OcfaModule::initialize all stuff is baptized" << endl;
      setEvidenceFactory(EvidenceFactory::Instance());
    
      if (getMessageBox() == 0){
	
	throw OcfaException("mpMessageBox is 0", this);
      }
      
      //  delelete moduleInstance;
    }
    
  }
}
