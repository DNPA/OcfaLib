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
						
#include<sstream>
#include"../inc/CustomMessageBox.hpp"
#include"../inc/ConcreteMessage.hpp"
#include"../inc/MessagingEndPoint.hpp" //  RJM:CODEREVIEW
#include"misc.hpp"
#include"OcfaObject.hpp"
#include"ace/Signal.h"


using namespace ocfa::message;
using namespace ocfa::misc;
using namespace ocfa;
using namespace std;

    
CustomMessageBox::CustomMessageBox(string name, string mnamespace): OcfaObject("CustomMsgBox","message"), _initializing(true), _moduleinstance(0), _box(0){
  if (initialize(name, mnamespace)){
    ocfaLog(LOG_DEBUG, "Initialization ok");
  } else {
    ocfaLog(LOG_ERR, "Initialization failed");
    //RJM we throw an exception here, there is no other way for module to know things went bad over here.
    throw OcfaException("Problem initializing CustomMessageBox",this);
  }
  _initializing = false;
}

bool CustomMessageBox::initialize(string name, string mnamespace){
  // set up all kind of stuff, notably ignore SIGPIPE !
  ACE_Sig_Action no_sigpipe(static_cast<ACE_SignalHandler>(SIG_IGN), SIGPIPE);
  _initializing = true; //RJM:CODEREVIEW already set to true in constructor, not called anywere else, could be removed
  // RJM:CODEREVIEW urgent issue: The ConcreteMessageBox should in its constructor have the createInstance
  // functionality that curently resides in MessagingEndPoint. That way the cross dependency problem
  // would be resolved that keeps the messaging lib loadable modules from being linkable under cygwin.
  // ConcreteMessageBox *thebox = ConcreteMessageBox::createInstance(name, mnamespace); RJM:CODEREVIEW ConcreteMessageBox 
  //                                                                                               renamed to MessagingEndPoint
  _box = MessagingEndPoint::createInstance(name, mnamespace);
  if (_box){
    _moduleinstance = new ModuleInstance(_box->getModuleInstance());
    ocfaLog(LOG_INFO, string("My modulename: ") + _moduleinstance->getModuleName());
    ocfaLog(LOG_INFO, string("My moduleinstance") + _moduleinstance->getInstanceURI());
    return true;
  } else {
    ocfaLog(LOG_ERR, "Initialization failed");
    return false;
  }
}

    
CustomMessageBox::~CustomMessageBox(){
  ocfaLog(LOG_DEBUG, "Destructor CustomMessageBox Called"); 
  
  ocfaLog(LOG_DEBUG, "Deleting MessagingEndPoint");						
  delete _box;
  
  delete _moduleinstance;										//RJM:CODEREVIEW
  ocfaLog(LOG_DEBUG, "Destructor CustomMessageBox end.");
}

// the message returned by this function must be passed to messageDone later 
Message *CustomMessageBox::getNextMessage(int inPriority, int inTimeOut){
  getLogStream(LOG_DEBUG) << "CustomMessageBox:getNextMessage prio:" << inPriority
			  << " timeout: " << inTimeOut << endl;

  MessageWrapper *inmsgwrapper = 0;
    
  inmsgwrapper = _box->getNextMessage(inPriority, inTimeOut);
    
  if (inmsgwrapper == 0) return 0;

  Message *inmsg = inmsgwrapper->getPayLoad();  
  ConcreteMessage *cm = dynamic_cast<ConcreteMessage *>(inmsg);
  cm->printID("Incoming:");
  delete inmsgwrapper;
  inmsgwrapper = 0;

  ModuleInstance *recipient = inmsg->getReceiver(); 
  if (recipient){
  getLogStream(LOG_DEBUG) << " Received message: " << inmsg->getSubject()
			  << ", Sender: " << inmsg->getSender()->getInstanceURI()
			  << ", Receiver: " <<  inmsg->getReceiver()->getInstanceURI()
			  << ", Type: " << static_cast<int>(inmsg->getType()) << ", Content: "
			  << inmsg->getContent() << endl;
  } else {
    getLogStream(LOG_DEBUG) << "Received message empty modinstance" << endl;
  }
 	
  return inmsg;
}


void CustomMessageBox::createMessage(Message **outMessage, const ModuleInstance *receiver, Message::CastType casttype, Message::MessageType inType, std::string inAnswer, std::string inContent, int priority){
  *outMessage = new ConcreteMessage(_moduleinstance, receiver, casttype, inType, inAnswer, inContent, priority);
  ConcreteMessage *cm = dynamic_cast<ConcreteMessage *>(*outMessage);
  cm->printID("Outgoing:");
}
//RJM:CODEREVIEW the folowing methods are new convenience method to make the usage of the API more transparant and thus
//more maintainable.
void CustomMessageBox::createEvidenceMessage(Message **outMessage,std::string handle,				//RJM:CODEREVIEW
					     int prio,									//RJM:CODEREVIEW
					     Message::EvidenceMessageType metype,  		                        //RJM:CODEREVIEW
					     std::string receivertype							//RJM:CODEREVIEW
					     ){          	              						//RJM:CODEREVIEW
  std::string subject;												      //RJM:CODEREVIEW
  switch (metype) {												      //RJM:CODEREVIEW
  case Message::EVIDENCE_NEW: subject="newevidence";									      //RJM:CODEREVIEW
    break;											      //RJM:CODEREVIEW
  case Message::EVIDENCE_REQ: subject="request";									      //RJM:CODEREVIEW
    break;											      //RJM:CODEREVIEW
  case Message::EVIDENCE_ANS: subject="awnser";									      //RJM:CODEREVIEW
  }														      //RJM:CODEREVIEW
  ModuleInstance *minst=new ModuleInstance("127.0.0.1",receivertype,"wildcard","wildcard");			      //RJM:CODEREVIEW
  createMessage(outMessage,minst,Message::ANYCAST,Message::mtEvidence,subject,handle,prio);					      //RJM:CODEREVIEW
  delete minst;												      //RJM:CODEREVIEW
  return;													      //RJM:CODEREVIEW
}														      //RJM:CODEREVIEW

void CustomMessageBox::createHaltMessage(Message **outMessage){                                                       //RJM:CODEREVIEW
  createMessage(outMessage,0,Message::BROADCAST,Message::mtHalt,"halt","halt",0);						      //RJM:CODEREVIEW
  return;													      //RJM:CODEREVIEW
}														      //RJM:CODEREVIEW


void CustomMessageBox::createEOCMessage(Message **outMessage){                                                //RJM:CODEREVIEW
  ModuleInstance *minst=new ModuleInstance("127.0.0.1","router","wildcard","wildcard");				      //RJM:CODEREVIEW
  createMessage(outMessage,minst,Message::ANYCAST,Message::mtEOC,"eoc","eoc",MSG_LOWPRIO);					      //RJM:CODEREVIEW
  delete minst;												      //RJM:CODEREVIEW
  return;													      //RJM:CODEREVIEW
}														      //RJM:CODEREVIEW

void CustomMessageBox::createRecoverMessage(Message **outMessage){                                                    //RJM:CODEREVIEW
  ModuleInstance *minst=new ModuleInstance("127.0.0.1","anycast","wildcard","wildcard");			      //RJM:CODEREVIEW
  createMessage(outMessage,minst,Message::ANYCAST,Message::mtRecover,"recover","recover",MSG_LOWPRIO);				      //RJM:CODEREVIEW
  delete minst;												      //RJM:CODEREVIEW
  return;													      //RJM:CODEREVIEW
}														      //RJM:CODEREVIEW

void CustomMessageBox::createSetLogLevelMessage(Message **outMessage,std::string prefix,std::string loglevel,           	      	     //RJM:CODEREVIEW	
						std::string receivertype){                                                           //RJM:CODEREVIEW
  string content = prefix + " " + loglevel;									     //RJM:CODEREVIEW
  ModuleInstance *minst=new ModuleInstance("127.0.0.1",receivertype,"wildcard","wildcard");			     //RJM:CODEREVIEW
  createMessage(outMessage,minst,Message::ANYCAST,Message::mtSystem,"SetLogLevel",content,0);					     //RJM:CODEREVIEW
  delete minst;												     //RJM:CODEREVIEW
  return;													     //RJM:CODEREVIEW
}														     //RJM:CODEREVIEW

void CustomMessageBox::sendMessage(Message &inMessage){
  _box->sendMessage(inMessage);
}

// Method intended to only be used by anycast relays
// The message will have it's id set. If a message with id > 0 is received by an messagebox,
// the id and message will be stored for later reference when the messageDone() is called.
// An ACK will then be sent to sender (typically an anycast relay)
void CustomMessageBox::sendTask(Message *msg, unsigned int id){
  _box->sendTask(msg, id);
}

// method intended to be used by Clients of the MessageBox
void CustomMessageBox::messageDone(const Message *msg){
  _box->messageDone(msg);
}

  
