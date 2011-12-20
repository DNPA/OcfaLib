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
						
#include"../inc/ConcreteMessage.hpp"
#include"../inc/AcceptMessagingEndPoint.hpp"
#include"../inc/ReceiveSockHandler.hpp"

extern "C" {

  using namespace ocfa::message;
  AcceptMessagingEndPoint *constructor(ocfa::misc::ModuleInstance *modinstance){
    AcceptMessagingEndPoint *s = new AcceptMessagingEndPoint(modinstance);
    return s;
  }

}

using namespace ocfa::misc;
using namespace std;

namespace ocfa {

  namespace message {

    AcceptMessagingEndPoint::AcceptMessagingEndPoint(ModuleInstance *modinstance): MessagingEndPoint(modinstance), _castfacade(),_result(-1), _remote_addr_recv(23111), _modules(){

      // depending on mbox type connect or accept
      if (!accept()){
	throw OcfaException("AcceptMessagingEndPoint initialization failed.");
      }
    }

    AcceptMessagingEndPoint::~AcceptMessagingEndPoint(){ 
    }
      
    void AcceptMessagingEndPoint::registerInstance(string instance, ACE_SOCK_Stream *outstream, ACE_SOCK_Stream *instream){
      _castfacade.registerInstance(instance, outstream);

      if (_modInstInStreams.find(instream) == _modInstInStreams.end()){
 	_modInstInStreams[instream] = instance;
      } else {
	ocfaLog(LOG_ERR, "Trying to associate instream with moduleinstance which allready had been set !");
      }
    }


    void AcceptMessagingEndPoint::sendMessage(Message &inMessage){
      sendUnicast(&inMessage); 
    }


    bool AcceptMessagingEndPoint::sendBroadcast(Message *msg){
      vector <InstanceInfo *> recepients = _castfacade.broadcast(msg->getSender()->getInstanceURI()); //aparently all but self (RJM)
      if (recepients.size() > 0){
	sendMessage(recepients, msg);
      }
 
      return true;
    }
    
    bool AcceptMessagingEndPoint::sendUnicast(Message *msg){
      vector <InstanceInfo *> recepients = _castfacade.unicast(msg->getReceiver()->getInstanceURI());
      if (recepients.size() > 0)
	sendMessage(recepients, msg);
 
      return true;
    }

    // used by relay, non-relay should pass a multicast message to toRelay()
    bool AcceptMessagingEndPoint::sendMulticast(Message *msg){
      vector <InstanceInfo *> recepients = _castfacade.multicast(msg->getSubject());
      if (recepients.size() > 0)
	sendMessage(recepients, msg);
 
      return true;
    }
    
    // used by relays
    bool AcceptMessagingEndPoint::sendMessage(vector <InstanceInfo *> & recipients, Message *msg){
      // we need to change the CastType to unicast

      msg->setCastType(Message::UNICAST);
      for (vector <InstanceInfo *>::iterator itr = recipients.begin(); itr != recipients.end(); itr++){
	ModuleInstance recipient((*itr)->getInstName());
	msg->setReceiver(&recipient);
        
	getLogStream(LOG_DEBUG) << "sending message to "  
				<< recipient.getInstanceURI() << " with type " 
				<< static_cast<int>(msg->getType()) << "content:" << msg->getContent()
				<< endl;  

	MessageWrapper *mw = wrapMessage(msg); 
	string serialized = serializeMessageWrapper(mw); 
	(*itr)->getSockStream()->send(serialized.c_str(), strlen(serialized.c_str()) + 1);
	delete mw;
      } 

      return true;
    }
    
    // initialize the server messagebox by listening for connections on 23111 
    bool AcceptMessagingEndPoint::accept(){

      int basePort=23111; 
      ReceiveSockHandler *receivesockhandler = 0;     
      try {
        receivesockhandler = new ReceiveSockHandler(basePort); 
      } 
      catch (...){
        getLogStream(LOG_CRIT) << "Bind failed. Is there another instance of anycast running ?" << endl;
	return false;
      }
      if (ACE_Reactor::instance()->register_handler(receivesockhandler, ACE_Event_Handler::ACCEPT_MASK) == -1){
	ocfaLog(LOG_ERR,"Register of receivehandler failed");
	return false;
      } else {
        getLogStream(LOG_DEBUG) << "ReceiveSockHandler install succeeded." << endl;
	// start the reactor thread
	activate();
      }
   
      return true;

    }
    

    void AcceptMessagingEndPoint::sendTask(Message *msg, unsigned int id){

      vector <InstanceInfo *> recepients = _castfacade.unicast(msg->getReceiver()->getInstanceURI());
      if (recepients.size() > 0){
	MessageWrapper *msgw = new MessageWrapper(MessageWrapper::mwTask, msg);
	msgw->setAnyCastID(id);
	msgw->setAnyCastRelay(_moduleinstance->getInstanceURI());
	string serialized = serializeMessageWrapper(msgw);
	(*recepients.begin())->getSockStream()->send(serialized.c_str(), strlen(serialized.c_str()) + 1);
	delete msgw;
      }

    }


    // method intended to be used by Clients of the MessageBox
    void  AcceptMessagingEndPoint::messageDone(const Message *msg){
      getLogStream(LOG_ERR) << "messageDone not implemented" << endl;
    }

    MessageWrapper *AcceptMessagingEndPoint::preprocessMessage(MessageWrapper *mw){
      Message *inmsg = 0; 
      switch (mw->getType()){
      case MessageWrapper::mwTask:{
	getLogStream(LOG_ERR) << "Task received in acceptor" << endl;
        return mw;
      }	
      case MessageWrapper::mwTaskProgress:{
        getLogStream(LOG_DEBUG) << "Completed task received" << endl;
	ostringstream ofs;
        ofs << mw->getAnyCastID();
	mw->getPayLoad()->setSubject(ofs.str());
	mw->getPayLoad()->setType(Message::mtTaskProgress);
        return mw;
      }
      case MessageWrapper::mwUser:{
	      
	inmsg = mw->getPayLoad();

	if (inmsg == 0){
		
	  // Maybe just return here? Or do we consider the digiwash corrupt??
	  getLogStream(LOG_CRIT) << "Received messageWrapper with empty payload" << endl;
	  getLogStream(LOG_CRIT) << "anycastId is " << mw->getAnyCastID() << endl;
	  getLogStream(LOG_CRIT) << "type is " << static_cast<int>(mw->getType()) << endl;
	  throw OcfaException("Received a messagewrapper with empty payload!");
	} else {
	  switch (inmsg->getType()){
	  case Message::mtSubscribe:{
	    ModuleInstance *minst = inmsg->getSender();
	    _castfacade.subscribeChannel(minst->getInstanceURI(), inmsg->getSubject());
	    ocfaLog(LOG_DEBUG, string("msgSubscribe received from ") + minst->getInstanceURI() + string(" for channeltopic ") + inmsg->getSubject());
	    return 0;
	  }
	  case Message::mtUnsubscribe:
	    ocfaLog(LOG_DEBUG, "msgUnsubscribe received");
	    return 0;
	  case Message::mtHalt:
	  case Message::mtEOC:
	  case Message::mtModuleInstance:
	  case Message::mtEvidence:
	  case Message::mtHeartBeat:
	  case Message::mtModuleDisconnect:
	  case Message::mtTaskProgress:
	  case Message::mtSystem:
	  case Message::mtRecover:
	      ;
											               ;

	  }
	}
	      
	// FIXME: prio check to baseclass ? (see also connectmessagingendpoint)
	switch (inmsg->getCastType()){
	case Message::UNICAST:
	  sendUnicast(inmsg);
	  break;
	case Message::BROADCAST:
	  sendBroadcast(inmsg);
	  break;
	case Message::MULTICAST:
	  sendMulticast(inmsg);
	  break;
	case Message::ANYCAST:
	  /* do nothing */
	  break;
	default:
	  ocfaLog(LOG_ERR, "Requested to send unknown casttype");
	  //error
	}

	getLogStream(LOG_DEBUG) << "returning message with type " << static_cast<int>(inmsg->getType())<< endl;
	return mw;
      }
	break;
      case MessageWrapper::mwInternalConnect:{
	inmsg = mw->getPayLoad();
        ACE_SOCK_Stream *instream = mw->getSockStream();
	ACE_INET_Addr peeraddr; 
	instream->get_remote_addr(peeraddr);
	char addrbuf[64];
	peeraddr.get_host_addr(addrbuf, 64);
	
	ACE_INET_Addr connecttoaddr(atoi(inmsg->getSubject().c_str()), addrbuf);
	ACE_SOCK_Stream *outstream = new ACE_SOCK_Stream();
	ACE_SOCK_Connector connector;
	if (connector.connect(*outstream, connecttoaddr) == -1){
	  getLogStream(LOG_CRIT) << "Failed to connect back to peer '" << inmsg->getSubject() << "' on '" << addrbuf << "'"   << endl;
	} else {
	  getLogStream(LOG_DEBUG) << "Connect back succeeded. Registering sockstream" << endl;
	  string instance = inmsg->getSender()->getInstanceURI();
	  registerInstance(instance, outstream, instream);
	  Message *tmpmsg = new ConcreteMessage(_moduleinstance, inmsg->getSender(), Message::UNICAST, Message::mtModuleInstance, instance, "", 0);
        
	  getLogStream(LOG_DEBUG) << "Sending mtModuleInstance to connected module  " << instance << endl; 

	  MessageWrapper *tmpmw = wrapMessage(tmpmsg); 
	  string serialized = serializeMessageWrapper(tmpmw); 
	  outstream->send(serialized.c_str(), strlen(serialized.c_str()) + 1);
	  delete tmpmw;
	  delete tmpmsg;
	  
	}
	return mw;
      }
	break;
      case MessageWrapper::mwInternalDisconnect:{
	      
	ocfaLog(LOG_DEBUG, "Internal Disconnect received");
	ACE_SOCK_Stream *sock = mw->getSockStream();
        std::map<ACE_SOCK_Stream *, std::string>::iterator itr = _modInstInStreams.find(sock);
	if (itr != _modInstInStreams.end()){
	  string ModUri = itr->second;
	  ACE_SOCK_Stream *outstream = _castfacade.unregisterInstance(ModUri);
	  if (outstream){
	    // found modinstance to remove
	    outstream->close();
	    delete outstream;
	    ModuleInstance *modinst = new ModuleInstance(ModUri);
	    inmsg = new ConcreteMessage(modinst, _moduleinstance, Message::BROADCAST, Message::mtModuleDisconnect, "","",0 );
	    mw->setPayLoad(inmsg);
	    return mw;
	  } else {
            getLogStream(LOG_ERR) << "Unregister of module " << ModUri << " failed." << endl;
	    return 0;
	  }
	} else {
          getLogStream(LOG_ERR) << "Unknown module disconnected" << endl;
          return 0; //RJM: not sure about this, but better than no return at all.
	}
      }
      }
      return 0; //this should not hapen;
    }

  }
}
