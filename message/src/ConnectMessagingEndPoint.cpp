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
#include"../inc/ConnectMessagingEndPoint.hpp"
#include"../inc/OcfaStreamHandler.hpp"

extern "C" {
  using namespace ocfa::message;
  ConnectMessagingEndPoint *constructor(ocfa::misc::ModuleInstance *modinstance){
    ConnectMessagingEndPoint *c = new ConnectMessagingEndPoint(modinstance);
    return c;
  }

}

using namespace ocfa::misc;

namespace ocfa {

  namespace message {
    //May instead of hardcoding 23111 here, create a static method MessagingEndpoint::getBasePort(std:string casename)
    //that returns 23111. That way we could in the near future easily move to a case->portset based portmapper solution
    //that alows multiple cases to be run on the same hardware.
    ConnectMessagingEndPoint::ConnectMessagingEndPoint(ModuleInstance *modinstance): MessagingEndPoint(modinstance), _result(-1),_remote_addr_send(23111,modinstance->getHostname().c_str()), _sock_outstream(){
      updateTypeName("ConnectMessagingEndPoint");
      if (!connect()){
	throw MessageConnectException("Making connection to messaging server (anycastrelay) failed",this); 
      }     
    }


    ConnectMessagingEndPoint::~ConnectMessagingEndPoint(){
      ocfaLog(LOG_DEBUG, "Destructor ConnectMessagingEndPoint called");	    
      Message *msg = new ConcreteMessage(_moduleinstance, _moduleinstance, Message::BROADCAST, Message::mtModuleDisconnect, "", "", 0); //If valgring brought you here, please ignore.
      MessageWrapper *mw = new MessageWrapper(MessageWrapper::mwUser, msg);  
      sndMessage(mw);
      _sock_outstream.close();
      //RJM:CODEREVIEW shouldn't we be deleting the message msg and the message wrapper. If not, the MessageWrapper constructor
      //and sndMessage interfaces are wrong (hould use pointer to pointer)
    }


    void ConnectMessagingEndPoint::sndMessage(MessageWrapper *mw){
      getLogStream(LOG_DEBUG) << "Serializing messagewrapper " << endl; 
      string serialized = serializeMessageWrapper(mw); 
      getLogStream(LOG_DEBUG) << "Sending message on _outstream " << endl;
      // Since this is a client we have only one outgoing stream 
      _sock_outstream.send(serialized.c_str(), strlen(serialized.c_str()) + 1);
    }

    void ConnectMessagingEndPoint::sendMessage(Message &inMessage){
      getLogStream(LOG_DEBUG) << "Creating messagewrapper" << endl;
      MessageWrapper *omsg = new MessageWrapper(MessageWrapper::mwUser, &inMessage);
      sndMessage(omsg); 
      delete omsg;
    }


    // method intended to be used by Clients of the MessageBox
    void ConnectMessagingEndPoint::messageDone(const Message *msg){
      map<const Message *, MessageWrapper *>::iterator itr = _taskmap.find(msg);
      if (itr != _taskmap.end() ){
	itr->second->setType(MessageWrapper::mwTaskProgress);
	sndMessage(itr->second);
	delete msg;
        delete itr->second;
        _taskmap.erase(itr);
      }
    }

    void ConnectMessagingEndPoint::sendTask(Message *msg, unsigned int id){
      getLogStream(LOG_ERR) << "sendTask not implemented" << endl;
    }



    MessageWrapper *ConnectMessagingEndPoint::preprocessMessage(MessageWrapper *mw){
      Message *inmsg = 0; 
      switch (mw->getType()){
      case MessageWrapper::mwTask:{
	/* fall through */
	getLogStream(LOG_DEBUG) << "I've been assigned to a task" << endl;
	ostringstream ofs;
	ofs << mw->getAnyCastID();
	getLogStream(LOG_DEBUG) << "TASKID:" << ofs.str() << endl;
	// Store the MessageWrapper so that we can send an ack when we are done
	_taskmap[mw->getPayLoad()] = mw;
	mw = wrapMessage(mw->getPayLoad());
	return mw;
      }
      case MessageWrapper::mwTaskProgress:
      case MessageWrapper::mwUser:{
	      
	inmsg = mw->getPayLoad();
	if (inmsg == 0){
	  // Maybe just return here? Or do we consider the digiwash corrupt??
	  getLogStream(LOG_CRIT) << "Received messageWrapper with empty payload" << endl;
	  getLogStream(LOG_CRIT) << "anycastId is " << mw->getAnyCastID() << endl;
	  getLogStream(LOG_CRIT) << "type is " << static_cast<int>(mw->getType()) << endl;
	  throw OcfaException("Received a messagewrapper with empty payload!");
	}
	// FIXME : reintroduce priority check ?      
	getLogStream(LOG_DEBUG) << "returning message with type " << static_cast<int>(inmsg->getType())<< endl;
	return mw;
      }
	break;
      case MessageWrapper::mwInternalConnect:{
	getLogStream(LOG_ERR) << "mwInternalConnect in ConnectMessagingEndPoint" << endl;
	return 0;
      }
	break;
      case MessageWrapper::mwInternalDisconnect:{
	getLogStream(LOG_CRIT) << "Lost connection" << endl;      

	// throw away the envelope but keep the payload. The caller MUST delete msg1 !
	inmsg = new ConcreteMessage(_moduleinstance, _moduleinstance, Message::BROADCAST, Message::mtModuleDisconnect, "","",0 );
	//RJM:CODEREVIEW does this transfer responsability? if it does the interface is wrong. If it does not than
	//we have a tricky issue as normally inmsg is a pointer without responsablity, so we may need to delete it 
	//and set it to NULL here.
	mw->setPayLoad(inmsg);
	return mw;
      }
      }
      return 0; //This should not hapen;
    }

    // this method should only be called by client-like applications
    bool ConnectMessagingEndPoint::connect(){
      ACE_SOCK_Connector _connector_send, _connector_receive ;

      // try creating a listen in range 23200-30000
      int baseport=23200;
      ReceiveSockHandler *receivesockhandler = 0;

      while (baseport < 30000){
	try {
	  receivesockhandler = new ReceiveSockHandler(baseport);
	  break;
	} catch (std::string &e){
	  getLogStream(LOG_INFO) << "SockHandler construct failed for port " << baseport << endl;
	  baseport++;
	}
      }
      if (receivesockhandler == 0){
	throw OcfaException("Create listen failed");
      } else {
	getLogStream(LOG_DEBUG) << "Listening on " << baseport << endl;
      }

      if (ACE_Reactor::instance()->register_handler(receivesockhandler, ACE_Event_Handler::ACCEPT_MASK) == -1){
	ocfaLog(LOG_ERR,"Register of receivehandler failed");
	return false;
      }
     
      // now start the thread which waits for incoming connections
      activate();

      // connect our outgoing stream
      if (_connector_send.connect(_sock_outstream,_remote_addr_send) == -1){
	ocfaLog(LOG_ERR, "connect failed"); 
	return false;  
      } else {
	ocfaLog(LOG_DEBUG, "Connector open succeeded");	
	// connected ! 
	// create message holding info, serialize and send
	ACE_INET_Addr localendpoint;
	_sock_outstream.get_local_addr(localendpoint);
	ostringstream instname; 
	instname << "Inst" << localendpoint.get_port_number();

	// delete the old modinst and replace with a more accurate one
	string mname = _moduleinstance->getModuleName();
	string mnamespace = _moduleinstance->getNameSpace(); 
	delete(_moduleinstance);
	ocfaLog(LOG_DEBUG,"IP is: " + string(localendpoint.get_host_addr()));
	_moduleinstance = new ModuleInstance(localendpoint.get_host_addr(), mname, mnamespace, instname.str());
	_moduleinstance->setPort(localendpoint.get_port_number());

	ModuleInstance *mcopy = new ModuleInstance(*_moduleinstance); 
	mcopy->setPort(localendpoint.get_port_number());
	ostringstream strbaseport;
	strbaseport << baseport;
	Message *sockinfo = new ConcreteMessage(_moduleinstance, mcopy, Message::BROADCAST, Message::mtModuleInstance, strbaseport.str(), "", 0);
	//RJM:CODEREVIEW shouldn't we be deleting mcopy
	MessageWrapper *msgwrapper = new MessageWrapper(MessageWrapper::mwInternalConnect, sockinfo);  
	getLogStream(LOG_DEBUG) << "MessageType: " <<  static_cast<int>(sockinfo->getType()) 
				<< " moduleinstance: " << sockinfo->getReceiver()->getInstanceURI() << endl;
        sndMessage(msgwrapper);	
	ocfaLog(LOG_DEBUG, "Sent message. Deleting");  
	delete msgwrapper;
	delete sockinfo;
	return true;
      }
    }
  
  }

}
