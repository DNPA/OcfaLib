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
						
#include"MessagingEndPoint.hpp"
#include"OcfaStreamHandler.hpp"
#include<iostream>
using namespace ocfa::misc;

namespace ocfa {

  namespace message {

    // Event handler to handle stream events
    OcfaStreamHandler::OcfaStreamHandler(ACE_SOCK_Stream peer):_module_instance_received(false), _peer(peer), _istr(""), _nmbr_msg_received(0),_buf(0), _buflen(1024),deserializeMessageWrapper(serializeMessageWrapper)
    {
      _buf = new char[_buflen + 1];
    }
    
    OcfaStreamHandler::~OcfaStreamHandler(){
      delete []_buf;
      _peer.close();
      OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Destructor called" << endl; 
    }

    ACE_HANDLE OcfaStreamHandler::get_handle() const {
      return _peer.get_handle();
    }

    void OcfaStreamHandler::queueInternalDisconnect()
    {
        MessageWrapper *m = new MessageWrapper(MessageWrapper::mwInternalDisconnect, 0);
        m->setSockStream(&_peer);
        //RJM:CODEREVIEW Who if anyone deletes this object?
        ACE_Message_Block *block = new ACE_Message_Block(reinterpret_cast<char *>(m), sizeof(MessageWrapper *));
        OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Enqueueing Internal Disconnect Message !" << endl;
        block->msg_priority(128);
        ocfa::message::queue->enqueue_prio(block);
    } 


    int OcfaStreamHandler::handle_input(ACE_HANDLE fd){
      if (fd == ACE_INVALID_HANDLE){ 
	return -1;
      }
 
      int numbytes = 0;
      // we need to read up to a '\0' since we expect to receive only text 
      // if we encounter '\0' 
      //  we push basepointer onto stream, 
      //  process stream and clear stream
      //  advance basepointer until all bytes are eaten,

      if ((numbytes = _peer.recv(_buf,_buflen)) > 0){
	_buf[numbytes] = 0;
	char *currstr = _buf;

	for (int i = 0; i < numbytes; i++){
	  if (_buf[i] == 0){ 

	    _istr.append(currstr) ;
	    try {
	      MessageWrapper *msg1 = deserializeMessageWrapper(_istr);
	      if (msg1 == 0){
                 OcfaLogger::Instance()->syslog(LOG_CRIT, "OcfaStreamHandler") << "Deserialize failed" << endl;
		 return -1;
	      }
	      OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Archive: " <<  _istr << "|end" << endl;
	      OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "OcfaStreamHandler: received message with type " << static_cast<int>(msg1->getType()) << endl; 
	      msg1->setSockStream(&_peer);
     	      // Block should be deleted by receiving thread
	      ACE_Message_Block *block = new ACE_Message_Block(reinterpret_cast<char *>(msg1), sizeof(MessageWrapper *));
	      int prio = 0;
              if (msg1->getPayLoad() != 0){  
		prio = msg1->getPayLoad()->getPriority();
	      } else {
		OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaStreamHAndler") << "Empty payload received" << endl;
	      }
	      // Note: In ACE_Message_Queue 0 is the lowest priority, hence we substract OcfaPriority from 128
	      if ((prio < 0) ||  (prio > 128) ){
		OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaStreamHandler") << "Invalid prio " << prio << endl;
		prio = 0; 
	      } else {
		prio = 128 - prio;
	      }
	      block->msg_priority(prio);
	      OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Enqueueing with prio " << prio << endl;
	      int nmbrmsgs = ocfa::message::queue->enqueue_prio(block); // RJM:CODEREVIEW does this transfer responsability?
              if (nmbrmsgs > 0){
		OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Enqueued message. NmbrOnQueue:" << nmbrmsgs << endl;
	      } else {
                OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaStreamHAndler") << "Failed to Enqueue message !!" << endl;
	      }
	      
	      _nmbr_msg_received++;
	      _istr = ""; 
            } catch (ocfa::misc::InvalidXMLException &e) {
              //FIXME: we aparently reveived an invalid message from this FD. We should:
              // * Log the name of the offensive module.
              // * Disconnect the offensive module.
              // * Log the xml content somewhere for analysis.
              OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaStreamHAndler") << "Received invalid message XML: " << _istr << endl;
              OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaStreamHAndler") << e.what() << std::endl; 
              //_peer.close();
              queueInternalDisconnect();
              _istr = "";
              
	    } catch (exception &e) {
	      OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaStreamHandler ")  << "Stream error:" << e.what() << endl;
	      _istr = "";
	    }
	    currstr = _buf + i + 1; // advance pointer to next substring
	  }
	}
	// copy remainder to istream
	_istr.append(currstr);
      } else {
	OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "No bytes at all read in handle_input(). Client disconnected." << endl;
	OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Nmbr of msgs received: " <<  _nmbr_msg_received << endl;
	OcfaLogger::Instance()->syslog(LOG_DEBUG, "OcfaStreamHandler ")  << "Posting disconnect message on internal queue" << endl;
        queueInternalDisconnect();  
	return -1;
      }
 
      return 0;
    }

  }

}
