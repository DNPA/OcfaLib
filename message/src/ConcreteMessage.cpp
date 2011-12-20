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
						
#include"ConcreteMessage.hpp"
#include"message/Serialize.hpp"
#include <misc/OcfaLogger.hpp>

using namespace ocfa::misc;
namespace ocfa {
  namespace message {
  
  const int Message::MIN_PRIORITY = 100;
  int ConcreteMessage::msgcount = 0; 

  ostream& operator<<(ostream &o, const Message::MessageType &m){
      switch(m){
      case Message::mtSubscribe: 
	o << "mtSubscribe"; 
	break;
      case Message::mtUnsubscribe:
	o<< "mtUnsubscribe";
	break;
      case Message::mtHalt:	
	o<< "mtHalt";
	break;
      case Message::mtEOC:	
	o<<"mtEOC"; 
	break;
      case Message::mtModuleInstance:
	o<<"mtModuleInstance"; 
	break;
      case Message::mtEvidence:
	o<<"mtEvidence"; 
	break;
      case Message::mtHeartBeat:	
	o<<"mtHeartBeat"; 
	break;
      case Message::mtModuleDisconnect:
	o<<"mtModuleDisconnect"; 
	break;
      case Message::mtTaskProgress:
	o<<"mtTaskProgress"; 
	break;
      case Message::mtSystem: 
	o<<"mtSystem"; 
	break;
      case Message::mtRecover:			//RJM:CODEREVIEW Added recover type that was defined earlier.
	o<<"mtRecover";				//RJM:CODEREVIEW
	break;					//RJM:CODEREVIEW
      }
      return o;
    }
    

     ConcreteMessage::ConcreteMessage(ModuleInstance *sender, const ModuleInstance *receiver, CastType casttype, MessageType mtype, string subject, string content, int priority): _priority(priority), _sender(0), _receiver(0), _subject(subject),  _content(content),_mtype(mtype), _casttype(casttype) {
       OcfaLogger::Instance()->syslog(LOG_DEBUG, "message.ConcreteMessage") << "entering ConcreteMessage::ConcreteMessage" << endl;
       if (sender){
	 OcfaLogger::Instance()->syslog(LOG_DEBUG, "message.ConcreteMessage") <<  "setting sender to " << sender->getInstanceURI() << endl;
        _sender = new ModuleInstance(sender); // for getSender(), see below
       }
       if (receiver){
	 OcfaLogger::Instance()->syslog(LOG_DEBUG, "message.ConcreteMessage") <<  "Setting receiver to  "  << receiver->getInstanceURI() << endl;
	_receiver = new ModuleInstance(receiver);
       }
       _debugid = ++msgcount;
       printID("ConcreteMessage");
      }

      ConcreteMessage::~ConcreteMessage(){
	printID("~ConcreteMessage");
	delete _sender;
	delete _receiver;
      }


    void ConcreteMessage::printID(string arg){
       OcfaLogger::Instance()->syslog(LOG_DEBUG, arg) <<  "DEBUGID " << _debugid << endl;  
    }
      
    void ConcreteMessage::setSender(ModuleInstance *sender){
       delete _sender;
       _sender = new ModuleInstance(sender);
    }
 
    void ConcreteMessage::setReceiver(ModuleInstance *receiver){
	 delete _receiver;								
        _receiver = new ModuleInstance(receiver); 		
    }


  }
}






