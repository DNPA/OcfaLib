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
						
#ifndef INCLUDED_CONCRETE_MESSAGE_HPP
#define INCLUDED_CONCRETE_MESSAGE_HPP
#include "message/Message.hpp"
#include "misc.hpp"
#include <sstream>

using namespace std;

namespace ocfa {

  namespace message {


    // This is the first concrete message in the message-hierarchy, however, you'll
    // probably want to subclass this.
    class ConcreteMessage: public Message {
    public:
 
      ConcreteMessage(misc::ModuleInstance *sender, const misc::ModuleInstance *receiver, CastType casttype, MessageType mtype, std::string subject, std::string content, int priority);

      virtual misc::ModuleInstance *getSender() const { 
	return _sender;
      }

      virtual misc::ModuleInstance *getReceiver() const {
	return _receiver;
      }

      virtual std::string getReceiverType() const {		//RJM:CODEREVIEW Added convenience method to avoid complex interface with module instances
        return _receiver->getModuleName();		//RJM:CODEREVIEW
      }							//RJM:CODEREVIEW
      
      virtual std::string getSubject() const {
	return _subject;
      }

      virtual std::string getContent() const {
	return _content;
      }

      virtual MessageType getType() const {
	return _mtype;
      }

      virtual CastType getCastType() const {
	return _casttype;
      }

      int getPriority() const {
	return _priority;
      }

      virtual void setSender(misc::ModuleInstance *sender);
      virtual void setReceiver(misc::ModuleInstance *receiver);	
      
      virtual void setType(MessageType mtype){
        _mtype = mtype;
      }
  
 
      virtual void setSubject(std::string subject){
	_subject = subject;
      }
 
      virtual void setCastType(CastType casttype){
	_casttype = casttype;			
      }				
      void printID(string arg);
      virtual ~ConcreteMessage();

    protected:
      ConcreteMessage(): Message(), _priority(0), _sender(0), _receiver(0),  _subject(""), _content(""), _mtype(Message::mtSubscribe), _casttype(Message::UNICAST){};
      ConcreteMessage(const ConcreteMessage &): Message(), _priority(0), _sender(0), _receiver(0), _subject(""), _content(""), _mtype(Message::mtSubscribe), _casttype(Message::UNICAST){
	throw misc::OcfaException("copy of concretemessage not allowed");
      };

      ConcreteMessage &operator=(const ConcreteMessage &){
	throw misc::OcfaException("Assignment of ConcreteMessage not allowed");
      }


      int _priority;
      misc::ModuleInstance *_sender;
      misc::ModuleInstance *_receiver;
      std::string _subject;
      std::string _content;
      MessageType _mtype;
      CastType _casttype;
      
      static int msgcount;
      int _debugid;
     
    };

  }
}

#endif 



