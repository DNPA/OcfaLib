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
						
#ifndef INCLUDED_MSG_HPP
#define INCLUDED_MSG_HPP
#define MSG_LOWPRIO 6
#define MSG_EVIDENCE_LOWPRIO 5
#define MSG_EVIDENCE_HIGHPRIO 1
#define MSG_HIGHPRIO 0
#include<string>
#include<iostream>
#include "../misc.hpp"

namespace ocfa {
  namespace message {
    
    class Message {
    public:
      static  const int MIN_PRIORITY;
      enum CastType {
	UNICAST,
	BROADCAST,
	MULTICAST,
	ANYCAST
      };
      enum EvidenceMessageType { 	//RJM:CODEREVIEW
        EVIDENCE_NEW,			//RJM:CODEREVIEW
	EVIDENCE_REQ,			//RJM:CODEREVIEW
	EVIDENCE_ANS			//RJM:CODEREVIEW
      };				//RJM:CODEREVIEW
      enum MessageType {
	mtSubscribe,
	mtUnsubscribe,
	mtHalt,
	mtEOC,
	mtModuleInstance,
	mtEvidence,
	mtHeartBeat,
	mtModuleDisconnect,
        mtTaskProgress,
	mtSystem, // system specific messages.
	mtRecover
      };


      virtual ~Message(){};
      virtual int getPriority() const = 0;
      virtual misc::ModuleInstance *getSender() const  = 0; 
      virtual misc::ModuleInstance *getReceiver() const = 0;
      virtual std::string getReceiverType() const = 0;		//RJM:CODEREVIEW Convenience for if the module instance is not realy needed
      virtual MessageType getType() const = 0; 
      virtual std::string getContent() const = 0;
      virtual std::string getSubject() const = 0;
      virtual CastType getCastType() const = 0;
      virtual void setSender(misc::ModuleInstance *) = 0;
      virtual void setReceiver(misc::ModuleInstance *) = 0;		
      virtual void setCastType(CastType) = 0; 
      virtual void setSubject(std::string) = 0;
      virtual void setType(MessageType) = 0;
      
    };

    // definition currently in ConcreteMessage.cpp
    //std::ostream& operator<<(std::ostream &o, const Message::MessageType &m);
    //string serializeMessage(Message * const  m);
    //string serializeMessage(Message * m);
    //Message *deserializeMessage(string serialized);

    
  }
}



#endif
