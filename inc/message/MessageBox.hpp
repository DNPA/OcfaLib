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
						
#ifndef __OCFAMESSAGEBOX_
#define __OCFAMESSAGEBOX_
#include<string>
#include "../misc.hpp"
#include "Message.hpp"

namespace ocfa {
	namespace message {
	  class MessageBox {
	  public:
	    virtual ~MessageBox(){};	  
	    static MessageBox *createInstance(std::string name, std::string mnamespace);
	    virtual Message *getNextMessage(int inPriority =  ocfa::message::Message::MIN_PRIORITY, int inTimeOut = 0) = 0;
	    virtual void sendMessage(ocfa::message::Message &inMessage) = 0;
	    virtual void messageDone(const Message *msg) = 0;
	    //JBS added getModuleInstance to that it can be used for baptizing
	    virtual misc::ModuleInstance *getModuleInstance() = 0;
	    virtual void createEvidenceMessage(Message **outMessage,std::string handle,					//RJM:CODEREVIEW
						int prio = MSG_EVIDENCE_LOWPRIO,					//RJM:CODEREVIEW
						Message::EvidenceMessageType metype=Message::EVIDENCE_NEW,              //RJM:CODEREVIEW
						std::string receivertype="router"					//RJM:CODEREVIEW
					)=0; 		 								//RJM:CODEREVIEW
            virtual void createHaltMessage(Message **outMessage)=0;							//RJM:CODEREVIEW
	    virtual void createEOCMessage(Message **outMessage)=0;							//RJM:CODEREVIEW
	    virtual void createRecoverMessage(Message **outMessage)=0;                                                    //RJM:CODEREVIEW
	    virtual void createSetLogLevelMessage(Message **outMessage,std::string prefix,std::string loglevel,		//RJM:CODEREVIEW
	    					std::string receivertype)=0;						//RJM:CODEREVIEW
	    virtual void createMessage(Message **outMessage, const misc::ModuleInstance *receiver, Message::CastType casttype, Message::MessageType inType, std::string inAnswer, std::string inContent, int priority = 0) = 0; //RJM:CODEREVIEW Depricated, use abouve methods instead !
	  protected:
	    static MessageBox* _instance;
	  };
      

	}
}
#endif
