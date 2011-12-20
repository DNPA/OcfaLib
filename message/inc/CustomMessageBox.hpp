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
						
#ifndef __OCFACUSTOMMESSAGEBOX_
#define __OCFACUSTOMMESSAGEBOX_
#include"misc.hpp"
#include<map>
#include<vector>
// #include"ConcreteMessageBox.hpp" RJM:CODEREVIEW renamed to MessagingEndPoint
#include "MessagingEndPoint.hpp" // RJM:CODEREVIEW
#include"CastStrategy.hpp"
#include"misc/ModuleInstance.hpp"
#include"message/AnycastMessageBox.hpp"
//#include"message/MessageBox.hpp"
#include"message/Message.hpp"

namespace ocfa {
  namespace message {
    class CustomMessageBox: public AnycastMessageBox, public OcfaObject {
    public:


      CustomMessageBox(std::string name, std::string mnamespace);
      virtual ~CustomMessageBox();
      Message *getNextMessage(int inPriority = ocfa::message::Message::MIN_PRIORITY, int inTimeOut = 0);
     
      virtual void createMessage(Message **outMessage, const misc::ModuleInstance *receiver, Message::CastType casttype, Message::MessageType inType, std::string inAnswer, std::string inContent, int priority = 0);

      void sendMessage(ocfa::message::Message &inMessage);
      virtual misc::ModuleInstance* getModuleInstance(){
	return _moduleinstance;
      }

      virtual void sendTask(Message *msg, unsigned int id);
      virtual void messageDone(const Message *msg);

      //RJM:CODEREVIEW the folowing are convenience methods to simplify API usage and avoid non intuitive 
      //module instance usage.
      virtual void createEvidenceMessage(Message **outMessage,std::string handle,					//RJM:CODEREVIEW
		int prio=MSG_EVIDENCE_LOWPRIO,										//RJM:CODEREVIEW
      		Message::EvidenceMessageType metype=Message::EVIDENCE_REQ,                     				//RJM:CODEREVIEW
      		std::string receivertype="router"         								//RJM:CODEREVIEW
	);                     												//RJM:CODEREVIEW
      virtual void createHaltMessage(Message **outMessage);                                                       	//RJM:CODEREVIEW
      virtual void createEOCMessage(Message **outMessage);                                                        	//RJM:CODEREVIEW
      virtual void createRecoverMessage(Message **outMessage);                                                    	//RJM:CODEREVIEW
      virtual void createSetLogLevelMessage(Message **outMessage,std::string prefix,std::string loglevel,         	//RJM:CODEREVIEW
      		std::string receivertype);                                      					//RJM:CODEREVIEW

//    protected:				//RJM:CODEREVIEW
   private:					//RJM:CODEREVIEW no derived classes so it doesn't need to be protected, private will do.
      bool initialize(std::string name, std::string mnamespace);
      bool _initializing;
      misc::ModuleInstance *_moduleinstance;
      MessagingEndPoint *_box; 
    };
  }
}
#endif
 
