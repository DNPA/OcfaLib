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
						
#ifndef INCLUDED_MESSAGEBOX_H
#define INCLUDED_MESSAGEBOX_H

#include<vector>
#include<map>
#include"OcfaObject.hpp"
#include"message/Message.hpp"
#include"MessageWrapper.hpp"
#include"misc/ModuleInstance.hpp"
//#include"ace/OS.h"
#include"ace/SOCK_Stream.h"
#include"ace/INET_Addr.h"
#include"ace/SOCK_Acceptor.h"
#include"ace/SOCK_Connector.h"
#include"ace/Reactor.h"
#include"ace/Event_Handler.h"
#include"ace/Message_Queue.h"
#include<time.h>
#include "OcfaReactorTask.hpp"
#include "CastStrategy.hpp"


namespace ocfa {

  namespace message {

    extern ACE_Message_Queue<ACE_MT_SYNCH> *queue;



    class MessagingEndPoint: public OcfaObject {
    public: 

      static MessagingEndPoint *createInstance(std::string name, std::string mnamespace);
 
      bool activate();

      virtual ~MessagingEndPoint();

      virtual void sendTask(Message *msg, unsigned int id) = 0;
      virtual void messageDone(const Message *msg)= 0;
      virtual void sendMessage(Message &inMessage)= 0;

      virtual MessageWrapper *getNextMessage(int inPriority = ocfa::message::Message::MIN_PRIORITY, int inTimeOut = 0);
      unsigned int getQueueSize(){ return queue->message_count();};
      void removeInstanceSockOutstream(ACE_SOCK_Stream *s);
      misc::ModuleInstance *getModuleInstance(){
	return _moduleinstance;
      }
    protected:

      MessagingEndPoint(misc::ModuleInstance *modinstance);

      virtual MessageWrapper *preprocessMessage(MessageWrapper *mw) = 0;
      MessageWrapper *wrapMessage(Message *m);
       
      misc::ModuleInstance *_moduleinstance; 

      OcfaReactorTask _rt; 
      
    private:
      int _result;

    };

    

  }

}
#endif


