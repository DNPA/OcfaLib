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
						
#ifndef INCLUDED_SERVERMESSAGEBOX_H
#define INCLUDED_SERVERMESSAGEBOX_H
#include "MessagingEndPoint.hpp"

namespace ocfa {
  namespace message {
    class AcceptMessagingEndPoint: public MessagingEndPoint {
    public: 
      AcceptMessagingEndPoint(misc::ModuleInstance *modinstance);
      virtual ~AcceptMessagingEndPoint();
    
      bool sendMessage(std::vector <InstanceInfo *> & recipients, Message *msg);
      virtual void sendMessage(Message &inMessage);
      bool sendBroadcast(Message *msg);
      bool sendUnicast(Message *msg);
      bool sendMulticast(Message *msg);
      virtual void sendTask(Message *msg, unsigned int id);
      virtual void messageDone(const Message *msg);						
    protected:
      virtual MessageWrapper *preprocessMessage(MessageWrapper *mw);
      void registerInstance(std::string instance, ACE_SOCK_Stream *outstream, ACE_SOCK_Stream *instream);
      bool sndMessage(MessageWrapper *omsg, std::string moduleclass);
      bool accept(); // wait for clients
    private:      
      CastFacade _castfacade;    
      std::map<ACE_SOCK_Stream *, std::string>_modInstInStreams; 
      int _result; //RJM:CODEREVIEW If we change this in the baseclass from private to protected than we don't need it here.
      
      ACE_INET_Addr _remote_addr_recv; //RJM:CODEREVIEW If we change this in the baseclass from private to protected than we don't need it here.
      
      // The modules we have a connection with. When we receive socket info we will add a moduleinstance.
      std::vector<misc::ModuleInstance *> _modules;

    };
  }
}

#endif
