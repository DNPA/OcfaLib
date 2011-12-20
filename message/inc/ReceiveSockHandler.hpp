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

#ifndef INCLUDED_RECEIVESOCKHANDLER_H
#define INCLUDED_RECEIVESOCKHANDLER_H

#include"ace/Event_Handler.h"
#include"ace/SOCK_Acceptor.h"
#include"ace/INET_Addr.h"						
#include "OcfaStreamHandler.hpp"
#include "misc/OcfaException.hpp"

namespace ocfa {

  namespace message {

    // handler to accept connections, create a stream when connected and 
    // register a handler for stream events with the reactor.

    // Note that this is the ReceiveSockHandler
    // We never send data on this socket. Therefore we let the reactor handle the sockstream.

    class ReceiveSockHandler: public ACE_Event_Handler {
    public:
      // port is the port we bind to
      ReceiveSockHandler(int port);
      virtual ACE_HANDLE get_handle(void) const;
      virtual int handle_input(ACE_HANDLE );

      //RJM:CODEREVIEW we may want to add a handle_close method, I'm not sure here though

    private:
      ACE_INET_Addr _local;
      ACE_SOCK_Acceptor _acceptor;
    };

  }

}

#endif
