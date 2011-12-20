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

#include "ace/Reactor.h"
#include "ReceiveSockHandler.hpp"

using namespace ocfa::misc;
using namespace ocfa::message;

ReceiveSockHandler::ReceiveSockHandler(int port): _local(port), _acceptor(){
  if (_acceptor.open(_local,1) == -1){
    throw std::string("Bind failed on port");  
  } 
}

ACE_HANDLE ReceiveSockHandler::get_handle(void) const {
  return _acceptor.get_handle();
}

int ReceiveSockHandler::handle_input(ACE_HANDLE ){
  ACE_SOCK_Stream peer;
  ACE_INET_Addr peer_addr;
  if (_acceptor.accept(peer, &peer_addr) == -1){
    return -1; 
  } else {
// FIXME: Memleak here, but for modules no biggie ..
    OcfaStreamHandler *sh = new OcfaStreamHandler(peer);
    //RJM:Codereview Does the ACE_Reactor handle deletion of the OcfaStreamHandler ?
    if (ACE_Reactor::instance()->register_handler(sh, ACE_Event_Handler::READ_MASK) == -1){
      throw std::string("Register of streamhandler failed");
    }
  }
  return 0;  
}
