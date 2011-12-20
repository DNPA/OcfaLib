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
						
#ifndef DEFINED_OCFASTREAMHANDLER_HPP
#define DEFINED_OCFASTREAMHANDLER_HPP
#include<string>
#include"ace/Event_Handler.h"
#include"ace/SOCK_Stream.h"
#include "XMLWrapperConverter.hpp"
using namespace std;

namespace ocfa {

  namespace message {

    // Event handler to handle stream events
    class OcfaStreamHandler: public ACE_Event_Handler {
    public:
      OcfaStreamHandler(ACE_SOCK_Stream peer);
      virtual ~OcfaStreamHandler();
      virtual ACE_HANDLE get_handle() const;
      virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE);
      //RJM:CODEREVIEW : We may want to also implement handle_close
    protected:
      void queueInternalDisconnect();
    private:
      OcfaStreamHandler(const OcfaStreamHandler &): ACE_Event_Handler(), _module_instance_received(false), _peer(), _istr(""), _nmbr_msg_received(0),_buf(0), _buflen(1024)
           ,deserializeMessageWrapper(serializeMessageWrapper)
      {
	throw string("Not allowed to copy streamhandlers");
      }
      OcfaStreamHandler &operator=(const OcfaStreamHandler &){
	throw string("Assignment of OcfaStreamHandler not allowed");
      }
      bool _module_instance_received;
      ACE_SOCK_Stream _peer;
      string _istr;
      unsigned int _nmbr_msg_received;
      char *_buf;
      unsigned int _buflen;
      XMLWrapperConverter &deserializeMessageWrapper;
    };

  }

}

#endif
