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

#include <ace/Reactor.h>
#include "OcfaReactorTask.hpp"

namespace ocfa {
  namespace message {
    int OcfaReactorTask::svc (void){
      // note; we only use this thread to run the reactor, installation of handlers should
      // be done in the mainthread.
      // This way, we can use the same OcfaReactorTask for both clients and server (I hope ... :-/).
      ACE_Reactor::instance()->owner(ACE_OS::thr_self());
      ACE_Reactor::instance()->run_reactor_event_loop();
      return 0;
    }
  }
}
    
