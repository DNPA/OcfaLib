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
						
#include"../inc/MessagingEndPoint.hpp"
#include"../inc/ConcreteMessage.hpp"
#include "misc/IPAddress.hpp"
#include "misc/PolicyLoader.hpp"
#include<sstream>

using namespace ocfa::misc;


namespace ocfa {

  namespace message {

	  
    // static and externals
    ACE_Message_Queue<ACE_MT_SYNCH> *queue;


    MessagingEndPoint::MessagingEndPoint(ModuleInstance *modinstance): OcfaObject("MessagingEndPoint","message"),_moduleinstance(0), _result(-1){
        _moduleinstance = new ModuleInstance(modinstance);
	queue = new ACE_Message_Queue<ACE_MT_SYNCH>(16*1024,14*1024);
      }

    MessagingEndPoint::~MessagingEndPoint(){
      getLogStream(LOG_DEBUG) << "Destructor ConcreteMessagebox: Ending reactor event loop" << endl; 
      ACE_Reactor::instance()->end_reactor_event_loop(); // scary, since the reactor is running in the other thread
      getLogStream(LOG_DEBUG) << "Waiting for thread to finish" << endl;
      _rt.wait(); // hmmm, this probably is the wrong place... Dunno yet // RJM:CODEREVIEW seems like the right place to me.
      //RJM:CODEREVIEW We should probably be deleting _moduleinstance here
      //RJM:CODEREVIEW We should probably be deleting all _out_streams seconds here
      //RJM:CODEREVIEW We should probably be deleting _lastinstream here.
      getLogStream(LOG_DEBUG) << "Thread finished. End destructor" << endl;
    }

    bool MessagingEndPoint::activate(){
      return (_rt.activate() == 0);
    }

    MessageWrapper * MessagingEndPoint::wrapMessage(Message *m){
      return new MessageWrapper(MessageWrapper::mwUser, m);
    }


    // inTimeOutMs == 0: blocking call 
    // inTimeOutMs > 0 : Wait for inTimeOutMs milliseconds
    // inTimeOutMs < 0 : Poll
	   
    MessageWrapper *MessagingEndPoint::getNextMessage(int inPriority, int inTimeOutMs ){
      ACE_Message_Block *block;
      ocfaLog(LOG_DEBUG,"MessagingEndPoint::getNextMsg() called");
      if ((queue->is_empty()) && (inTimeOutMs < 0)){ // if the queue is empty and we don't want to block then return 0
        ocfaLog(LOG_DEBUG, "Queue empty, returning 0");
	return 0;
      }
      // JBS added peeking to make sure that we only retrieve messages with
      // the required priority
      // Maybe checking for errors here. Not sure how to handle it.
      ocfaLog(LOG_DEBUG, "peeking");
      ACE_Time_Value *deadline = 0;
      if (inTimeOutMs > 0){
	ocfaLog(LOG_DEBUG, "TimeOut set");
	deadline =  new ACE_Time_Value(inTimeOutMs / 1000, (inTimeOutMs % 1000) * 1000);
	(*deadline) += ACE_OS::gettimeofday();
      } else {
        getLogStream(LOG_DEBUG) << "Blocking call of getNextMessage" << endl;
      }

      int nmbrmsg = queue->peek_dequeue_head(block, deadline);
      delete deadline;

      // check whether there is something in the queue.
      if (nmbrmsg < 1){
	return 0;
      }

      ocfaLog(LOG_DEBUG, "found something in the queue");

      //Ace priorities are different than ours. In OcfaStreamHandler this is computer by 128-message priority.
      // so we compute the original priority back from the msg_priority.
      int prio = 128 - block->msg_priority();

      // check if the priority is important enough.
      if (prio < inPriority){

	// if it is important we get it out. It is possible that a new 
	// more important message is now in the head of the queue. 
	if (queue->dequeue_head(block) != -1){
	    
	  ocfaLog(LOG_DEBUG, "important stuff let's get it out");

	  MessageWrapper *m = 0;
	  
	  // sanity check. this should not happen. 
	  if (block == 0){
	    ocfaLog(LOG_ERR, "getNextMessage: There was something in the queue that seems to have disappeared");
	    //RJM:CODEREVIEW if this should not hapen shouldn't we thrown an exception here?
	    return 0;		
	  }
	  // get messagewrapper from block.
	  m = reinterpret_cast<MessageWrapper *>(block->base());
	  block->release();
	    
	  return preprocessMessage(m);

	} else {
	  ocfaLog(LOG_ERR, "We could peek, but not retrieve. Very Weird");
	}
      } // end if (prio < inPriority)
	
      
      return 0;
      
    }
  

  

    //RJM:CODEREVIEW may functionaly move to constructor of CustomMessageBox 
    MessagingEndPoint *MessagingEndPoint::createInstance(string name, string mnamespace){
      MessagingEndPoint *_instance = 0;
      OcfaObject o(name, mnamespace);

      // if you ever want to use a different loadable module specified from ocfa.conf,
      // then this is the place to read it from the config file and store it in classname.
      // It used to be like that, but this is removed since the config file got to cluttered
      string classname;
      if (OcfaConfig::Instance()->getValue("isRelay", &o) == "y"){
         classname = "AcceptMessagingEndPoint";
      } else {
         classname = "ConnectMessagingEndPoint";
      }
      string ipaddress = OcfaConfig::Instance()->getValue("routerIP", &o);
      if (ipaddress == ""){
	ipaddress = IPAddress::Value();
      }
      OcfaLogger::Instance()->syslog(LOG_INFO, "message.MessagingEndPoint")
	<<  "Using " + ipaddress + " as router address" << endl; // we need a static log function
      ModuleInstance *_moduleinstance = new ModuleInstance(ipaddress, name, mnamespace, "notset");


      typedef SinglePointerConstructor<MessagingEndPoint, ModuleInstance> MessagingEndPointConstructor;
      PolicyLoader<MessagingEndPointConstructor> loader(classname, "constructor");

      MessagingEndPointConstructor *constructor = loader.constructor();
      _instance = (*constructor)(_moduleinstance);
     
      return _instance;
    }
     

  }

}




