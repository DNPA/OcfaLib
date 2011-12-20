//RJM:CODEREVIEW This file is not reviewed. Author has marked this as being under revision.
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
						
#include"../inc/CastStrategy.hpp"

using namespace ocfa::misc;
using namespace std;


  // sent messages, reply time, socket etc
  
InstanceInfo::InstanceInfo(string instname, ACE_SOCK_Stream *s):_s(s), _instname(instname){

}
  
InstanceInfo::InstanceInfo(const InstanceInfo &i): _s(i.getSockStream()), _instname(i.getInstName()) {

}

InstanceInfo &InstanceInfo::operator=(const InstanceInfo &i){
  _s = i.getSockStream();
  _instname = i.getInstName();
  return *this;
}

ACE_SOCK_Stream *InstanceInfo::getSockStream() const {
  return _s;
}

string InstanceInfo::getInstName() const {
  return _instname;
}



void CastFacade::registerInstance(string instance, ACE_SOCK_Stream *s){
   
  if (registeredmodules.find(instance) == registeredmodules.end()){ 
    registeredmodules[instance] = new InstanceInfo(instance, s);
  }
    
}

bool CastFacade::subscribeChannel(string instance, string topic){
  if (registeredmodules.find(instance) == registeredmodules.end()){
    // should throw an exception here
    return false;
  }
  if (channels.find(topic) != channels.end()){
    // topic exists
    channels[topic]->push_back(instance);
      
  } else {
    // topic did not exist 
    channels[topic] = new vector<string>;
    channels[topic]->push_back(instance);
  }
  return true;
}


ACE_SOCK_Stream *CastFacade::unregisterInstance(string instance){
   // remove instance from registeredmodules
   ACE_SOCK_Stream *stream = 0;
   
   map<string, InstanceInfo *>::iterator itr = registeredmodules.find(instance);
   if (itr != registeredmodules.end()){
     stream = itr->second->getSockStream();
     delete itr->second;
     registeredmodules.erase(itr);
   }
   // remove from subscribed channels, if any
   for (map<string, vector<string> * >::iterator topic = channels.begin(); topic != channels.end(); topic++){
     for (vector<string>::iterator subscriber = topic->second->begin(); subscriber != topic->second->end(); subscriber++ ){
       if (*subscriber == instance){
         topic->second->erase(subscriber);
       }
     }
   }
  return stream;
}  


// send message to one of topic

vector<InstanceInfo *> CastFacade::anycast(string topic){
  vector<InstanceInfo *> v; 
  if (channels.find(topic) != channels.end()){     
    v.push_back(registeredmodules.find( (*channels[topic])[0] )->second) ;
  } else {
    ocfaLog(LOG_ERR, "Err: topic not found");
  }
  return v;
}

// send message to intended

vector<InstanceInfo *> CastFacade::unicast(string recipient){
  vector<InstanceInfo *> v; 
  if (registeredmodules.find(recipient) != registeredmodules.end()){
    v.push_back((*registeredmodules.find(recipient)).second);
  } else {
    ocfaLog(LOG_ERR, string("Err: ") + recipient + string(" not registered."));
  }
  return v;
}


// send message to channel subscribed

vector<InstanceInfo *> CastFacade::multicast(string topic){
  vector<InstanceInfo *> v;
  if (channels.find(topic) != channels.end()){
    vector<string> *recipient = channels[topic];
    for (vector<string>::iterator itr = recipient->begin(); itr != recipient->end(); itr++){
      v.push_back(registeredmodules.find( *itr )->second) ;
	 
    }
  } else {
    ocfaLog(LOG_ERR, "Err: channel not found");
  }
  return v;
}
  


// send message to everyone

vector<InstanceInfo *> CastFacade::broadcast(string sender){
  vector<InstanceInfo *> v;
  for (map<string, InstanceInfo *>::iterator itr = registeredmodules.begin(); itr != registeredmodules.end(); itr++){
    if (itr->second->getInstName() != sender)  
      v.push_back( itr->second);
  }
  return v;
}


CastFacade::CastFacade():OcfaObject("Anycast","CastFacade"){
  
}

CastFacade::~CastFacade(){
  ocfaLog(LOG_DEBUG, "Destructor castfacade.");
}

bool CastFacade::setMethod(string , string ){ 
  return false;
}


CastFacade::CastFacade(const CastFacade &): OcfaObject("Anycast","CastFacade"){
  throw OcfaException("Copy of CastFacade not allowed");
}

CastFacade &CastFacade::operator=(const CastFacade &){
  throw OcfaException("Assignment of CastFacade not allowed");
    
}



