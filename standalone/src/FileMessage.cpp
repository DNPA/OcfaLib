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
						
#include "FileMessage.hpp"
using namespace ocfa::message;
using namespace ocfa::misc;
using namespace std;
namespace ocfa {

  namespace message {
ostream& operator<<(ostream &o, const Message::MessageType &m){
  switch(m){
  case Message::mtSubscribe: 
    o << "mtSubscribe"; 
    break;
  case Message::mtUnsubscribe:
    o<< "mtUnsubscribe";
    break;
  case Message::mtHalt:	
    o<< "mtHalt";
    break;
  case Message::mtEOC:	
    o<<"mtEOC"; 
    break;
  case Message::mtModuleInstance:
    o<<"mtModuleInstance"; 
    break;
  case Message::mtEvidence:
    o<<"mtEvidence"; 
    break;
  case Message::mtHeartBeat:	
    o<<"mtHeartBeat"; 
    break;
  case Message::mtModuleDisconnect:
    o<<"mtModuleDisconnect"; 
    break;
  case Message::mtTaskProgress:
    o<<"mtTaskProgress"; 
    break;
  case Message::mtSystem: 
    o<<"mtSystem"; 
    break;
  }
  return o;
}
  

ostream& operator<<(ostream &o, const Message::CastType &m){

  switch(m){

  case Message::UNICAST:
    o << "unicast(0)";
    break;
  case Message::BROADCAST:
    o << "broadcast(1)";
    break;
  case Message::MULTICAST:
    o << "multicast(2)";
    break;
  case Message::ANYCAST:
    o << "anycast(3)";
    break;
  default:
    o << "nothing";

  }
  return o;
}

FileMessage::FileMessage(MessageType inType, CastType inCastType, int inPriority, 
			 const std::string inSubject, 
			 const string inContent, ocfa::misc::ModuleInstance *inSender, 
			 const ocfa::misc::ModuleInstance *inReceiver) : OcfaObject("FileMessage", "message"){

 
  mType = inType;
  mCastType = inCastType;
  mPriority = inPriority;
  mSubject = inSubject;
  mSender = new ModuleInstance(inSender);
  mReceiver = new ModuleInstance(inReceiver);
  mContent = inContent;
  getLogStream(LOG_DEBUG) << "Message created with prio " << mPriority << endl;
}

FileMessage::~FileMessage(){

  getLogStream(LOG_DEBUG) << "deleting filemessage " << endl;
  if (mSender != 0){

    delete mSender;
  }
  if (mReceiver != 0){

    delete mReceiver;
  }
}



int FileMessage::getPriority() const {

  return mPriority;
}

ModuleInstance *FileMessage::getSender() const  {
  return mSender;
}
 
ModuleInstance *FileMessage::getReceiver() const {

  return mReceiver;
}

Message::MessageType FileMessage::getType() const {

  return mType;
}
 
string FileMessage::getContent() const {

  return mContent;
}

string FileMessage::getSubject() const {

  return mSubject;
}

Message::CastType FileMessage::getCastType() const {

  return mCastType;
} 

void FileMessage::setPriority(int inPriority) {

  mPriority = inPriority;
}

void FileMessage::setSender(ModuleInstance *inSender)  {
  
  if (mSender != 0){

    delete mSender;
  }
  mSender = new ModuleInstance(inSender);
} 

void FileMessage::setReceiver(ModuleInstance *inReceiver) {

  if (mReceiver != 0){

    delete mReceiver;
  }
  mReceiver = new ModuleInstance(inReceiver);
}

void FileMessage::setType(Message::MessageType inType) {
  
  mType = inType;
} 

void FileMessage::setContent(string inContent) {

  mContent = inContent;
}

void FileMessage::setSubject(string inSubject) {

  mSubject = inSubject;
}

void FileMessage::setCastType(Message::CastType inType) {

  mCastType = inType;
} 
  }
}
