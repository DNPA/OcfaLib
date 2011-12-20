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
						
#ifndef INCLUDED_MESSAGEWRAPPER_HPP
#define INCLUDED_MESSAGEWRAPPER_HPP 
#include"ConcreteMessage.hpp"
#include"ace/SOCK_Stream.h"
namespace ocfa {
  namespace message {

    class MessageWrapper {
    public:
      enum mwType {
	mwTaskProgress,
	mwTask,
	mwInternalDisconnect,
	mwInternalConnect,
	mwUser
      };

      MessageWrapper(mwType mwtype, ocfa::message::Message *payload):_payload(payload),_anycastid(0),_mwtype(mwtype), _instream(0), _anycastrelay(""){
    
      };
      void setAnyCastID(unsigned long id){
	_anycastid = id;
      };
      unsigned long getAnyCastID(){
	return _anycastid;
      };
      ocfa::message::Message *getPayLoad(){
	return _payload;
      };
      void setPayLoad(ocfa::message::Message *payload){
	_payload = payload;
      }
      // ModuleAddress recepient;
      ACE_SOCK_Stream *getSockStream(){
	return _instream;
      }
      void setSockStream(ACE_SOCK_Stream *instream){
	_instream = instream;
      }
      mwType getType() const {
	return _mwtype;
      }
      void setType(mwType mwtype){
	_mwtype = mwtype;
      }
      std::string getAnyCastRelay(){
	return _anycastrelay;
      }
      void setAnyCastRelay(std::string instanceuri){
	_anycastrelay = instanceuri;
      }
    protected:
      MessageWrapper():_payload(0),_anycastid(0), _mwtype(mwUser), _instream(0), _anycastrelay(""){
      } 
      MessageWrapper(const MessageWrapper&): _payload(0),_anycastid(0), _mwtype(mwUser), _instream(0), _anycastrelay(""){
	throw misc::OcfaException("Not allowed to copy MessageWrapper");
      }
      MessageWrapper &operator=(const MessageWrapper &){
	throw misc::OcfaException("Assignment of MessageWrapper not allowed");
      }

    private:
      ocfa::message::Message *_payload;
      unsigned long _anycastid; 
      mwType _mwtype;
      ACE_SOCK_Stream *_instream;
      std::string _anycastrelay;
    };
  }

}
#endif
