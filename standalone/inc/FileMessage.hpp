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
						
#include "message/Message.hpp"
#include "OcfaObject.hpp"
namespace ocfa {

  namespace message {

    class FileMessage: public Message, public ocfa::OcfaObject {
    public:
      
      FileMessage(MessageType inType, CastType inCastType, int inPriority, const std::string inSubject, 
		  const std::string inContent, ocfa::misc::ModuleInstance *inSender, const ocfa::misc::ModuleInstance *inReceiver);
      virtual int getPriority() const ;
      virtual ~FileMessage();
      virtual ModuleInstance *getSender() const  ; 
      virtual ModuleInstance *getReceiver() const ;
      virtual MessageType getType() const ; 
      virtual string getContent() const ;
      virtual string getSubject() const ;
      virtual CastType getCastType() const ; 

      virtual void setPriority(int) ;
      virtual void setSender(ModuleInstance *)  ; 
      virtual void setReceiver(ModuleInstance *) ;
      virtual void setType(MessageType) ; 
      virtual void setContent(string) ;
      virtual void setSubject(string) ;
      virtual void setCastType(CastType) ; 
    private:
      int mPriority;
      ocfa::misc::ModuleInstance *mSender;
      ocfa::misc::ModuleInstance *mReceiver;
      Message::MessageType mType;
      std::string mContent;
      std::string mSubject;
      CastType mCastType;       
    };
     
    ostream& operator<<(ostream &o, const Message::CastType &m);

   
  }
}
