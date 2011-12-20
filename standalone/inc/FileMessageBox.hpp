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
						
#include "message/MessageBox.hpp"
#include "store/Filename.hpp"
#include "OcfaObject.hpp"
#include <iostream>
namespace ocfa {
  namespace message {

    class FileMessageBox: public MessageBox, public ocfa::OcfaObject {
    public:       
      
      FileMessageBox(std::string inName, std::string inNameSpace);
      virtual Message *getNextMessage(int inPriority =  ocfa::event::Event::MIN_PRIORITY, int inTimeOut  = 0) ;
      virtual void sendMessage(ocfa::message::Message &inMessage) ;
      virtual void createMessage(Message **outMessage, const ModuleInstance *receiver, 
				    Message::CastType casttype, Message::MessageType inType, 
				    std::string inAnswer, std::string inContent, int priority ) ;
      
     virtual void messageDone(const Message *msg) ;
      //JBS added getModuleInstance to that it can be used for baptizing
      virtual ocfa::misc::ModuleInstance *getModuleInstance() ;
      virtual ~FileMessageBox();
      virtual int getEventSourceType();
      virtual ocfa::event::Event *getNextEvent(int inPrio);
      virtual ocfa::event::Event *getNextTimeOutEvent(int inPriority, int inTimeout);
      
    protected:

      void createTestItem();
      virtual void ensureAbsolutePath(std::string &ioPath);
      std::string prepareMetaHandle(std::string inEvidenceId, ocfa::store::Filename inMetaDataFile, 
				    ocfa::store::Filename inDataFile);
    private:
      ocfa::misc::ModuleInstance *mInstance;
      std::ifstream *mTestDataStream; 
      std::string mDataDir;
      int mCounter;
      bool mShouldStop;
      ItemIdentifier *mItemIdentifier;
    };
  }
}
