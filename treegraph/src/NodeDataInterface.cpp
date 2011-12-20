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
						
#define __USE_FILE_OFFSET64
#include "treegraph.hpp"
#include "misc/AbstractWriteFacet.hpp"
#include <boost/lexical_cast.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace treegraph {
    void NodeDataInterface::streamToOutput(AbstractWriteFacet &write_to_storeentity) {
            static char readBuffer[4096];
            size_t bytesRead;
            openStream(); 
            while((bytesRead = streamRead(readBuffer, 4096)) > 0){
                 write_to_storeentity(readBuffer, bytesRead);
            }
            closeStream();
    }
    void NodeDataInterface::openStream() {
       OcfaObject *asoobject=dynamic_cast< OcfaObject * > (this);
       if (this->hasContent()) {
          if (this->getSize() > 0) {
             throw ocfa::misc::OcfaException(std::string("The depricated openStream method not implemented. Override NodeDataInterface::streamToOutput instead. (size=") + boost::lexical_cast< std::string > (this->getSize()) + ")." ,asoobject);
          } else {
             throw ocfa::misc::OcfaException("The depricated openStream method not implemented. Override NodeDataInterface::streamToOutput instead. (size=0!)",asoobject);
          }
       } else {
         throw ocfa::misc::OcfaException("The depricated openStream method not implemented. there is no content so this method should not ever be called by OcfaLib.",asoobject);
       }
    }
    void NodeDataInterface::closeStream() {
       OcfaObject *asoobject=dynamic_cast< OcfaObject  *> (this);
       throw ocfa::misc::OcfaException("The depricated closeStream method not implemented. Override NodeDataInterface::streamToOutput instead.",asoobject);
    }
    size_t NodeDataInterface::streamRead(char *buf, size_t count){
       OcfaObject *asoobject=dynamic_cast< OcfaObject *> (this);
       throw ocfa::misc::OcfaException("The depricated streamRead method not implemented. Override NodeDataInterface::streamToOutput instead.",asoobject);
    }
    bool NodeDataInterface::hasContent() {
       return false;
    }
    off_t NodeDataInterface::getSize() {
       OcfaObject *asoobject=dynamic_cast< OcfaObject *> (this);
       if (this->hasContent()) {
           throw ocfa::misc::OcfaException("getSize not implemented by NodeDataInterface subclass that claims to have content.",asoobject);
       } else {
           throw ocfa::misc::OcfaException("getSize not implemented by NodeDataInterface subclass, there is no content so this method should not ever be called by OcfaLib.",asoobject); 
       } 
    }
    std::string NodeDataInterface::getHardLinkablePath(std::string targetbasepathi,ocfa::misc::DigestPair **) {
       return "";
    }
    std::string NodeDataInterface::getSoftLinkablePath(ocfa::misc::DigestPair **){
       return "";
    }    
  }

}

