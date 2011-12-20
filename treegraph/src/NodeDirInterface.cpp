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
#include "misc.hpp"
using namespace ocfa::misc;
namespace ocfa {
  namespace treegraph {
     bool NodeDirInterface::hasSubEntities() {
        return false;
     } 

     void NodeDirInterface::resetSubEntityIterator(){
        if (this->hasSubEntities()) {
           throw ocfa::misc::OcfaException("resetSubEntityIterator not implemented by subclass of NodeDirInterface.");
        }
        throw ocfa::misc::OcfaException("resetSubEntityIterator should never get called by OcfaLib on a NodeDirInterface that has no sub entities.");
     }
     bool NodeDirInterface::nextSubEntity(){
       if (this->hasSubEntities()) {
           throw ocfa::misc::OcfaException("nextSubEntity not implemented by subclass of NodeDirInterface.");
        }
        throw ocfa::misc::OcfaException("nextSubEntity should never get called by OcfaLib on a NodeDirInterface that has no sub entities.");
     }
     void NodeDirInterface::getCurrentSubEntity(TreeGraphNode ** subent){
        if (this->hasSubEntities()) {
           throw ocfa::misc::OcfaException("getCurrentSubEntity not implemented by subclass of NodeDirInterface.");
        }
        throw ocfa::misc::OcfaException("getCurrentSubEntity should never get called by OcfaLib on a NodeDirInterface that has no sub entities.");
     }
     std::string NodeDirInterface::getCurrentSubEntityRelation(){
        if (this->hasSubEntities()) {
           throw ocfa::misc::OcfaException("getCurrentSubEntityRelation not implemented by subclass of NodeDirInterface.");
        }
        throw ocfa::misc::OcfaException("getCurrentSubEntityRelation should never get called by OcfaLib on a NodeDirInterface that has no sub entities.");
        return "undefined";
     }



  }

}

