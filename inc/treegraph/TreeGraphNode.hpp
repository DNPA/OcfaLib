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
						
#ifndef TREEGRAPHNODE_HPP
#define TREEGRAPHNODE_HPP

#include "NodeDataInterface.hpp"
#include "NodeDirInterface.hpp"
#include "NodeMetaInterface.hpp"
namespace ocfa {
  namespace treegraph {
/**
  * class TreeGraphNode
  * TreeGraphNode is the base class for filesystems and any data or directory entry that
  * can be identified as part of a filesystem.
  * 
  */
    class TreeGraphNode: public NodeDataInterface,public NodeDirInterface,public NodeMetaInterface {
    public:
     /**
      * Prepares the system entity represented by the TreeGraphNode object for being deleted
      * on destuction of the TreeGraphNode object. Note: this operation changes the file
      * permissions and possibly ownerhips on files regardless of their prior settings to
      * allow for reading, writing and execution by the current user.
      */
      virtual void unlinkOnDestruct() = 0;

      virtual ~TreeGraphNode() {};

    };
}}
#endif				// TREEGRAPHNODE_HPP
