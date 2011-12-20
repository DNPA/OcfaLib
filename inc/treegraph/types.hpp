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
						
#ifndef FSTYPES_H
#define FSTYPES_H

#include "TreeGraphNode.hpp"
namespace ocfa {
  namespace treegraph {
/**
  * class FsConnectedNode
  * This class is used to represent directories,files etc that are part of the main
  * directory structure on a filesystem.
  */

    class FsConnectedNode:virtual public TreeGraphNode {

    };
/**
 * class DeletedNode
 * This class is used to represent deleted entities on a filesystem 
 */
    class DeletedNode:virtual public TreeGraphNode {

    };
/** 
 * class FsSystemNode
 * This class is used to represent system nodes on a filesystem not part of the
 * main directory tree
 */
    class FsSystemNode:virtual public TreeGraphNode {

    };
/** class FsUnalocatedNode
 * This class is used to represent sections of unalocated data in a filesystem 
 */  
    class UnalocatedNode:virtual public TreeGraphNode {

    };
}}
#endif				// FSTYPES_H
