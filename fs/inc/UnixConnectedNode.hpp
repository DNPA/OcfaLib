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
						
#ifndef UNIXCONNECTEDNODE_H
#define UNIXCONNECTEDNODE_H

#include "BasicFsConnectedNode.hpp"

namespace ocfa
{
  namespace fs
  {
/**
  * class UnixConnectedNode
  * This class extends the BasicFsConnectedNode by adding aditional unix specific
  * stat information as metadata.
  */
    //RJM:CODEREVIEW Alternate naming: ModUnixDirTreeConnectedNode:public DirTreeConnectedNode
    //This class extends the BasicFsConnectedNode with unix filesystem specific metadata.
    class UnixConnectedNode:public BasicFsConnectedNode
    {

/** Public methods: */
    public:
    /**
      * constructor
      *  The constructor mirrors the parameter usage of BasicFsConnectedNode, consult that class form more information.      
      */
      UnixConnectedNode (string charset, string path, bool readonly, std::string name);

    /**
      * as described in TreeGraphNode::getCurrentSubEntry
      * @param subent
      *        
      */
      void getCurrentSubEntity (TreeGraphNode ** subent);
      std::string getInodeType();

    };
  }
}
#endif				// UNIXCONNECTEDNODE_H
