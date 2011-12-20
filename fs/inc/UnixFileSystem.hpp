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
						
#ifndef UNIXFILESYSTEM_H
#define UNIXFILESYSTEM_H

#include "BasicFsFileSystem.hpp"

namespace ocfa {
	namespace fs {
/**
  * class UnixFileSystem
  * This simple subclass of BasicFsFileSystem for only extends the function of its
  * baseclass by returning UnixConnectedNode's where the baseclass would return
  * BasicFsConnectedNode's.
  */
//RJM:CODEREVIEW alternate naming: ModUnixDirTreeRoot: public DirTreeConnector
//This class extends the BasicFsFilesystem with unix filesystem specific metadata on files and directories.
class UnixFileSystem : public BasicFsFileSystem
{

/** Public methods: */
public:
    /**
      * Constructor
      *    The constructor uses the same fields as the BasicFsFileSystem, consult that class for more information.       
      */
    UnixFileSystem( bool ro, string charset, dev_t dev,string mountpoint,string fstype,string devicefile);

    /**
      * as described for TreeGraphFactory::getCurrentSubEntity
      * @param subent
      *        
      */
    void getCurrentSubEntity( TreeGraphNode ** subent );

    /**
      * as described for TreeGraphFactory::createTopNode
      * @param path
      *        
      * @param node
      *        
      */
    void createTopNode( string path, ocfa::treegraph::FsConnectedNode ** node,std::string basets="INVALID" );


};
}
}
#endif // UNIXFILESYSTEM_H
