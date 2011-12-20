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
						
#ifndef ENCESEEXPORTOFFILESYSTEM_H
#define ENCESEEXPORTOFFILESYSTEM_H
#include <dirent.h>
#include "BasicFsConnectedNode.hpp"
//The folowing defines a set of 'special' file names and prefixes as used by encase in its export functionality.
#define ENCESEEXPORTOFFILESYSTEM_UNALLOCATED "Unallocated Clusters"
#define ENCESEEXPORTOFFILESYSTEM_VOLUMEBOOT "Volume Boot"
#define ENCESEEXPORTOFFILESYSTEM_VOLUMEBITMAP "Volume Bitmap"
#define ENCESEEXPORTOFFILESYSTEM_VOLUMESLACK "Volume Slack"
#define ENCESEEXPORTOFFILESYSTEM_PRIMFAT "Primary FAT"
#define ENCESEEXPORTOFFILESYSTEM_SECFAT "Secondary FAT"
#define ENCESEEXPORTOFFILESYSTEM_JOURNAL "Journal Area"
#define ENCESEEXPORTOFFILESYSTEM_INODEBITMAP "Inode Bitmap"
#define ENCESEEXPORTOFFILESYSTEM_INODETABLE "Inode Table"
#define ENCESEEXPORTOFFILESYSTEM_GROUPDESCRIPTORS "Group Descriptors"
#define ENCESEEXPORTOFFILESYSTEM_EXTENDBLOCKS "Extent Blocks"
#define ENCESEEXPORTOFFILESYSTEM_BLOCKDESCRIPTORS "Block Descriptors"
#define ENCESEEXPORTOFFILESYSTEM_HARDLINKS "Hard Links"
#define ENCESEEXPORTOFFILESYSTEM_VOLINFO "System Volume Information"
#define ENCESEEXPORTOFFILESYSTEM_LOSTFILES "Lost Files"
#define ENCESEEXPORTOFFILESYSTEM_DELETED '_'
#define ENCESEEXPORTOFFILESYSTEM_SYSNODE '$'

namespace ocfa {
	namespace fs {
//RJM:CODEREVIEW Alternate naming: ModEncaseExportDirTreeFsPartition: public DirTreeConnectedNode
//This class represents a sane view on a filesystem sub branch of an encase export.
class EncaseExportOfFileSystem : public BasicFsConnectedNode
{
    bool mHasReturnedTopNode;  //Flag for iterator purposes, have we returned the ROOTDIR pseudo dir already?
    bool mHasReturnedDeleted;  //Flag for iterator purposes, have we returned the DELETED pseudo dir already?
    bool mHasReturnedSystem;   //Flag for iterator purposes, have we returned the SYSTEM pseudo dir already?
    DIR *mDir;			// the open directory handle.
    std::string mPath;		
    std::string mActiveSubEntry;
    std::string mCurrentSubEntityRelation;
/** Public methods: */
public:
    /**
      * Constructor
      *  Parameters propogate those of the top TreeGraphFactory node.        
      */
    EncaseExportOfFileSystem(string charset,string path,std::string name);
    bool hasSubEntities() {return true;}
    /**
      * as described for TreeGraphFactory::getCurrentSubEntity
      * @param subent
      *        
      */
    void getCurrentSubEntity( TreeGraphNode ** subent );
    void resetSubEntityIterator();
    bool nextSubEntity();
    string getCurrentSubEntityRelation();
    static bool isSystemNodeName(string nodename) { //RJM:CODEREVIEW big enough to move to cpp.
       return ( 
	   ((nodename.size() > 1) && (nodename.c_str()[0] == ENCESEEXPORTOFFILESYSTEM_SYSNODE)) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_VOLINFO) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_HARDLINKS) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_BLOCKDESCRIPTORS) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_EXTENDBLOCKS) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_GROUPDESCRIPTORS) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_INODEBITMAP) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_INODETABLE) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_JOURNAL) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_SECFAT) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_PRIMFAT) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_VOLUMEBITMAP) ||
	   (nodename == ENCESEEXPORTOFFILESYSTEM_VOLUMEBOOT)
	   );
    }
    static bool isUnalocatedNodeName(string nodename) { // //RJM:CODEREVIEW big enough to move to cpp.
       return (
	       (nodename == ENCESEEXPORTOFFILESYSTEM_VOLUMESLACK) ||
	       (nodename == ENCESEEXPORTOFFILESYSTEM_UNALLOCATED)
	      );
    }
    static bool isDeletedNodeName(string nodename) { //RJM:CODEREVIEW may be moved to cpp for consistency with abouve.
        return ((nodename.size() > 1) && (nodename.c_str()[0]==ENCESEEXPORTOFFILESYSTEM_DELETED));
    }
    static bool isLostNodeName(string nodename) { //RJM:CODEREVIEW may be moved to cpp for consistency with abouve.
       return (nodename == ENCESEEXPORTOFFILESYSTEM_LOSTFILES);
    }
    static bool isEncaseNodeName(string nodename) { ////RJM:CODEREVIEW big enough to move to cpp.
       return (isSystemNodeName(nodename) || 
	       isUnalocatedNodeName(nodename) || 
	       isDeletedNodeName(nodename) ||
	       isLostNodeName(nodename)
	       );
    }
protected:
    EncaseExportOfFileSystem(EncaseExportOfFileSystem& eef):
	    TreeGraphNode(eef),
	    BasicFsConnectedNode(eef),
	    mHasReturnedTopNode(false),
	    mHasReturnedDeleted(false),
	    mHasReturnedSystem(false),
	    mDir(0),
	    mPath(""),
	    mActiveSubEntry(""),
	    mCurrentSubEntityRelation("")
    {
       throw misc::OcfaException("No copying allowed",this);
    }
    EncaseExportOfFileSystem& operator=(EncaseExportOfFileSystem&) {
       throw misc::OcfaException("No assignment allowed",this);
       return *this;
    }
	    
};
}
}
#endif 
