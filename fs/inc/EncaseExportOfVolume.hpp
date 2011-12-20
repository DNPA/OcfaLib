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

//RJM:CODEREVIEW Comments:
//This is the top node of the EncaseExport loadable module. We'll try to explain the basic function of this
//module here as this would most likely be more clear than describing part of it in different header files.
//This module works on a directory structure as provided by an encase export, and it tries to map this
//directory structure to one more in sync with expected usage. An important goal is the seperation of
//connected from non connected entities. Where the encase export interleaves them, we'll try to make a more
//clear distinction by moving them to different sub trees. The encase export holds a set of files and directories
//with names or prefixes that have a specific meaning and don't have a simular name in the original system.
//The loadable module tries to map these to the apropriate node types.
//At the top level the encase export will contain:
//  * A directory for each partition where a filesystem was found.
//  * A file with a name starting with a lowercase 's' that represents a swap partition.
//  * A file named "Unused Disk Area" (possibly more simular named) with unallocated space.
//
//The top level node will map each of these directory entities to equaly named nodes of the proper type.
//At the filesystem level encase uses special names for special files that represnt non file entities in the filesystem
//or volume areas not covered by the filesystem. The loadable module uses pseudo directories to group some of these
//interleaved files and directories in a beter way. The "Volume Slack", "Unallocated Cluster" and "Lost Files" are the only
//ones that are directly mapped to the coresponding treegraph.
//The regular files are all mapped to the pseudo dir named "ROOTDIR". Deleted files, that are prefixed with a '_' are
//represented under the "DELETED" pseudo dir, and specialy named 'system' directories and files are represented under
//the 'SYSTEM' pseudo directory.
//
#ifndef ENCESEEXPORTOFVOLUME_H
#define ENCESEEXPORTOFVOLUME_H
#include <dirent.h>
#include "BasicFsFileSystem.hpp"
#include "EncaseExportOfFileSystem.hpp"
#define ENCESEEXPORTOFVOLUME_UNUSED "Unused Disk Area"
namespace ocfa {
	namespace fs {
//RJM:CODEREVIEW Alternate name: ModEncaseExportDirTreeRoot:public DirTreeConnector
//This class represents the top node of a more sain view on a directory structure as created with an encase export.
class EncaseExportOfVolume : public BasicFsFileSystem
{
    DIR *mDir;
    std::string mPath;
    std::string mActiveSubEntry;
    std::string mCurrentSubEntityRelation;
/** Public methods: */
public:
    /**
      * Constructor
      *   The constructor parmaters mirror that of the BasicFsFileSystem, consult that class for more information.       
      */
    EncaseExportOfVolume(bool ro, string charset, dev_t dev,string mountpoint,string fstype,string devicefile);

    /**
      * as described for TreeGraphFactory::getCurrentSubEntity
      * @param subent
      *        
      */
    void getCurrentSubEntity( TreeGraphNode ** subent );
    void resetSubEntityIterator();
    bool nextSubEntity();
    std::string getName() {return "IMAGE";}
    string getCurrentSubEntityRelation();
protected:
    EncaseExportOfVolume(EncaseExportOfVolume& eef):
	    TreeGraphNode(eef),
	    BasicFsFileSystem(eef),
	    mDir(0),
	    mPath(""),
	    mActiveSubEntry(""),
	    mCurrentSubEntityRelation("")
    {
       throw misc::OcfaException("No copying allowed",this);
    }
    EncaseExportOfVolume& operator=(EncaseExportOfVolume&) {
       throw misc::OcfaException("No assignment allowed",this);
       return *this;
    }
	    
};
}
}
#endif // UNIXFILESYSTEM_H
