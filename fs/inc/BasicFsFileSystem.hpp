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
						
#ifndef BASICFSFILESYSTEM_H
#define BASICFSFILESYSTEM_H

#include "BasicFsEntity.hpp"
#include <treegraph/TreeGraphFactory.hpp>

namespace ocfa {
	namespace fs {
/**
  * class BasicFsFileSystem
  * The base implementation of the FsFileSystem
  * JBS: More comments please, especially, why some methods do nothing.
  */
//RJM:CODEREVIEW Alternative names: DirTreeConnector public TreeGraphFactory, public GenericDirTreeNode
//This class is the most basic root and connector node for directory based (that is mounted filesystem based) loadable modules.
//The BasicFsFileSystem can be used on its own, or as the base class of more extended mounted filesystem modules.
//
class BasicFsFileSystem : public ocfa::treegraph::TreeGraphFactory,public BasicFsEntity
{

/** Public methods: */
public:
    /**
      * Constructor
      * @param ro
      *    This flag should be set if the filesystem was mounted read only.     
      * @param charset
      *    This string holds the charset hint as detected by the TreeGraphModuleLoader.
      * @param dev
      *    This string holds the device identifier of the mounted filesystem
      * @param mountpoint
      *    This string holds the (pseudo) mountpoint as supplied by the TreeGraphModuleLoader
      * @param owner
      *    This integer holds the userid used as mountflag as detected by the TreeGraphModuleLoader
      * @param fstype
      *    This string holds the name of the filesystem as detected by the TreeGraphModuleLoader
      * @param devicefile
      *    This string holds the path of the device file of the device that the filsystem is located on
      */
    BasicFsFileSystem( bool ro, string charset, dev_t dev,string mountpoint,string fstype,string devicefile);

    /**
      * Destructor
      */
    ~BasicFsFileSystem(  );

    /**
      * As described in TreeGraphFactory::getCharset
      */
    string getCharset(  );

    /**
      * As described in TreeGraphFactory::getIgnoreGUids
      */
//    bool getIgnoreGUids(  );

    /**
      * As described in TreeGraphFactory::setIgnoreGUids
      */
//    void setIgnoreGUids(bool ignore);

    /**
      * As described in TreeGraphFactory::setIgnoreTimeStamps
      */
//    void setIgnoreTimeStamps(bool ignore);

    /**
      * As described in TreeGraphFactory::canDoDeletedNodes
      */
//    bool canDoDeletedNodes(  );

    /**
      * As described in TreeGraphFactory::canDoSystemNodes
      */
//    bool canDoSystemNodes(  );

    /**
      * As described in TreeGraphFactory::canDoUnalocatedNodes
      */
//    bool canDoUnalocatedNodes(  );

    /**
      * As described in TreeGraphFactory::setIgnoreDeletedNodes
      */
//    void setIgnoreDeletedNodes(bool ignore);

    /**
      * As described in TreeGraphFactory::setIgnoreSystemNodes
      */
//    void setIgnoreSystemNodes(bool ignore);

    /**
      * As described in TreeGraphFactory::setIgnoreUnalocatedNodes
      */
//    void setIgnoreUnalocatedNodes(bool ignore);

    /**
      * As described in TreeGraphFactory::createTopNode
      * @param path
      *        
      * @param node
      *        
      */
    void createTopNode( string path, ocfa::treegraph::TreeGraphNode ** node,std::string basets="INVALID");

    /**
      * as described for TreeGraphNode::hasSubEntities. 
      */
    bool hasSubEntities(  );

    /**
      * as described for TreeGraphNode::resetSubEntityIterator
      */
    void resetSubEntityIterator(  );

    /**
      * as described for TreeGraphNode::nextSubEntity
      */
    bool nextSubEntity(  );

    /**
      * as described for TreeGraphNode::getCurrentSubEntity
      * @param subent
      *        
      */
    void getCurrentSubEntity( TreeGraphNode ** subent );

    /**
      * as described for TreeGraphNode::getCurrentSubEntityRelation
      */
    string getCurrentSubEntityRelation(  );

    /**
     * described for TreeGraphFactory::getFsOwner
     */
//    uid_t getFsOwner();

/** Protected methods: */
protected:
    /**
      * A protected method that allows derived classes to access the device number of the
      * filesystem device.
      */
    dev_t getDevNum(  );
    bool getIgnoreTimestamps();
    std::string getMountPoint();


/**Attributes: */

private:
    /**
      * Flag holding information if the filesystem was mounted read only.
      */
    bool mReadOnly;
    /**
      * Atribute holding the (detected or explicitly set) character set the filesystem
      * uses for filename encoding.
      */
    string mCharset;
    /**
      * This flag holds information if for any reason uid/gid fields should be ignored
      * for the filesystem when compounding stat metadata.
      */
//    int mIgnoreGUID;
    /**
      * This flag holds information if for any reason timestamp fields should be ignored
      * for the filesystem when compounding stat metadata
      */
//    int mIgnoreTimeStamps;
    /**
      * This field holds the device number of the filesystem device.
      */
    dev_t mDeviceNum;
    /**
     *  This fields holds the path for the mountpoint of the device file
     */
    std::string mMountPoint;
    /**
     * The user id the filesystem was mounted with
     */
//    uid_t mOwner;
};
}
}

#endif // BASICFSFILESYSTEM_H
