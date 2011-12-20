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
						
#ifndef BASICFSCONNECTEDNODE_H
#define BASICFSCONNECTEDNODE_H
#include "BasicFsEntity.hpp"
#include <treegraph/types.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <treegraph.hpp>
namespace ocfa {
  namespace fs {
/**
  * class BasicFsConnectedNode
  * This class is the basic implementation of the FsConnectedNode.
  */
    //RJM:CODEREVIEW Alternative naming: DirTreeConnectedNode public GenericDirTreeNode, public ConnectedNode
    //This class implements the basic connected node for directory based (mounted filesystem based) loadable
    //modules. It is used on itself in the BasicFilesystem module, and is used as baseclass inj other loadable
    //modules.
    class BasicFsConnectedNode:public BasicFsEntity, public ocfa::treegraph::FsConnectedNode {

/** Public methods: */
    public:
    /**
      * The parameters are propagated from the filesystem, see filesystem documentation
      * for more info.
      */
      BasicFsConnectedNode(string charset,string path,bool readonly,std::string name);

    /**
      * destructor
      */
      ~BasicFsConnectedNode();
      void unlinkOnDestruct();
    /**
      * as described for TreeGraphNode::getSize
      */
      bool hasContent();

    /**
      * as described for TreeGraphNode::isReadable , determines the readability by checking if
      * either: * The ACLs declare it world readable * The entity is owned by the
      * effective uid of the active   process, and the ACLs declare it user readable. *
      * The ACLs declare it group readable, and the group   ownership of the entity is
      * the 'ocfa' group. But in case of a directory also the folowing: * The ACLs
      * declare it world executable * The entity is owned by the effective uid of the
      * active   process, and the ACLs declare it user executable. * The ACLs declare it
      * group executable, and the group   ownership of the entity is the 'ocfa' group.
      */
      bool isReadable();


      off_t getSize();
    /**
      * as described for TreeGraphNode::openStream
      */
      void openStream();

    /**
      * as described for TreeGraphNode::closeStream
      */
      void closeStream();

    /**
      * 
      * @param buf
      *        
      * @param count
      *        
      */
      size_t streamRead(char *buf, size_t count);

    /**
      * as described for TreeGraphNode::hasSubEntities, returns true in the case of
      * directories, false otherwise.
      */
      bool hasSubEntities();

    /**
      * as described for TreeGraphNode::resetSubEntityIterator
      */
      void resetSubEntityIterator();

    /**
      * as described for TreeGraphNode::nextSubEntity
      */
      bool nextSubEntity();

    /**
      * as described for TreeGraphNode::getCurrentSubEntry, returns a newly created
      * BasicFsConnectedNode from the directory entry that is currently active.
      * @param subent
      *        
      */
      void getCurrentSubEntity(TreeGraphNode ** subent);

    /**
      * as described for TreeGraphNode::getCurrentSubEntityRelation, returns
      * "direntry::<inodetype>".
      */
      string getCurrentSubEntityRelation();

    /**
      * as described for TreeGraphNode::isUnlinkable, returns true on files, on dirs it
      * returns true under any the folowing conditions: * The dir is world w+x * The file
      * is owned by the effective uid, and is owner w+x * The file is group owned by the
      * 'ocfa' group and is group w+x
      */
      bool isRecursivelyUnlinkable();

    /**
      * 
      */
      string getSoftLinkablePath(ocfa::misc::DigestPair **);

      string getHardLinkablePath(std::string basereppath,ocfa::misc::DigestPair **);

      misc::FragmentList *getStoreDataMask();

      std::string getInodeType();
/** Protected methods: */
    protected:
      void setCurrentSubEntityRelation(std::string val);
    /**
      * This protected method suplies derived classes with access to the basic stat
      * structure.
      */
      struct stat *getStat();

    /**
      * This protected method suplies derived classes with access to the path of the
      * node.
      */
      string getPath();

    /**
      * This protected method provides derived classes with the charset used by the
      * filesystem for representation of nodenames.
      */
      string getCharset();

      string getSubentName();
      
      BasicFsConnectedNode(const BasicFsConnectedNode& bfc):
	      TreeGraphNode(bfc),
	      BasicFsEntity(bfc),
	      FsConnectedNode(bfc),
	      mStat(),
	      mPath(""),
	      mFile(0),
	      mDir(0),
	      mCharset("BOGUS"),
	      mActiveSubEntry(""),
	      mCurrentSubEntityRelation("") 
      {
          throw misc::OcfaException("No copying allowed",this);	      
      }
      const BasicFsConnectedNode& operator=(const BasicFsConnectedNode&) {
          throw misc::OcfaException("No assigment allowed",this);
	  return *this;
      }
/**Attributes: */

    private:
    /**
      * The posix stat structure of the file/dir/symlink etc that is represented by this
      * object.
      */
      struct stat mStat;
    /**
      * The path this object was created from.
      */
      string mPath;
    /**
      * A filehandle used for reading from file entities.
      */
      FILE *mFile;
    /**
      * For directory nodes, the open dir handle.
      */
      DIR *mDir;
    /**
      * The charset
      */
      string mCharset;
    /**
       *
       */
      std::string mActiveSubEntry;

      std::string mCurrentSubEntityRelation;
    };
}}
#endif				// BASICFSCONNECTEDNODE_H
