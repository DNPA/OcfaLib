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
						
#ifndef BASICFSENTITY_H
#define BASICFSENTITY_H
#ifndef LINUX 
#include <libgen.h>
#endif
#include <misc.hpp>
#include <treegraph/TreeGraphNode.hpp>
namespace ocfa {
  namespace fs {
/**
  * class BasicFsEntity
  * This class implements some of the basic functionality of the TreeGraphNode. The
  * methods of TreeGraphNode not defined here have will throw an exception. The folowing
  * methods have an empty implementation: isReadable() returns true, asStream()
  * returns 0, isUnlinkable() returns false.
  */
    //RJM:CODEREVIEW alternate naming: DirTreeNode public TreeGraphNode, public OcfaObject
    //This class is the base implementation of directory tree (mounted filesystems) treegraph
    //nodes. It basically is a class used only to set the default behaviour of all its derived
    //classes in a somewhat sane way. There should be no actual instances of BasicFsEntity.
    class BasicFsEntity : virtual public ocfa::treegraph::TreeGraphNode , public OcfaObject {

/** Public methods: */
    public:
    /**
      * Constructor
      * @param readonly
      *    This parameter propagates the read only flag from the root.    
      * @param name
      *    The name to give the new node.
      */
      BasicFsEntity(bool readonly, string name = "");

    /**
      * Destructor
      */
      virtual ~BasicFsEntity();

    /**
      * as described for TreeGraphNode::getName
      */
      string getName();

    /**
      * as described for TreeGraphNode::isReadOnly
      */
      virtual bool isReadOnly();

    /**
      * as described for TreeGraphNode::isReadable
      */
      bool isReadable();

    /**
      * as described for TreeGraphNode::takeMetaMap
      * @param map
      *    The map is a container of metadata names and metadata values for the node.
      *        
      */
      void takeMetaMap(map < string, misc::MetaValue * >**map);


      bool hasContent();
      size_t streamRead(char *buf, size_t count);
      bool isRecursivelyUnlinkable();
      virtual std::string getSoftLinkablePath(ocfa::misc::DigestPair **);
      virtual std::string getHardLinkablePath(std::string basereppath,ocfa::misc::DigestPair **);
      misc::FragmentList *getStoreDataMask();
      off_t getSize(){return 0;}
      void openStream(){}  //RJM:CODEREVIEW A 'did not overload' exception may be better here.
      void closeStream(){} //RJM:CODEREVIEW A 'did not overload' exception may be better here.
      void unlinkOnDestruct();
      bool hasSubEntities();
      void resetSubEntityIterator();
      bool nextSubEntity();
      void getCurrentSubEntity(ocfa::treegraph::TreeGraphNode **ent);
      string getCurrentSubEntityRelation();
/** Protected methods: */
    protected:
    /**
      * Protected method to update the name of the TreeGraphNode by a derived object.
      * @param name
      *        
      */
      void updateName(string name);

    /**
      * Protected method used to fetch the flag that is used to determine if the derived
      * object of TreeGraphNode will need to unlink the system entity represented by that
      * object on its own destrucion.
      */
      bool getUnlinkOnDestruct();

    /**
      * Protected method that allows derived classes of BasicFsEntity to add extra meta
      * data.
      * @param name
      *        
      * @param val
      *        
      */
      void addMetaValue(string name, misc::MetaValue ** val);
      BasicFsEntity(const BasicFsEntity& bfe):
	      TreeGraphNode(bfe),
	      OcfaObject(bfe),
	      mName("BOGUS"),
	      mUnlinkOnDestruct(false),
	      mReadOnly(true),
	      mMetaMap(0) 
      {
          throw misc::OcfaException("No copying allowed",this);
      }
      const BasicFsEntity& operator=(const BasicFsEntity&) {
          throw misc::OcfaException("No assignment allowed",this);
	  return *this;
      }
	      
/**Attributes: */
    protected:
    /**
      * The utf8 encoded version of the name of the TreeGraphNode
      */
        string mName;
    /**
      * Flag indicating if the object should (if conceptual) unlink the system entity
      * represented by the object when the object gets destroyed.
      */
      bool mUnlinkOnDestruct;
    /**
      * Flag indicating if the object is explicitly marked read only. 
      */
      bool mReadOnly;
    /**
      * A pointer to map that will be filled with all the metadata  the filesystem had
      * available on the entity.
      */
        map < string, misc::MetaValue * >*mMetaMap;
      string mTimeSource;
    };
}}
#endif				// BASICFSENTITY_H
