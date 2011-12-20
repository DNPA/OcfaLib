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
#ifdef CYGWIN
#include <libgen.h>
#endif 						
#include "BasicFsFileSystem.hpp"
#include "BasicFsConnectedNode.hpp"
#include <misc.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {
    BasicFsFileSystem::BasicFsFileSystem(bool ro, string charset,dev_t dev,string mountpoint,string fstype,string devicefile):
	    BasicFsEntity(ro,"undef"),
	    mReadOnly(true),
	    mCharset(charset),
	    mDeviceNum(dev),
	    mMountPoint(mountpoint)
    {
	string x;
	x=devicefile;
        updateName("basicfsfilesystem");
        misc::MetaValue *sv=new misc::ScalarMetaValue(Scalar("filesystem"));
        addMetaValue(string("nodetype"),&sv);
	sv=new misc::ScalarMetaValue(Scalar(fstype));
	addMetaValue(string("fs-type"),&sv);
    }
    //
    BasicFsFileSystem::~BasicFsFileSystem() {

    } 
    //
    string BasicFsFileSystem::getCharset() {
      return mCharset; 
    }


    void BasicFsFileSystem::createTopNode(string path,
					     ocfa::treegraph::TreeGraphNode ** node,std::string basets) {
	if (*node != 0) {
           throw OcfaException("createTopNode with non NULL target FsConnectedNode pointer",this);
	}
	*node=new BasicFsConnectedNode(mCharset,path,isReadOnly(),basename(const_cast<char *>(path.c_str())));
	//FIXME: we should test if the path is realy on the same filesystem.
    }

    bool BasicFsFileSystem::hasSubEntities() {
       //JBS:CODEREVIEW Dit is niet goed, kan ook leeg zijn !
       return true;
    }


    void BasicFsFileSystem::resetSubEntityIterator() {
        
    }


    bool BasicFsFileSystem::nextSubEntity() {
      return false;
    }


    void BasicFsFileSystem::getCurrentSubEntity(TreeGraphNode ** subent) {

      if (*subent != 0) {
        throw OcfaException("getCurrentSubEntity with non NULL target Entity pointer",this);
      }
      *subent=new BasicFsConnectedNode(mCharset,mMountPoint,isReadOnly(),"ROOTDIR");
    }


    string BasicFsFileSystem::getCurrentSubEntityRelation() {
      return "dir";
    }


    dev_t BasicFsFileSystem::getDevNum() {
      return mDeviceNum;
    }
    std::string BasicFsFileSystem::getMountPoint() {
      return mMountPoint;
    }
  }
}
