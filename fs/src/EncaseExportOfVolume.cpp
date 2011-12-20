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
						
#include <dirent.h>
#include <EncaseExportOfVolume.hpp>
#include <EncaseExportOfFileSystem.hpp>
#include <FileDumpOfUnalocatedNode.hpp>
#include <FileDumpOfSwapPartition.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {

    // JBS Coder review more documentation s.v.p.
    EncaseExportOfVolume::EncaseExportOfVolume(bool ro, string charset, dev_t dev,string mountpoint,string fstype,string devicefile):
	    BasicFsFileSystem(ro,charset,dev,mountpoint,fstype,devicefile),
	    mDir(0),
	    mPath(mountpoint), 
	    mActiveSubEntry(""),
	    mCurrentSubEntityRelation("undefined")
    {
	updateTypeName("EncaseExportOfVolume");
	ocfaLog(LOG_INFO,"Being constructed");
        updateName("encaseexport");
        misc::MetaValue *sv2=new misc::ScalarMetaValue(Scalar("encaseexport"));
	addMetaValue(string("fs-type"),&sv2);
	resetSubEntityIterator();
    }
    //

    void EncaseExportOfVolume::getCurrentSubEntity(TreeGraphNode ** subent) {
       if (*subent != 0) {
	        throw OcfaException("getCurrentSubEntity with non NULL target Entity pointer",this);
       }
       if (mActiveSubEntry == ENCESEEXPORTOFVOLUME_UNUSED) {
          *subent=new FileDumpOfUnalocatedNode(getMountPoint()+"/" + mActiveSubEntry);
       } else {
	  if (mCurrentSubEntityRelation=="swappartitionentry") {
            *subent=new FileDumpOfSwapPartition(getMountPoint()+"/" + mActiveSubEntry + "/Unallocated Clusters");
	  } else {
            *subent=new EncaseExportOfFileSystem(getCharset(),getMountPoint()+"/" + mActiveSubEntry,mActiveSubEntry);
	  }
       }
    } 
    
    void EncaseExportOfVolume::resetSubEntityIterator() {
	  if (mDir) {
	          closedir(mDir);
	  }
	  mDir=0;
	  mDir=opendir(mPath.c_str());
	  if (mDir==0) {
	      throw OcfaException("Unable to open dir for reading:"+mPath,this);
	  }
	  nextSubEntity();
    }


    bool EncaseExportOfVolume::nextSubEntity() {
	  mCurrentSubEntityRelation="partitionentry";
          struct dirent *dent=0;
	  do { 
		  dent=readdir(mDir);
	  } while ((dent) && ((string(dent->d_name) == ".") || (string(dent->d_name) == "..")));

	  if (dent) {
	      mActiveSubEntry=dent->d_name;
	      mActiveSubEntry=dent->d_name;
	      if (dent->d_name[0] == 'U') {
                 mCurrentSubEntityRelation="partitionentry";
	      }
	      if (dent->d_name[0] == 's') {
                 mCurrentSubEntityRelation="swappartitionentry";
	      }
	      return true;
	  }
	  mActiveSubEntry="";
	  return false;
     }
    
    string EncaseExportOfVolume::getCurrentSubEntityRelation(){
        return mCurrentSubEntityRelation;
    }
  }
}

extern "C"
{
	  ocfa::fs::EncaseExportOfVolume * constructor (std::map<std::string,ocfa::misc::Scalar> * attributes)
          {
                  string charset="LATIN1";
                  string mountpoint="";
		  std::map<std::string,ocfa::misc::Scalar>::const_iterator p;
                  p=attributes->find("charset");
                  if (p!=attributes->end())
                    charset= p->second.asUTF8();
                  p=attributes->find("mountpoint");
                  if (p!=attributes->end())
                    mountpoint=p->second.asUTF8();
                  ocfa::fs::EncaseExportOfVolume * fs =new ocfa::fs::EncaseExportOfVolume (true, charset, 0, mountpoint,"unknown", "");
	          return fs;
	  }
}
