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
#include "EncaseExportOfFileSystem.hpp"
#include <EncaseExportTopNode.hpp>
#include <FileDumpOfUnalocatedNode.hpp>
#include <FileDumpOfDeletedNode.hpp>
#include <DeletedPseudoNode.hpp>
#include <SystemPseudoNode.hpp>
//JBS:CodeReview documenteren s.v.p.
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {

   
    EncaseExportOfFileSystem::EncaseExportOfFileSystem(string charset,string path,std::string name):
	    BasicFsConnectedNode(charset,path,true,name),
	    mHasReturnedTopNode(false),
	    mHasReturnedDeleted(false),
	    mHasReturnedSystem(false),
	    mDir(0),
	    mPath(path), 
	    mActiveSubEntry(""),
	    mCurrentSubEntityRelation("undefined")
    {
	updateTypeName("EncaseExportOfFileSystem");
	ocfaLog(LOG_INFO,"Being constructed");
        //updateName("encaseexport");
	resetSubEntityIterator();
    }
    //
    void EncaseExportOfFileSystem::getCurrentSubEntity(TreeGraphNode ** subent) {
       if (*subent != 0) {
	        throw OcfaException("getCurrentSubEntity with non NULL target Entity pointer",this);
       }
       if (!mHasReturnedTopNode) {
          *subent=new EncaseExportTopNode(getCharset(),mPath,isReadOnly(),"ROOTDIR");
	  mHasReturnedTopNode=true;
	  return;
       } if (!mHasReturnedDeleted) {
	  *subent=new DeletedPseudoNode(getCharset(),true,false,mPath,isReadOnly(),"DELETED");
	  mHasReturnedDeleted=true;
	  return;
       }
       if (!mHasReturnedSystem) {
           *subent=new SystemPseudoNode(getCharset(),true,false,mPath,isReadOnly(),"SYSTEM");
	   mHasReturnedSystem=true;
	   return;
       }
       if (EncaseExportOfFileSystem::isUnalocatedNodeName(mActiveSubEntry)) {
            *subent=new FileDumpOfUnalocatedNode(mPath+"/" + mActiveSubEntry);
	    return;
       } 
       if (EncaseExportOfFileSystem::isLostNodeName(mActiveSubEntry)) {
          *subent=new BasicFsConnectedNode(getCharset(),getPath()+"/"+mActiveSubEntry,isReadOnly(),mActiveSubEntry);      
          return;
       }
       return;
    } 
    
    void EncaseExportOfFileSystem::resetSubEntityIterator() {
	  if (mDir) {
	          closedir(mDir);
	  }
	  mDir=0;
	  mDir=opendir(mPath.c_str());
	  if (mDir==0) {
	      throw OcfaException("Unable to open dir for reading:"+mPath,this);
	  }
	  mActiveSubEntry="ROOTDIR";
	  mCurrentSubEntityRelation="dirdirentry";
	  mHasReturnedTopNode=false;
	  mHasReturnedDeleted=false;
	  mHasReturnedSystem=false;
    }


    bool EncaseExportOfFileSystem::nextSubEntity() {
	  if (!mHasReturnedTopNode) {
	     mCurrentSubEntityRelation="dirdirentry";
	     return true;
	   } else if (!mHasReturnedDeleted) {
	     mCurrentSubEntityRelation="dirdirentry";
	     return true; 
	  } else if (!mHasReturnedSystem) {
	     mCurrentSubEntityRelation="fsinfo";
	     return true;
	  }
	  mCurrentSubEntityRelation="undefined";
          struct dirent *dent=0;
	  do {
	      dent=readdir(mDir);
	  } while (dent && (!EncaseExportOfFileSystem::isLostNodeName(dent->d_name)) &&
			   (!EncaseExportOfFileSystem::isUnalocatedNodeName(dent->d_name))
		  );
	  if (dent) {
	      mActiveSubEntry=dent->d_name;
	      if (EncaseExportOfFileSystem::isLostNodeName(dent->d_name)) {
                 mCurrentSubEntityRelation="lost";
	      } else {
                 mCurrentSubEntityRelation="unallocated";
	      }
	      return true;
	  }
	  mActiveSubEntry="";
	  return false;
     }
    string EncaseExportOfFileSystem::getCurrentSubEntityRelation(){
	 return mCurrentSubEntityRelation;
    }
  }
}


