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
						
#include "BasicFileDump.hpp"
#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <grp.h> 
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {

    /**
     * JBS more documentation please.
     *
     */
     BasicFileDump::BasicFileDump(std::string path):
	     TreeGraphNode(),
	     BasicFsEntity(true,"basicfiledump"),
	     mFile(fopen(path.c_str(),"r")),
	     mPath(path),
	     mHasContent(mFile != 0)
     {
       updateTypeName("BasicFileDump");
       if (mFile) {
         fclose(mFile);
       }
       mFile=0;
       struct stat astat;
       if (lstat(mPath.c_str(),&astat)== -1) {
	   throw OcfaException("Problem calling stat on "+mPath,this);
       }
       if (!(S_ISREG(astat.st_mode))) {
           throw OcfaException("Trying to create a BasicFileDump from something that is not a regular file "+mPath,this);
       }
       misc::MetaValue *sv=new misc::ScalarMetaValue(Scalar(astat.st_size));
       addMetaValue(string("size"),&sv);
       sv=new misc::ScalarMetaValue(Scalar("file"));
       addMetaValue(string("nodetype"),&sv);
     }
     bool BasicFileDump::hasContent() {
       return mHasContent;
     }

     off_t BasicFileDump::getSize() {
        struct stat basestat;
        if (lstat(mPath.c_str(),&basestat)== -1) {
           throw OcfaException("Problem calling stat on "+mPath,this);
        } 
        return basestat.st_size;
     }

     void BasicFileDump::openStream() {
       if (mFile) {
         fclose(mFile);
       }
       mFile=fopen(mPath.c_str(),"r");
     }
     size_t BasicFileDump::streamRead(char *buf, size_t count){
        return fread(static_cast<void *>(buf),1,count,mFile);
     }
     void BasicFileDump::closeStream() {
         fclose(mFile);
         mFile=0;
     }


    string BasicFileDump::getSoftLinkablePath(ocfa::misc::DigestPair **) {
	 return ""; //FIXME: we may under some circumstances want to return soft linkable paths.
    }
    
    string BasicFileDump::getHardLinkablePath(std::string basepath,ocfa::misc::DigestPair **) {
          struct stat hlrepstat;
          struct stat basestat;
          if (lstat(basepath.c_str(),&hlrepstat)== -1) {
             throw OcfaException("Problem calling stat on "+basepath,this);
          }
          if (lstat(mPath.c_str(),&basestat)== -1) {
             throw OcfaException("Problem calling stat on "+mPath,this);
          }
          if (hlrepstat.st_dev == basestat.st_dev)
                 return mPath;
          return "";
    }


     
  }
}
