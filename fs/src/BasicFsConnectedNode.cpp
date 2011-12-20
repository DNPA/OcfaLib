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
#include "BasicFsConnectedNode.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <misc.hpp>
#include <string>
#include <dirent.h>
#include <grp.h>
#include <errno.h>
#include <treegraph/TreeGraphModuleLoader.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {

    /**
     * JBS: Better variable naming please.:
     * sv, dt, ignts
     */
    BasicFsConnectedNode::BasicFsConnectedNode(string charset,std::string path,bool readonly,std::string name):
	    BasicFsEntity(readonly,name),
	    mStat(),
	    mPath(path),
	    mFile(0),
	    mDir(0),
	    mCharset(charset),
            mActiveSubEntry(""),
	    mCurrentSubEntityRelation("undefined")
    {
       updateTypeName("BasicFsConnectedNode");
       ocfaLog(LOG_DEBUG,"path="+path);
       if (getName() ==  "") {
#ifdef CYGWIN
           updateName(Scalar(basename(const_cast<char *>(path.c_str()))).asUTF8());
#else
           updateName(Scalar(basename(path.c_str())).asUTF8());
#endif
       }
       if (lstat(mPath.c_str(),&mStat)== -1) {

          throw OcfaException("Problem calling stat on "+mPath,this);
       }
       misc::MetaValue *sv=new misc::ScalarMetaValue(Scalar(0));
       addMetaValue(string("isdeleted"),&sv);
       sv=0;
       if (S_ISREG(mStat.st_mode)) {
	       sv=new misc::ScalarMetaValue(Scalar(mStat.st_size));
	       addMetaValue(string("size"),&sv);
	       sv=new misc::ScalarMetaValue(Scalar("file"));
       }
       else if (S_ISDIR(mStat.st_mode)) {sv=new misc::ScalarMetaValue(Scalar("dir"));}
       else {
          if (S_ISCHR(mStat.st_mode)) { sv=new misc::ScalarMetaValue(Scalar("characterdevice"));}
          else if (S_ISBLK(mStat.st_mode)) {sv=new misc::ScalarMetaValue(Scalar("blockdevice"));}
          else if (S_ISFIFO(mStat.st_mode)) {sv=new misc::ScalarMetaValue(Scalar("fifo"));}
          else if (S_ISLNK(mStat.st_mode)) {sv=new misc::ScalarMetaValue(Scalar("softlink"));}
          else if (S_ISSOCK(mStat.st_mode)) {sv=new misc::ScalarMetaValue(Scalar("socket"));}
          else {
             //FIXME: log it!
             sv=new misc::ScalarMetaValue(Scalar("undefined"));
          }
       }
       addMetaValue(string("nodetype"),&sv);
       sv=0;

       const misc::DateTime *dt=new DateTime(getStat()->st_atime,mTimeSource);
       sv=new misc::ScalarMetaValue(Scalar(&dt));
       addMetaValue(string("accesstime"),&sv);
       dt=new DateTime(getStat()->st_mtime,mTimeSource);
       sv=new misc::ScalarMetaValue(Scalar(&dt));
       addMetaValue(string("modificationtime"),&sv);
       dt=new DateTime(getStat()->st_ctime,mTimeSource);
       sv=new misc::ScalarMetaValue(Scalar(&dt));
       addMetaValue(string("changetime"),&sv);
    }
    std::string BasicFsConnectedNode::getInodeType() {
       if (S_ISREG(mStat.st_mode)) {
          return "file";
       } else if (S_ISDIR(mStat.st_mode)) {
          return "dir";
       } else {
          return "special";
       }
    }
						    
    BasicFsConnectedNode::~BasicFsConnectedNode() {
       if (mDir) {
	    closedir(mDir);
       }
       mDir=0;
       // JBS Added unlink on destruct code.
       if (getUnlinkOnDestruct()){

	 int result;

	 if (getInodeType() == "dir"){

	   result = rmdir(mPath.c_str());
	 }
	 else {

	   result = unlink(mPath.c_str());
	 }
	 if (result != 0){

	   getLogStream(LOG_ERR) << "cannot unlink " << mPath << " error: "
				 << errno << endl;

	   throw OcfaException("Cannot unlink " + mPath); 
	 }
       }
    } 
    
    bool BasicFsConnectedNode::hasContent() {
      if (S_ISREG(mStat.st_mode)) return true;
      return false;
    }


    bool BasicFsConnectedNode::isReadable() {
      uid_t myuid=geteuid();
      if (myuid == 0) return true;
      struct group *grp=getgrnam("ocfa");
      if (grp==0) {
	// JBS is it really necessary to have an  ocfa group available in order to use the fs library?
        throw OcfaException("Unable to find the group id of the 'ocfa' group.",this);
      }
      // JBS more comments.What are you doing here and what has ocfa to do with it.
      if (S_ISDIR(mStat.st_mode)) {
         if (((mStat.st_mode & S_IROTH)&&(mStat.st_mode & S_IXOTH)) ||
	  ((mStat.st_mode & S_IRUSR)&& (mStat.st_uid==myuid) && (mStat.st_mode & S_IXUSR)) ||
	  ((mStat.st_mode & S_IRGRP)&& (mStat.st_gid==grp->gr_gid) && (mStat.st_mode & S_IXGRP))
	 ){
	    return true;
	 }
      } else if ((mStat.st_mode & S_IROTH) ||
          ((mStat.st_mode & S_IRUSR)&& (mStat.st_uid==myuid)) ||
	  ((mStat.st_mode & S_IRGRP)&& (mStat.st_gid==grp->gr_gid))
	 ) {
	      return true;
      }
      getLogStream(LOG_ERR) << "isReadable: non readable node " << (mStat.st_mode & S_IROTH) << ":" <<
	      ((mStat.st_mode & S_IRUSR)&& (mStat.st_uid==myuid)) << ":" <<
	      ((mStat.st_mode & S_IRGRP)&& (mStat.st_gid==grp->gr_gid)) << "\n";
      return false;
    }


    off_t BasicFsConnectedNode::getSize() {
        struct stat basestat;
        if (lstat(mPath.c_str(),&basestat)== -1) {
           throw OcfaException("Problem calling stat on "+mPath,this);
        }
        return basestat.st_size;
    }

    void BasicFsConnectedNode::openStream() {
      if (mFile != 0) {
        fclose(mFile);
	mFile=0;
      }
      mFile=fopen(mPath.c_str(),"r");
      if (mFile==0) {
         throw OcfaException("Unable to open file for reading :"+mPath,this);
      }
    }


    void BasicFsConnectedNode::closeStream() {
       if (mFile != 0) {
	 fclose(mFile);
         mFile=0;
       }
    }

    size_t BasicFsConnectedNode::streamRead(char *buf, size_t count) {
      return fread(static_cast<void *>(buf),1,count,mFile);	
    }


    bool BasicFsConnectedNode::hasSubEntities() {
	if (S_ISDIR(mStat.st_mode)) {
		resetSubEntityIterator();
		if (mActiveSubEntry!="") { 
			return true;
		}
	}
        return false; 
    }


    void BasicFsConnectedNode::resetSubEntityIterator() {
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


    bool BasicFsConnectedNode::nextSubEntity() {
       struct dirent *dent=0;
       do {
         dent=readdir(mDir);
       } while (dent && ((dent->d_name == string("."))||(dent->d_name == string(".."))));
       if (dent) {
	 mActiveSubEntry=dent->d_name;
	 return true;
       }
       mActiveSubEntry="";
       return false;
    }


    void BasicFsConnectedNode::getCurrentSubEntity(TreeGraphNode ** subent) {
	if (*subent !=0) {
          throw OcfaException("getCurrentSubEntity called with nonn NULL entity pointer as target",this);
	}
	if (mActiveSubEntry=="") {
          throw OcfaException("No current sub entity available");   
	}
	BasicFsConnectedNode *rsubent=new BasicFsConnectedNode(getCharset(),getPath()+"/"+mActiveSubEntry,isReadOnly(),mActiveSubEntry);
	mCurrentSubEntityRelation=rsubent->getInodeType() + "direntry";
        if ((mCurrentSubEntityRelation != "dirdirentry") && (mCurrentSubEntityRelation != "filedirentry")) {
           mCurrentSubEntityRelation="specialdirentry";
        }
        *subent=rsubent;	
    }


    string BasicFsConnectedNode::getCurrentSubEntityRelation() {
       return mCurrentSubEntityRelation; 
    }
    void BasicFsConnectedNode::setCurrentSubEntityRelation(std::string val) {
       mCurrentSubEntityRelation=val;
       if ((mCurrentSubEntityRelation != "dirdirentry") && (mCurrentSubEntityRelation != "filedirentry")) {
         mCurrentSubEntityRelation="specialdirentry";
       }
    }

    bool BasicFsConnectedNode::isRecursivelyUnlinkable() {

      uid_t myuid=geteuid();
      struct group *grp=getgrnam("ocfa");
      if (grp==0) {
           throw OcfaException("Unable to find the group id of the 'ocfa' group.",this);
      }
      //JBS more comments please.
      if (S_ISREG(mStat.st_mode)||
          ((mStat.st_mode & S_IWOTH)&&(mStat.st_mode & S_IXOTH)) ||
          ((mStat.st_mode & S_IWUSR)&& (mStat.st_mode & S_IXUSR) && (mStat.st_uid==myuid)) ||
          ((mStat.st_mode & S_IWGRP)&& (mStat.st_mode & S_IXGRP)&&(mStat.st_gid==grp->gr_gid))
      ) return true;
     return false;
    }


    string BasicFsConnectedNode::getSoftLinkablePath(ocfa::misc::DigestPair **) {
      return ""; //FIXME, without this we get softlinkable paths from workdirs.
      struct group *grp=getgrnam("ocfa");
      if (grp==0) {
	      throw OcfaException("Unable to find the group id of the 'ocfa' group.",this);
      }
      if (S_ISREG(mStat.st_mode) && isReadOnly() && (
	          (mStat.st_mode & S_IROTH) ||
	          ((mStat.st_mode & S_IRGRP)&& (mStat.st_gid==grp->gr_gid))
		      )) return mPath;
      return ""; 
    }
    
    string BasicFsConnectedNode::getHardLinkablePath(std::string hlreppath,ocfa::misc::DigestPair **) {
          if (S_ISREG(mStat.st_mode)) {
            struct stat hlrepstat;
            if (lstat(hlreppath.c_str(),&hlrepstat)== -1) {
               throw OcfaException("Problem calling stat on "+hlreppath,this);
            } 
            if (hlrepstat.st_dev == mStat.st_dev) 
                 return mPath;
          }
          return "";
    }
    FragmentList *BasicFsConnectedNode::getStoreDataMask() {
      return 0;
    }
    struct stat *BasicFsConnectedNode::getStat() {
      return &mStat; 
    }


    string BasicFsConnectedNode::getPath() {
      return mPath;
    }

    string BasicFsConnectedNode::getCharset() {
      return mCharset;
    }

    string BasicFsConnectedNode::getSubentName() {
       if (mActiveSubEntry == "") {
          throw OcfaException("No current sub entity available");
       }
       return mActiveSubEntry;
    }
    void BasicFsConnectedNode::unlinkOnDestruct() {
      BasicFsEntity::unlinkOnDestruct();
      if (getInodeType() == "dir") {
	// JBS return value should be checked.
	  chmod(mPath.c_str(),S_IWUSR|S_IRUSR|S_IXUSR); 
      } 
    }
  }
}
