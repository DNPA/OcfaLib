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
						
#include "UnixConnectedNode.hpp"
#include <treegraph.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {
    // JBS Better variable naming ignguids, ignts, sv
    // JBS Try to extract some logical chunks from it. 100 lines for a method is too long. 
    UnixConnectedNode::UnixConnectedNode(string charset,string path,bool readonly,std::string name):BasicFsConnectedNode(
						      charset,path,readonly,name) {
       updateTypeName("UnixConnectedNode");
       misc::MetaValue *sv=0;
       if (getStat()->st_uid) {
	         sv=new misc::ScalarMetaValue(Scalar(getStat()->st_uid));
	         addMetaValue(string("uid"),&sv);
       }
       if (getStat()->st_gid) {
	         sv=new misc::ScalarMetaValue(Scalar(getStat()->st_gid));
	         addMetaValue(string("gid"),&sv);
       }
       if (getStat()->st_mode & S_ISUID) {
         sv=new misc::ScalarMetaValue(Scalar(getStat()->st_uid));
	 addMetaValue(string("suid"),&sv);
       }
       if (getStat()->st_mode & S_ISGID) {
	 sv=new misc::ScalarMetaValue(Scalar(getStat()->st_gid));
	 addMetaValue(string("sgid"),&sv);
       }
       if (getStat()->st_mode & S_ISVTX) {
	 sv=new misc::ScalarMetaValue(Scalar("true"));
	 addMetaValue(string("sticky"),&sv);
       }
       if (getStat()->st_mode & S_IRGRP) {
         sv=new misc::ScalarMetaValue(Scalar(getStat()->st_gid));
	 addMetaValue(string("groupreadable"),&sv);
       }
       if (getStat()->st_mode & S_IWGRP) {
         sv=new misc::ScalarMetaValue(Scalar(getStat()->st_gid));
	 addMetaValue(string("groupwritable"),&sv);
       }
       if (getStat()->st_mode & S_IROTH) {
         sv=new misc::ScalarMetaValue(Scalar("true"));
	 addMetaValue(string("worldreadable"),&sv);
       }
       if (getStat()->st_mode & S_IWOTH) {
	 sv=new misc::ScalarMetaValue(Scalar("true"));
	 addMetaValue(string("worldwritable"),&sv);
       }
       if (!(misc::OcfaConfig::Instance()->getValue("ignoreowneracl",this)!="false")) {
          if (getStat()->st_mode & S_IRUSR) {
		  sv=new misc::ScalarMetaValue(Scalar(getStat()->st_uid));
		  addMetaValue(string("userreadable"),&sv);
	  }
	  if (getStat()->st_mode & S_IWUSR) {
                  sv=new misc::ScalarMetaValue(Scalar(getStat()->st_uid));
		  addMetaValue(string("userwritable"),&sv);
	  }
       }
       if ((!(S_ISDIR(getStat()->st_mode)))||(!(misc::OcfaConfig::Instance()->getValue("ignoredirexecacl",this)!="false"))) {
          if (getStat()->st_mode & S_IXGRP) {
		  sv=new misc::ScalarMetaValue(Scalar(getStat()->st_gid));
		  addMetaValue(string("groupexecutable"),&sv);
	  }
	  if (getStat()->st_mode & S_IXOTH) {
		  sv=new misc::ScalarMetaValue(Scalar("true"));
		  addMetaValue(string("worldexecutable"),&sv);
	  }
	  if (!(misc::OcfaConfig::Instance()->getValue("ignoreowneracl",this)!="false")) {
             if (getStat()->st_mode & S_IXUSR) {
               sv=new misc::ScalarMetaValue(Scalar(getStat()->st_uid));
	       addMetaValue(string("userexecutable"),&sv);
	     }
	  }
       }
       if (S_ISDIR(getStat()->st_mode)) {
	       
       } else if (S_ISREG(getStat()->st_mode)) {
	  if (getStat()->st_nlink > 1) {
            sv=new misc::ScalarMetaValue(Scalar(getStat()->st_nlink));
	    addMetaValue(string("filelinks"),&sv);
            sv=new misc::ScalarMetaValue(Scalar(static_cast<long long>(getStat()->st_ino) ));
	    addMetaValue(string("inode"),&sv);
	  }
       } else {
	       if (S_ISLNK(getStat()->st_mode)) {
		 char linkbuf[8192];
		 size_t count=0;
                 if ((count=readlink(path.c_str(),linkbuf,8192)>0)) {
		    linkbuf[count]=0;
                    sv=new misc::ScalarMetaValue(Scalar(string(linkbuf),getCharset()));
		    addMetaValue(string("softlink"),&sv);
		 }
                 sv=new misc::ScalarMetaValue(Scalar("link"));
	       } else if (S_ISBLK(getStat()->st_mode)) {
	         sv=new misc::ScalarMetaValue(Scalar("blockdevice"));		       
               } else if (S_ISCHR(getStat()->st_mode)) {
                 sv=new misc::ScalarMetaValue(Scalar("characterdevice"));
               } else if (S_ISFIFO(getStat()->st_mode)) {
                 sv=new misc::ScalarMetaValue(Scalar("fifo"));
               } else if (S_ISSOCK(getStat()->st_mode)) {
                 sv=new misc::ScalarMetaValue(Scalar("socket"));
               } else {
                 sv=new misc::ScalarMetaValue(Scalar("UNKNOWN"));
               }
	       addMetaValue(string("special-type"),&sv);
       }
    } 
    std::string UnixConnectedNode::getInodeType() {
	if (S_ISREG(getStat()->st_mode)) {
	      return "file";
	} else if (S_ISDIR(getStat()->st_mode)) {
	      return "dir";
	} else if (S_ISLNK(getStat()->st_mode)){
	    return "softlink";
	}  else if (S_ISBLK(getStat()->st_mode)) {
            return "blockdevice";
	} else if (S_ISCHR(getStat()->st_mode)) {
            return "characterdevice";
	} else if (S_ISFIFO(getStat()->st_mode)) {
            return "fifo";
	} else if (S_ISSOCK(getStat()->st_mode)) {
            return "socket";
	} else {
            return "UNKNOWN";
	}
    }
    //
    void UnixConnectedNode::getCurrentSubEntity(TreeGraphNode ** subent) {
        if (*subent !=0) {
	     throw OcfaException("getCurrentSubEntity called with nonn NULL entity pointer as target",this);
	}
        UnixConnectedNode *rsubent=new UnixConnectedNode(getCharset(),getPath()+"/"+getSubentName(),isReadOnly(),getSubentName());
        setCurrentSubEntityRelation(rsubent->getInodeType() + "direntry");
	*subent=rsubent;
    }
}}
