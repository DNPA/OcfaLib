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
#include "UnixFileSystem.hpp"
#include <UnixConnectedNode.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {
    UnixFileSystem::UnixFileSystem(bool ro, string charset, dev_t dev,string mountpoint,string fstype,string devicefile):BasicFsFileSystem(
						ro,charset,dev,mountpoint,fstype,devicefile
						) {
	updateTypeName("UnixFileSystem");
        updateName("unixfilesystem");
	ocfaLog(LOG_INFO,"Being constructed");
        misc::MetaValue *sv2=new misc::ScalarMetaValue(Scalar("unix"));
	addMetaValue(string("fs-type"),&sv2);
    }
    //
    void UnixFileSystem::getCurrentSubEntity(TreeGraphNode ** subent) {
       if (*subent != 0) {
	        throw OcfaException("getCurrentSubEntity with non NULL target Entity pointer",this);
       }
       *subent=new UnixConnectedNode(getCharset(),getMountPoint(),isReadOnly(),"ROOTDIR");
    } 
    //
    void UnixFileSystem::createTopNode(string path,
					    ocfa::treegraph::FsConnectedNode ** node,std::string basets) {
         if (*node != 0) {
	           throw OcfaException("createTopNode with non NULL target FsConnectedNode pointer",this);
 	 }
         *node=new UnixConnectedNode(getCharset(),path,isReadOnly(),basename(const_cast<char *>(path.c_str())));
	 //FIXME: we should test if the path is realy on the same filesystem.
    }
  }
}
extern "C"
{
  ocfa::fs::UnixFileSystem * constructor ( std::map<std::string,ocfa::misc::Scalar> *attributes)
  {
   bool ro=false;
   if ((*attributes)["ro"].asUTF8() == "true") ro=true;
   string charset=(*attributes)["charset"].asUTF8();
   dev_t dev=(*attributes)["device"].asInt();
   string mountpoint=(*attributes)["mountpoint"].asUTF8();
   string fstype=(*attributes)["fstype"].asUTF8();
   string devicefile=(*attributes)["devicefile"].asUTF8();
   ocfa::fs::UnixFileSystem * fs =new ocfa::fs::UnixFileSystem (ro, charset, dev, mountpoint,fstype, devicefile);
   return fs;
  }
}
