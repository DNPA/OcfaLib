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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sstream>
#include <errno.h>
#include <libgen.h>
#include <linux/limits.h> // for PATH_MAX 

#include "misc/FsUtil.hpp"

namespace ocfa {
  namespace misc {
    namespace fsutil {
    
    //Private helper method for determining if two paths reside on the same device.
    bool isOnSameDevice(std::string p1,std::string p2) {
      struct stat astat;
      struct stat bstat;
      if (lstat(p1.c_str(),&astat)== -1) {
	return false;
      }
      if (lstat(p2.c_str(),&bstat)== -1) {
	return false;
      }
      if (astat.st_dev == bstat.st_dev) { 
	return true;
      }
      return false;
    }

    // check whether file exists
    bool fileExists(std::string path) {
      struct stat astat;
      if (lstat(path.c_str(),&astat)== -1) {
	return false;
      }
      return true;
    }

     //Function to dereferencing all symbolic links in a path string.
     std::string dereferencePath(std::string path) {
       char dereferenced[PATH_MAX+1];
       ssize_t lastderef=1;
       std::string rval=path;
       int loopcount=0;
       while (lastderef != -1) {
           loopcount++;
           if (loopcount > 100) {
              return "/bogus/symlink-loop";
           }
           lastderef=readlink(rval.c_str(), dereferenced, PATH_MAX+1);
           if (lastderef != -1) {
              std::string newrval=std::string(dereferenced,lastderef);
              if (dereferenced[0] != '/') {
                  char tempbuf[PATH_MAX+1];
                  snprintf(tempbuf,PATH_MAX,"%s",rval.c_str());
                  char *containingdir=dirname(tempbuf);
                  newrval=std::string(containingdir) + std::string("/") + std::string(dereferenced,lastderef);
              }
              if (newrval == rval) {
                 return rval;
              }
              rval=newrval;
           }
       }
       return rval;
     }
   }
 }
}
