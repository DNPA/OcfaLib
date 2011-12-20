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
						
#define __USE_FILE_OFFSET64
#include <treegraph/TreeGraphModuleLoader.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <dlfcn.h>
#include <misc/PolicyLoader.hpp>
using namespace ocfa::misc;
namespace ocfa {
  namespace treegraph {

    TreeGraphFactory *TreeGraphModuleLoader::mActiveFileSystem=0;
    PLTreeGraph *TreeGraphModuleLoader::mPolicyLoader=0;
//    std::string TreeGraphModuleLoader::mTimeSource="UNDEFINEDTIMESOURCE";

    bool TreeGraphModuleLoader::selectAndInit(std::string module, std::map<std::string,misc::Scalar> *attributes) {
         PLTreeGraph *oldloader=0;
         if (mPolicyLoader) {
            oldloader=mPolicyLoader;
	 }
	 mPolicyLoader=new PolicyLoader<CTreegraphType>(module,"constructor");
         if (oldloader) {
            oldloader->closeLib();
            delete oldloader;
         }
	 CTreegraphType *constructor = mPolicyLoader->constructor();
         TreeGraphFactory *oldfilesystem=0;
         if (mActiveFileSystem) {
            oldfilesystem=mActiveFileSystem;
         }
	 mActiveFileSystem=(*constructor)(attributes);
         if (oldfilesystem) {
           delete oldfilesystem;
         }
         return true;
    }

    TreeGraphFactory *TreeGraphModuleLoader::getFactory() {
      return mActiveFileSystem;
    } 
    //
//    std::string TreeGraphModuleLoader::getTimeSource( ) {
//       return mTimeSource;
//    }
    //
//    void TreeGraphModuleLoader::baptize(std::string timesource) {
//      mTimeSource=timesource;
//    }

  }
}

