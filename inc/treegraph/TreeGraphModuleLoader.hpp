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
						
#ifndef FILESYSTEMSELECTOR_H
#define FILESYSTEMSELECTOR_H
#include <string>
#include <map>
#include "TreeGraphFactory.hpp"
#include <misc/PolicyLoader.hpp>
namespace ocfa {
  namespace treegraph {
    typedef SinglePointerConstructor< TreeGraphFactory, std::map< std::string,misc::Scalar > > CTreegraphType;
    typedef PolicyLoader<CTreegraphType> PLTreeGraph;
    struct MountInfo;
    class TreeGraphModuleLoader
    {
      
      /** Public methods: */
    public:
      
      /**
       * This version of the selectAndInit method is used to set and select an active
       * filesystem using a specified loadable module. This call replaces the now depecated
       * calls selectAndInitEncaseExport and selectAndInitPartition
       *
       *  @param module
       *       Names the treegraph module to load.
       *
       *  @param attributes
       *       Gives a map of named attributes specific to the loadable module.
       *       Please note that modules loaded like this can only be used as connector
       *       and not as root node.
       **/
      static bool selectAndInit(std::string module, std::map<std::string,misc::Scalar> *attributes=0);
      
      /**
       * This method returns a pointer to the TreeGraphFactory object for the currentl
       * selected filesystem.
       */
      static TreeGraphFactory * getFactory();
      
    private:
      /**
       * This static atribute is used to hold a pointer to the currently active
       * TreeGraphFactory object.
       */
      static TreeGraphFactory * mActiveFileSystem;
      
      static PLTreeGraph *mPolicyLoader;
    };
  }
}

#endif // FILESYSTEMSELECTOR_H
