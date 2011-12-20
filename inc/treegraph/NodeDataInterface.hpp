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
						
#ifndef NODEDATAINTERFACE_HPP
#define NODEDATAINTERFACE_HPP
#include "misc.hpp"
#include <string>
namespace ocfa {
  namespace treegraph {
   /* The NodeDataInterface is one of the 3 sub interfaces of the TreeGraphNode */    
    class NodeDataInterface {
/** Public methods: */
    public:
    /**
      * Returns if the TreeGraphNode has any content.
      */
      virtual bool hasContent();

    /**
      * Returns the size of the node data or 0 if this size is unknown.
      */
      virtual off_t getSize();
    /**
      * NOTE: The following methods are considered depricated. Please overrule streamToOutput instead.
      */
      virtual void openStream();   //DEPRICATED
      virtual void closeStream();  //DEPRICATED
      virtual size_t streamRead(char *buf, size_t count); //DEPRICATED

    /**
      * Give the node a functor it can use to stream its content to a store entity.
      */
      virtual void streamToOutput(ocfa::misc::AbstractWriteFacet &writefacet);

    /**
      * This method will for TreeGraphNode that represent a file try to return a string
      * containing a path that could be used by the repository for soft linking.  For
      * this operation to return a pathe the folowing conditions must be met:  
      * * The TreeGraphNode must represent a regular file.
      * * The file resides on a read only filesystem.
      * * The file is readable to any memeber of the 'ocfa' group. 
      * * The config parameter 'staticmounts' is set to 'true'.
      */
      virtual std::string getSoftLinkablePath(ocfa::misc::DigestPair **nodedigests=NULL) ;
 
     /**
      * This method will for TreeGraphNode that represent a file try to return a string
      * containing a path that could be used by the repository for hard linking. For
      * this operation to return a path the folowing conditions must be met:
      * * The TreeGraphNode must represent a regular file.
      * * The file must reside on the same filesystem as the repository it is going to be
      *   linked from.
      * * The returned path must be unlinkable to the module library.
      */ 
      virtual std::string getHardLinkablePath(std::string targetbasepath,ocfa::misc::DigestPair **nodedigests=NULL);


      virtual ~NodeDataInterface(){}
    };
}}
#endif				// NODEDATAINTERFACE_HPP
