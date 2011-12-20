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
						
#ifndef TREEGRAPH_FACTORY_HPP
#define TREEGRAPH_FACTORY_HPP
 
#include "types.hpp"
namespace ocfa {
  namespace treegraph {
/**
  * class TreeGraphFactory
  * This subclass of TreeGraphNode represents a currently selected filesystem.
  */

    class TreeGraphFactory {

/** Public methods: */
    public:
    /**
      * Get the (either auto detected or implicitly set) character set used for nodenames
      * on the treegraph module. 
      */
     virtual string getCharset() = 0;

    /**
      * This method alows to directly create a ConnectedNode object that repesents a
      * particular dir of file as located on the filesystem. This method will throw an
      * exception if the suplied path does not reside on the particular filesystem.
      * @param path : The path to use as base image, file or dir for the loaded module.
      *        
      * @param node : The top node returned by this method.
      *
      * @param hardlinkrepository : A path within the repository filesystem that the module may use
      *                             to determine if it can return soft linkable paths.
      * 
      * @param eid : The evidence identifier for the top node. The module can use this to create a
      *              usable timesource for its datetime metadata.      
      */
      virtual void createTopNode(string path, TreeGraphNode **node,std::string timesoucebase="INVALID") = 0;

      virtual ~TreeGraphFactory(){}

    };
}}
#endif				// TREEGRAPH_FACTORY_HPP
