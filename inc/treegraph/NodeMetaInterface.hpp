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
						
#ifndef NODEMETAINTERFACE_HPP
#define NODEMETAINTERFACE_HPP
#include <string>
#include <map>
#include "../misc.hpp"
namespace ocfa {
  namespace treegraph {
/* The NodeMetaInterface is one of the 3 sub interfaces of the TreeGraphNode */
    class NodeMetaInterface {

/** Public methods: */
    public:
    /**
      * Returns the name of the TreeGraphNode in the encoding given by the filesystem 
      * that created the TreeGraphNode.
      */
      virtual std::string getName() = 0;

    /**
      * Take the MetaMap from the TreeGraphNode in order to suply it to the evidence library.
      * Note, this operation only returns a valid meta map ones, and returns NULL on a
      * second call.
      * @param map
      *        
      */
      virtual void takeMetaMap(std::map < std::string, misc::MetaValue * >**map) = 0;

      virtual ~NodeMetaInterface(){}

    };
}}
#endif				//  NODEMETAINTERFACE_HPP 
