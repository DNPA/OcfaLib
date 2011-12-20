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
						
#ifndef SYSPSEUDONODE
#define SYSPSEUDONODE
#include <BasicFsConnectedNode.hpp>
namespace ocfa {
	namespace fs {
	   //RJM:CODEREVIEW Alternate naming: ModEncaseExportDirTreeSystemPseudoNode: public DirTreeConnectedNode
	   //This class represents the pseudo directory of an encase export filesystem subbranch that holds
	   //only the special 'system' nodes.
           class SystemPseudoNode: public BasicFsConnectedNode {
            public:
	     SystemPseudoNode(string charset, bool ignguids, bool ignts,string path,bool readonly,std::string name);
             bool nextSubEntity(); 
	     std::string getName() {return "FSSYTEMNODES";}
	   };
	}
}

#endif
