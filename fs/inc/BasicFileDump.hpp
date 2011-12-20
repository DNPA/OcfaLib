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
						
#ifndef BASICFILEDUMP
#define BASICFILEDUMP
#include "BasicFsEntity.hpp"
namespace ocfa {
	namespace fs {
	  /**
	   * JBS Documentation: What does this class do? 
	   */
	  //RJM:CODEREVIEW Alternate naming: DirTreeFileDumpImplementation: public GenericDirTreeNode
	  //This class is the basic implementation for classes that represent a non file entity
	  //as a filedump. 
          class BasicFileDump:public BasicFsEntity {
	     FILE *mFile;  //The open file handle
	     std::string mPath; // the path of the filedump
	     bool mHasContent;
	   public:
             BasicFileDump(std::string path);
	     bool hasContent();
	     void openStream();
             off_t getSize();
             size_t streamRead(char *buf, size_t count);
	     void closeStream();
	     std::string getSoftLinkablePath(ocfa::misc::DigestPair **); 
	     std::string getHardLinkablePath(std::string basepath,ocfa::misc::DigestPair **);
	   protected:
	     BasicFileDump(const BasicFileDump& bfd):TreeGraphNode(bfd),BasicFsEntity(bfd),mFile(0),mPath(""),mHasContent(false) {
                throw misc::OcfaException("No copying allowed",this);
	     }
	     const BasicFileDump& operator=(const BasicFileDump&) {
		 throw misc::OcfaException("No assigment allowed",this);
                 return *this;
	     }
	  };
	}
}
#endif
