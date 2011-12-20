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
						
#include <log4cxx/fileappender.h>
#include "log4c/Baptizable.hpp"

namespace ocfa {
  namespace misc {
    namespace log4c {

      using namespace log4cxx;
      using namespace log4cxx::helpers;

      /**
       * a derivative of fileappener that logs to a file. The name of
       * the file is changed when the object is baptized.
       *
       */
      class OcfaFileAppender : public misc::log4c::Baptizable, public log4cxx::FileAppender {
	
      public:
	// Stupid undocumented Macros needed for automatich object loading. 
	DECLARE_LOG4CXX_OBJECT(OcfaFileAppender)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(OcfaFileAppender)
			LOG4CXX_CAST_ENTRY_CHAIN(FileAppender)
			LOG4CXX_CAST_ENTRY_CHAIN(WriterAppender)
		END_LOG4CXX_CAST_MAP()
	
	/**
	 * defautlt constructor. Automatically adds itself to the list of baptizables maintained by 
	 * the OcfaLog4cLogger.
	 *
	 */
	OcfaFileAppender();  
	/**
	 * @todo should remove itself from the list of baptizables.
	 */
	virtual ~OcfaFileAppender();
	
	OcfaFileAppender(const log4cxx::LayoutPtr& layout, const log4cxx::String& filename, 
			 bool append, bool bufferedIO, int bufferSize);
	OcfaFileAppender(const log4cxx::LayoutPtr& layout, const log4cxx::String& filename, bool append);
	OcfaFileAppender(const log4cxx::LayoutPtr& layout, const log4cxx::String& filename);
	//void setFile(const String& file);
	//void setFile(const String& file, bool append,
	//	     bool bufferedIO, int bufferSize);
	/**
	 * creates a new file name using this name. Then sets it as the file to which should be logged. 
	 */
	void baptize(std::string inName);

      };
    }
  }
}
