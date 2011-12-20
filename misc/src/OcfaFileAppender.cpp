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
						
#include "log4c/OcfaFileAppender.hpp"
#include "misc/OcfaLogger.hpp"
#include "log4c/Log4cxxLogger.hpp"

#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>

#include <iostream>
namespace ocfa {

  namespace misc {
    namespace log4c {
      
      using namespace std;
      using namespace log4cxx;
      using namespace log4cxx::helpers;
      using namespace log4cxx::spi;
	
      //  undocumented Macros needed for automatich object loading. 
      IMPLEMENT_LOG4CXX_OBJECT(OcfaFileAppender)

      /**
       * defautlt constructor. Automatically adds itself to the list of baptizables maintained by 
       * the OcfaLog4cLogger.
       *
       */
      OcfaFileAppender::OcfaFileAppender() : FileAppender() {

	  Log4cxxLogger::addBaptizable(this);
      }

      OcfaFileAppender::~OcfaFileAppender(){	
      }

      OcfaFileAppender::OcfaFileAppender(const LayoutPtr& layout, const String& filename, bool append, 
		       bool bufferedIO, int bufferSize)
	: FileAppender(layout, filename, append, bufferedIO, bufferSize){
	
	Log4cxxLogger::addBaptizable(this);
      }
	
      OcfaFileAppender::OcfaFileAppender(const LayoutPtr& layout, const String& filename, bool append)
	  : FileAppender(layout, filename, append) {

	Log4cxxLogger::addBaptizable(this);
      }
	  
	
      OcfaFileAppender::OcfaFileAppender(const LayoutPtr& layout, const String& filename)
       : FileAppender(layout, filename){

	Log4cxxLogger::addBaptizable(this);
      }


	/**
	 * creates a new file name using this name. Then sets it as the file to which should be logged. 
	 */
      
      void OcfaFileAppender::baptize(string prefix){

	string file = getFile();
	string::size_type pos = file.find_last_of("/");
	if (pos != string::npos){

	  file.replace(pos + 1, file.size(), prefix + ".log");
	}
	else {
	  
	  file = prefix + ".log";
	}
	//	OcfaLogger::Instance()->syslog(LOG_INFO, "misc.log4c.OcfafileAppender") << "going to log to " + file << endl;
	setOption("file", file);
	activateOptions();
      }

    }
    
  }
}
	
