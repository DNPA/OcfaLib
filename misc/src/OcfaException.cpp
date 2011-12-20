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
						
#include <misc/OcfaException.hpp>
#include <misc/OcfaLogger.hpp>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include<map>
#include<iostream>
#include<unistd.h>
#include<vector>
#ifdef LINUX
#include<execinfo.h>
#endif
#include<cxxabi.h>
using namespace std;
namespace ocfa {
  namespace misc {
     /**** CLASS OCFA Exception *********************************************/
     
     /**** Constructor ******************************************************/	
     OcfaException::OcfaException(string msgstr,OcfaObject const *throwmaster):thrower(throwmaster),msg(""){
	thrower=throwmaster;
	if (thrower) {
          msg=msgstr + ":" + throwmaster->getClassName() + ":" + throwmaster->whatObjInfo();
	} else {
          msg=msgstr + ":UNDEFINED:UNDEFINED";
	}
	thrower=throwmaster;
	saveStackTrace();
     }
    
     /**** Constructor ******************************************************/	
     OcfaException::OcfaException(string msgstr):thrower(NULL),msg(msgstr){
	saveStackTrace();
     }

     /**** METHODS **********************************************************/ 
     
     const char *OcfaException::what() const{
	     return msg.c_str();
     }
   
     void OcfaException::logWhat() const {
	     OcfaLogger::Instance()->syslog(LOG_ERR, "OcfaException ") << msg << endl;
     }
     
     const OcfaObject *OcfaException::getOcfaObject() const {
	     return thrower;
     }
    

     // This method adds a stacktrace to the msg-member of OcfaException
     void OcfaException::saveStackTrace(){
#ifdef LINUX
      void *array[10];
      size_t size;
      char **strings;
      size_t i;
      
      // Since the backtrace symbols are not immediately convertable by
      // the demangle function, we need to get the substring-to-demangle first.
      // For this, we use the regex.
      regex_t preg;
      regmatch_t pmatch[2];
      regcomp(&preg,".*\\((.*)\\+.*\\) \\[.*\\]",REG_EXTENDED);
      
      // get the trace
      size = backtrace(array, 10);
      strings = backtrace_symbols(array, size);

      msg = msg + string("\n\nBegin stacktrace:\n");

      // for every string in the trace, we try to get the substring-to-demangle.
      // if that fails we just add the raw string to the msg.
      for (i = 0; i < size; i++){
        int status = 0;
	ocfa::misc::OcfaLogger::Instance()->syslog(LOG_NOTICE, "OcfaException::saveStackTrace ") << "debug stacktrace: " << strings[i] << "\n";
	if (regexec(&preg, strings[i], 2, pmatch, 0) == 0){
	   char mangled[1024];
	   size_t last=pmatch[1].rm_eo - pmatch[1].rm_so;
	   char *realname=0;
	   if (last <  1024) {
	     strncpy(mangled, strings[i] + pmatch[1].rm_so, last);
	     mangled[last] = 0;
             realname = abi::__cxa_demangle(mangled, 0, 0, &status);
	   } else {
             realname=static_cast<char *>(malloc(20));
	     strncpy(realname,"OOPS,name to long",19);
	     realname[19]=0;
	   }
	   if (status == 0){
             msg = msg + string("\n") + string(realname);
	   } else {
             msg = msg + string("\n") + string(strings[i]);
	   }
	   free(realname); // let's hope demangle returns 0 when it fails
	} else {
           msg = msg + string("\n") + string(strings[i]);
	}
	
      }
      msg = msg + string("\n\nEnd stacktrace.");
      regfree(&preg);
      // documentation on backtrace_symbols says that only strings needs to be freed and not the
      // individual strings.
      free(strings);
#else
      
#endif
     }
  } /*end namespace ocfa*/
}
