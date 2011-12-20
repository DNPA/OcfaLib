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
						
#include <OcfaObject.hpp>
#include <misc/OcfaException.hpp>
#include <misc/OcfaLogger.hpp>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include <map>
#include <unistd.h>
#include <vector>
#include <boost/lexical_cast.hpp>
#ifdef LINUX
#include <execinfo.h>
#endif
#include <cxxabi.h>
#include <stdio.h>
using namespace std;
using namespace ocfa::misc;
namespace ocfa {
  using misc::OcfaException;
  using misc::OcfaLogger;

     /*Definition of static members*/
     map < string, int > OcfaObject::ms_obj_count;

     map < string, int > OcfaObject::ms_test_reference;
     size_t OcfaObject::reference_data_footprint;
     size_t OcfaObject::reference_lib_footprint;
     size_t OcfaObject::reference_dirty_footprint;
	    

     
     /**** Constructor ******************************************************/	
     OcfaObject::OcfaObject():mNamepace(string("DefaultNamespece")),myname(string("DefaultOcfa")) {
       myname=string("DefaultOcfa");
       mNamepace=string("DefaultNamespece");
       ms_obj_count[myname]++;
       throw OcfaException("OOPS:: Ocfa constructor with no arguments\n", this);
     }
     
     /**** Constructor ******************************************************/	
     OcfaObject::OcfaObject(string typ,string namspace):mNamepace(namspace),myname(typ) {
       if (myname == string("")) {
	       myname=string("DefaultOcfa");
	       mNamepace=string("DefaultNamespece");
	       ms_obj_count[myname]++;
	       throw OcfaException("OOPS:: Ocfa constructor with empty class name\n", this);
       }
       ms_obj_count[myname]++;
       if (mNamepace == string("")) {
          mNamepace=string("DefaultNamespece");
	  throw OcfaException("OOPS:: Ocfa constructor with empty namespace\n", this);
       }
       
       
     }
     
     
     /**** Copy Constructor **************************************************/	
     OcfaObject::OcfaObject(const OcfaObject &orig):mNamepace(string("DefaultNamespace")),myname(string("DefaultOcfa")){
       myname=orig.getClassName();
       mNamepace=orig.getClassNameSpace();
       ms_obj_count[myname]++;
     }
     
     /**** Constructor ******************************************************/	
     OcfaObject::OcfaObject(OcfaObject &orig):mNamepace(string("DefaultNamespace")),myname(string("DefaultOcfa")){
       myname=orig.getClassName();
       mNamepace=orig.getClassNameSpace();
       ms_obj_count[myname]++;
     }

     /**** Destructor *******************************************************/
     OcfaObject::~OcfaObject() {
       ms_obj_count[myname]--;
     }
   
     /**** METHODS **********************************************************/ 
     void OcfaObject::updateTypeName(const string& subtype){
       ms_obj_count[myname]--;
       myname=subtype;
       ms_obj_count[myname]++;
     }
 
     void OcfaObject::PrintObjCount(const string& tnam) {
       OcfaLogger::Instance()->syslog(LOG_WARNING) << "OcfaObject::PrintObjCount(" +tnam + ") :" + boost::lexical_cast<std::string>(ms_obj_count[tnam]) + " objects in the system\n";
     }
    
     void OcfaObject::PrintObjCount() {
	   map < string, int >::const_iterator namit;
	   for (namit = ms_obj_count.begin(); namit != ms_obj_count.end(); ++namit) {
	        PrintObjCount(namit->first);
	   } 
     }
     
     int OcfaObject::getObjectCount(const string& tnam){
       return ms_obj_count[tnam];
     }
    
     void OcfaObject::setMemLeakTestRefPoint() {
           ms_test_reference= ms_obj_count;
	   reference_data_footprint=OcfaObject::dataFootPrint();
	   reference_lib_footprint=OcfaObject::libFootPrint();
	   reference_dirty_footprint=OcfaObject::dirtyFootPrint();
     }
     void OcfaObject::printMemLeakTestResult() {
           map < string, int >::const_iterator namit;
	   bool objleak=false;  
	   bool rawleak=false;
	   for (namit = ms_obj_count.begin(); namit != ms_obj_count.end(); ++namit) {
		if (ms_test_reference[namit->first] != ms_obj_count[namit->first]) {
	          OcfaLogger::Instance()->syslog(LOG_WARNING) << "OcfaObject::printMemLeakTestResult(" << namit->first << ") :"
			  << (ms_obj_count[namit->first] - ms_test_reference[namit->first]) << " objects leaked\n";
		  objleak=true;
		}
	   }
	   if (objleak == false) {
              if (OcfaObject::dataFootPrint() > reference_data_footprint) {
		 rawleak=true;
                 OcfaLogger::Instance()->syslog(LOG_WARNING) << "OcfaObject::printMemLeakTestResult() generic data leakage " <<
			(OcfaObject::dataFootPrint() - reference_data_footprint) << "\n";
	      }
	      if (OcfaObject::libFootPrint() > reference_lib_footprint) {
		 rawleak=true;
		 OcfaLogger::Instance()->syslog(LOG_WARNING) << "OcfaObject::printMemLeakTestResult() library data leakage " <<
			 (OcfaObject::libFootPrint()-reference_lib_footprint) << "\n";
	      }
	      if (OcfaObject::dirtyFootPrint() > reference_dirty_footprint) {
		rawleak=true;
		OcfaLogger::Instance()->syslog(LOG_WARNING) << "OcfaObject::printMemLeakTestResult() dirty data leakage " <<
			(OcfaObject::dirtyFootPrint()-reference_dirty_footprint) << "\n";
	      }
	      if (rawleak == false) {
                 OcfaLogger::Instance()->syslog(LOG_WARNING) << "OcfaObject::printMemLeakTestResult() EXCELENT, no leaks\n";
	      }
	   }
     }
     
     string OcfaObject::getClassName() const { 
	     return myname;
     }
    
     string OcfaObject::getClassNameSpace() const {
             return mNamepace;
     }
     
     string OcfaObject::whatObjInfo() const { 
             return string("[]");
	     //return (string("(") + myname + string(" class has not implemented its own whatObjInfo method yet.)"));
     }
    
    /**
     * fills a map with existing ocfa objects.
     *
     */
     void OcfaObject::exportOcfaObjectCountTo(map<string, int> &outMap){

       map<string, int>::const_iterator iter;
       for (iter = ms_obj_count.begin(); iter != ms_obj_count.end(); iter++){
	 
	 if ((iter->second) > 0){
	   
	   outMap[iter->first] = iter->second;
	 }
       }
     }
   void OcfaObject::ocfaLog(syslog_level level,const string& line) const{

     OcfaLogger::Instance()->syslog(level, this) << line << endl; 
   }
     
    size_t OcfaObject::footPrint(size_t index) {
#ifdef LINUX
	    FILE *statm;
	    size_t size;
	    char *line=NULL;
	    vector <size_t> tokens;
	    int i=0;
	    int  s=0;
            statm=fopen("/proc/self/statm","r");
            getline(&line,&size,statm);
            fclose(statm);
            while (line[i] != 0) {
                if ((line[i] == '\n')|| (line[i] == ' ')) {
                   line[i]=0;
		   int tval=atoi(line+s);
		   if (tval < 0) {tval=0;}
                   tokens.push_back(static_cast<size_t>(tval));
                   s=i+1;
                 }
		 i++;
	    }
	    free(line);
	    return tokens[index+4];
#else
            return 0;
#endif
    } /*end method footprint*/

  ostream &OcfaObject::getLogStream(syslog_level inLevel) const{

    return OcfaLogger::Instance()->syslog(inLevel, this);

  }



} /*end namespace ocfa*/
