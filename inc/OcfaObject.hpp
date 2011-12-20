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
						
#ifndef __OCFACLASS_HPP__
  #define __OCFACLASS_HPP__

#include <map>
#include <iostream>
#include <string>
#include <unistd.h>
#include "misc/syslog_level.hpp"
#include <iostream>

namespace ocfa {

  /** 
   * The mother of all classes  its implementation can be found in the misc 
   * 
   **/
  class OcfaObject {
  public:
    /** Constructor
     *  Please note that every derived class is responsible for naming itself !!!*/
    OcfaObject(std::string typ,std::string nspace);
    /** Copy constructor */
    OcfaObject(OcfaObject & orig);
    /**Copy constructor*/
    OcfaObject(const OcfaObject & orig);
    /** Destructor */
    virtual ~ OcfaObject();
    /** Fetch the objecttype name */
    std::string getClassName() const;
    /** get  the namespace the object resides in */
    std::string getClassNameSpace() const;
    /**Set the subtype name of a derived class 
     * Only use if there are more than one class
     * derived from the baseclass */
    void updateTypeName(const std::string& subtype);
    /** Method for checking for leaked objects 
     * in implemtations */
    static void PrintObjCount(const std::string& tnam) ;
    /*Methods for detecting mem leaks under Linux */
    static size_t dataFootPrint() { return footPrint(0);}
    static size_t libFootPrint() { return footPrint(1);}
    static size_t dirtyFootPrint() { return footPrint(2);}
    /**
     * fills a map with ocfaclasses that have one or more instances in
     * memory
     */
    static void exportOcfaObjectCountTo(std::map<std::string, int> &outMap) ;
    /** Print the object count for each type of OcfaObject*/
    static void PrintObjCount() ;
    /** Virtual method that a derived calass could override in order to
     *  debug its state after exception */
    virtual std::string whatObjInfo() const;
    /** Fetch the number of objects there is of a particular type*/
    static int getObjectCount(const std::string& tname) ;
    /** Log a line */
    void ocfaLog(ocfa::misc::syslog_level level,const std::string& line) const;

    std::ostream &getLogStream(ocfa::misc::syslog_level) const;
    static void setMemLeakTestRefPoint();
    static void printMemLeakTestResult(); 
  private:
    /**
     * Ocfa's should always have name. Thus This constructor is private
     */
    OcfaObject();
    static size_t footPrint(size_t index);
    std::string mNamepace;
    std::string myname;
    static std::map < std::string, int > ms_obj_count;
    static std::map < std::string, int > ms_test_reference;
    static size_t reference_data_footprint;
    static size_t reference_lib_footprint;
    static size_t reference_dirty_footprint;
  }; /*end class Ocfa*/

} /*end ocfa namespace*/
#endif
