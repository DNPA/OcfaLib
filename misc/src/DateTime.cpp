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
						
#include <misc/DateTime.hpp>
#include <misc/OcfaLogger.hpp>
#include <string>
#include <boost/lexical_cast.hpp>
#include <stdio.h>
namespace ocfa { 
  namespace misc {

    DateTime::DateTime(long int val, string timesourceref):OcfaObject("DateTime","ocfa"),
      time(val), sourceref(timesourceref) {
   }
    DateTime::~DateTime() {
    }
    DateTime DateTime::operator+(int arg) {
      return DateTime(time + arg, sourceref);
    }
    long int DateTime::getTime() const {
      return time;
    }
    string DateTime::getTimeSourceRef() const {
      return sourceref;
    }
    std::string DateTime::translate(long int val) {
      time_t tp=0;
      tp=val;
      struct tm *tval=localtime(&tp);
      std::string monthpadding="";
      if (tval->tm_mon < 9) monthpadding="0";
      std::string daypadding="";
      if (tval->tm_mday < 10) daypadding="0";
      std::string hourpadding="";
      if (tval->tm_hour < 10) hourpadding="0";
      std::string minutepading="";
      if (tval->tm_min < 10) minutepading="0";
      std::string secondpadding="";
      if (tval->tm_sec < 10) secondpadding="0";
      std::string datetime= boost::lexical_cast<std::string>(1900+tval->tm_year) + "-" + monthpadding + 
                     boost::lexical_cast<std::string>(1+tval->tm_mon) + "-" + daypadding +
                     boost::lexical_cast<std::string>(tval->tm_mday) + "T" + hourpadding + 
                     boost::lexical_cast<std::string>(tval->tm_hour) + ":" + minutepading +
                     boost::lexical_cast<std::string>(tval->tm_min) + ":" + secondpadding +
                     boost::lexical_cast<std::string>(tval->tm_sec); 
      return datetime;
    }
    long int DateTime::translate(std::string iso8601) {
       struct tm timestruct;
       if (sscanf(iso8601.c_str(),"%4d-%2d-%2dT%2d:%2d:%2d",&(timestruct.tm_year),&(timestruct.tm_mon),&(timestruct.tm_mday),
			                                  &(timestruct.tm_hour),&(timestruct.tm_min),&(timestruct.tm_sec)) !=6){
          if (sscanf(iso8601.c_str(),"%4d:%2d:%2d %2d:%2d:%2d",&(timestruct.tm_year),&(timestruct.tm_mon),&(timestruct.tm_mday),
                                                          &(timestruct.tm_hour),&(timestruct.tm_min),&(timestruct.tm_sec)) !=6){
              OcfaLogger::Instance()->syslog(LOG_ERR, "misc.DateTime") << "Invalid time string, no ISO 8601 " << endl;
              return 0;
          }
       }
       timestruct.tm_year-=1900;
       timestruct.tm_mon--;
       return mktime(&timestruct);
    }
  }
}
