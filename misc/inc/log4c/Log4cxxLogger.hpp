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
						
#ifndef LOG4CXX_LOGGER_HPP
#define LOG4CXX_LOGGER_HPP

#include <pthread.h>
#include <sstream>
#include <misc/OcfaLogger.hpp>
#include <misc/syslog_level.hpp>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/logger.h>
#include "log4c/Baptizable.hpp"

/**
 *  Log4cpp Logger
 *  
 * Implementation of OcfaLogger that forwards it
 *  logging calls to the appropriate log4c logger. This allows 
 * a more elaborate configuration of logging. Log4c is built around
 * a hierachy of loggers. 'A.B' is a descendent of A.
 * The Log4cxxOcfalogger uses the hierarchy of namespace.object name.
 * 
 * It uses the following properties:
 * log4cxx.propertyfile a property file that configures the Log4c logging system.
 * 
 *
 */ 
namespace ocfa {

  namespace misc {
    
    namespace log4c {
      /**
       * Logstream is an extension on ostringstream that sends the current string to
       * a logger each tim it is flushed. 
       *
       */
      class LogStream : public std::ostringstream {
	
      public:
	LogStream(pthread_mutex_t *inLog4cMutex);
	/**
	 *sets the log4clogger to which the stream should log after flushing 
	 */
	void setLogger(log4cxx::LoggerPtr logger);
	void setLevel(log4cxx::LevelPtr inLevel);
	LogStream &flush();
	
      private:
	log4cxx::LoggerPtr logger;
	log4cxx::LevelPtr level;
	pthread_mutex_t *mLog4cMutex;
      };
      
      
      class Log4cxxLogger : public ocfa::OcfaLogger {
      public: 

	/**
	 * reconfigures the Logger, using log4cxx.propertyfile. It
	 * also baptizes all log4c object that have registered
	 * themselves as baptizables by calling their baptize method
	 * with an appropriate prefix.
	 *
	 */
	void baptize(ModuleInstance *minst);
	/**
	 * sets the general level of the log4 system.
	 *
	 */
	void setLevel(string level);


	void setLevel(std::string inLevel, std::string inPrefix);
	/**
	 * returns a syslog stream that can be used for logging for a certain object.
	 * @param level the level to which can be logged.
	 * @param object the OcfaObject that requested the syslog stream.
	 *
	 */
	virtual std::ostream &syslog(syslog_level level, const OcfaObject *object);

	/**
	 * returns a syslog stream can be used for logging for a
	 * certain method. 
	 * @param prefix the prefix that is used to identity the stream that should be retrieved.
	 * @param level the level of the stream
	 * @returns a stream to which debug information can be logged. An endl means the end of a message.
	 *  
	 *
	 */
	virtual std::ostream &syslog(syslog_level level, std::string prefix = "");
	Log4cxxLogger();
	virtual ~Log4cxxLogger();

	/**
	 * adds a baptizable to the list that will be baptized when the logger itself is baptized
	 * @TODO: May put this in the general framework.
	 *
	 * @param inBaptizable an object that wants to be baptized.
	 */
	static void addBaptizable(Baptizable *inBaptizable);
        bool needsStdIO(){ return false;}	
      protected:


	void setLevel(std::string inLevel, log4cxx::LoggerPtr inLogger); 
	/**
	 * Removes old configuration and sets new onew. 
	 *
	 */
	void configure(std::string inLogPropFile, string esysLogLevel);

	/**
	 * returns the log4c equivalent of a syslog_level.
	 *
	 */
	static log4cxx::LevelPtr getLog4cxxLevel(syslog_level inLevel);
	
	
      private:


//	std::string mPrefix;
	/**
	* the default logging stream to which is written. It will log
	* to the log4cxxlogger that is set on it.
	*/
	//	LogStream logStream;

	/**
	 * a map consisting of threadids and logstreams
	 *
	 */
	std::map<pthread_t, LogStream *> mLogStreamMap;

	static std::vector<Baptizable *> sBaptizables;
	static pthread_mutex_t mMutex;
      };
    }
  }
}
namespace std {

  ocfa::misc::log4c::LogStream &endl(ocfa::misc::log4c::LogStream &inLogStream);
}

extern "C" {

  ocfa::misc::OcfaLogger *createOcfaLogger();
}
#endif
