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
						
#include "log4c/Log4cxxLogger.hpp"
#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/exception.h>
#include "log4c/OcfaFileAppender.hpp"
#include "misc/OcfaException.hpp"
#include "misc/OcfaConfig.hpp"
#include <iostream>
using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace ocfa;

namespace ocfa {

  namespace misc {

    namespace log4c {
      using log4cxx::BasicConfigurator;
      using log4cxx::PropertyConfigurator;
      using log4cxx::LoggerPtr;

      pthread_mutex_t Log4cxxLogger::mMutex = PTHREAD_MUTEX_INITIALIZER;

      LogStream::LogStream(pthread_mutex_t *inLog4cMutex)  {
	
	logger = 0;
	mLog4cMutex = inLog4cMutex;
      }
      
      
      
      void LogStream::setLevel(LevelPtr inLevel){
	
	level = inLevel;
      }
      
      
      void LogStream::setLogger(LoggerPtr inLogger){
	
	if (logger != 0 && str() != ""){
	  
	  flush();
	}
	logger = inLogger;
      }
      
      
      LogStream &LogStream::flush(){
	
	if (logger != 0){
	  
	  if (mLog4cMutex == 0){

	    throw OcfaException("no log4cMutex!");
	  }
	  pthread_mutex_lock(mLog4cMutex);
	  logger->log(level, str());
	  pthread_mutex_unlock(mLog4cMutex);
	}
	str("");
	return *this;
      }
      Log4cxxLogger::Log4cxxLogger() {

	string propertyFile = OcfaConfig::Instance()->getValue("log4cxx.propertyfile");
	string esyslog = OcfaConfig::Instance()->getValue("syslog");
	
	configure(propertyFile, esyslog);
      }
      
      
      Log4cxxLogger::~Log4cxxLogger(){
      }

      void Log4cxxLogger::configure(string inLogPropFile, string inDefaultSyslogLevel){

	//string propertyFile = OcfaConfig::Instance()->getValue("log4cxx.propertyfile");
	if (inLogPropFile == ""){
	  
	  log4cxx::BasicConfigurator::configure();
	  setLevel(inDefaultSyslogLevel);
	   //ocfaLog(LOG_NOTICE, "using basicconfigurator"); 
	   //ocfaLog(LOG_DEBUG, "esyslog set to " + esyslog);
	}
	else {


	  string propertyFile = string(getenv("OCFAROOT")) + "/" + inLogPropFile;
	  // ocfaLog(LOG_NOTICE, " using " + propertyFile);
	  PropertyConfigurator::configure(propertyFile);
	}
      }
      
      /**
       * baptize, starts reading again. Assumes that the config already is baptized.
       * 
       *
       */
      void Log4cxxLogger::baptize(ModuleInstance *instance){

	string prefix = instance->getNameSpace() + "." + instance->getModuleName();
	ocfaLog(LOG_DEBUG, string("baptizing entries with " + prefix));

	string propertyFile = OcfaConfig::Instance()->getValue("log4cxx.propertyfile");
	string esyslog = OcfaConfig::Instance()->getValue("syslog");
	//cerr << "acquiring mutex lock in baptize " << endl;
	pthread_mutex_lock(&mMutex);
	//cerr << "baptize: acquired" << endl;
	sBaptizables.clear();
	//cerr << " going to configure" << endl;
	configure(propertyFile,  esyslog);
	
	vector<Baptizable *>::iterator iter;

	int entries = sBaptizables.size();
        
	for (int x = 0; x < sBaptizables.size(); x++){
	  
	  //cerr << "baptizing stuff" << endl;
	  sBaptizables[x]->baptize(prefix);
	}
	//cerr << " unlocking " << endl;
	pthread_mutex_unlock(&mMutex);
      }

      /**
       * adds an object that wants to be baptized to a list of baptizables. 
       * The caller has ownership over the object but should not delete it.
       * @param inBaptizable the object that wants to be baptized.
       *
       */
      void Log4cxxLogger::addBaptizable(Baptizable *inBaptizable){

	sBaptizables.push_back(inBaptizable);
      }


      void Log4cxxLogger::setLevel(string inLevel){

	LoggerPtr rootLogger = Logger::getRootLogger();
	setLevel(inLevel, rootLogger);
      }



      /**
       * sets the root level for the logger. 
       */
      void Log4cxxLogger::setLevel(std::string esyslog, LoggerPtr rootLogger){
	
	//LoggerPtr rootLogger = Logger::getRootLogger();
	if (esyslog == "debug"){
	  
	  rootLogger->setLevel(Level::DEBUG);
	}
	else if (esyslog == "info")
	  
	  rootLogger->setLevel(Level::INFO);
	
	else if (esyslog == "notice")
	  
	  rootLogger->setLevel(Level::INFO);	
	else if (esyslog == "warning"){
	  rootLogger->setLevel(Level::WARN);
	}
	else if (esyslog == "err"){
	  rootLogger->setLevel(Level::ERROR);
	}
	else if (esyslog == "crit")
	  
	  rootLogger->setLevel(Level::FATAL);
	
	else if (esyslog == "alert")
	  rootLogger->setLevel(Level::WARN);
	
	else if (esyslog == "emerg")
	  rootLogger->setLevel(Level::FATAL);
	
	else {
	  rootLogger->setLevel(Level::INFO);
	  rootLogger->error("Unknown syslog level: " + esyslog); 
	}
	
      }
      
      void Log4cxxLogger::setLevel(string inLevel, string inPrefix){

	LoggerPtr theLogger = Logger::getLogger(inPrefix);
	setLevel(inLevel, theLogger);
      }
	/**
	 * returns a syslog stream that can be used for logging for a certain object.
	 * @param level the level to which can be logged.
	 * @param object the OcfaObject that requested the syslog stream.
	 *
	 * Creates a prefix from the namespace and the name of the object, then calls 
	 * syslog with that prefix.
	 */
      std::ostream &Log4cxxLogger::syslog(syslog_level inLevel, const OcfaObject *inObject){
      
	std::string prefix = inObject->getClassNameSpace() + "." + inObject->getClassName(); 
	
	return syslog(inLevel, prefix);
      }
      
	/**
	 * returns a syslog stream can be used for logging for a
	 * certain method. 
	 * @param prefix the prefix that is used to identity the stream that should be retrieved.
	 * @param level the level of the stream
	 * @returns a stream to which debug information can be logged. An endl means the end of a message.
	 * 
	 * Sets the logstream's logger to the logger retrieved using the prefix, then returns the logstream. 
	 *
	 */      
      std::ostream &Log4cxxLogger::syslog(syslog_level inLevel, std::string inPrefix){
	
	LoggerPtr logger = Logger::getLogger(inPrefix);
	LevelPtr log4cLevel = getLog4cxxLevel(inLevel);
	pthread_t threadId = pthread_self();
	LogStream *logStream = 0;
	pthread_mutex_lock(&mMutex);
	if (mLogStreamMap[threadId] == 0){

	  mLogStreamMap[threadId] = new LogStream(&mMutex);
	}
	logStream = mLogStreamMap[threadId];
	pthread_mutex_unlock(&mMutex);
	logStream->setLogger(logger);
	logStream->setLevel(log4cLevel);
	return *logStream;
	
      }

	/**
	 * returns the log4c equivalent of a syslog_level.
	 *
	 */      
      LevelPtr Log4cxxLogger::getLog4cxxLevel(syslog_level inLevel){
	
	switch(inLevel){
	  
	case LOG_DEBUG:
	  
	  return Level::DEBUG;
	  break;
	case LOG_INFO:
	  return Level::INFO;
          break;
	case LOG_NOTICE: 
	case LOG_WARNING:
	  return Level::WARN;
	  break;
	case  LOG_ERR:
	  return Level::ERROR;
	  break;
	case LOG_CRIT:
	case LOG_ALERT: 
	case LOG_EMERG:
	  return Level::FATAL;
	  break;
	default:
	  return Level::DEBUG;
	}
      }       


      std::vector<Baptizable *> Log4cxxLogger::sBaptizables;
    }
  }
}
namespace std {

  
  ocfa::misc::log4c::LogStream &endl(ocfa::misc::log4c::LogStream &inLogStream){

      return inLogStream.flush();
    }
}

/**
 * c-methods that returns a OcfaLogger.
 */
OcfaLogger *createOcfaLogger(){

  return new ocfa::misc::log4c::Log4cxxLogger();
}
