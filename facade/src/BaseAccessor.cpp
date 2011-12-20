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
						
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "facade/BaseAccessor.hpp"
#include "message/MessageBox.hpp"
#include "misc/OcfaLogger.hpp"
#include <boost/lexical_cast.hpp>
using namespace ocfa::facade;
using namespace std;
using namespace ocfa::misc;
using namespace ocfa::message;
using namespace ocfa::evidence;

/**
 *
 * 
 */
BaseAccessor::BaseAccessor (std::string inName, std::string inNamespace,bool forceforeground)
  : OcfaModule(){
  bool daemonize=(OcfaConfig::Instance()->getValue("daemonize") == "true");
  bool needsstdio=OcfaLogger::Instance()->needsStdIO();
  if (daemonize && forceforeground) {
    getLogStream(LOG_NOTICE) << "daemonize is forced disabled by constructor argument" << endl;
    daemonize=false;
  }
  if (daemonize && needsstdio) {
    getLogStream(LOG_NOTICE) << "daemonize is forced disabled by incompatible logger" << endl;
    daemonize=false;
  }
  if (daemonize){

    getLogStream(LOG_NOTICE) << "going to fork" << endl;
    pid_t pid;
    /**
     * it can be argued that this should be in the module library. However, I put
     * it here because in other languages (like java), forking would be really weird.
     *
     */
    pid = fork();
    getLogStream(LOG_NOTICE) << "pid is " << pid  << endl;
    if (pid < 0){

      throw OcfaException ("Unable to fork to background", this);
    }
    else if (pid != 0) {
      ocfa::misc::OcfaLogger::Instance()->syslog(LOG_NOTICE, "BaseAccessor ") << inNamespace << "::" << inNamespace << " going to background\n";
      exit(0);
    }
    // This can be used to decouple the module completely from the commandline. It is useful for running
    // it as  aservice.  
    setsid();
    // close std and stdout
    close(0);
    close(1);
    close(2);

    // Open stubs for stdin/stdout/stderr
    int f1=open("/dev/null",O_RDWR);
    if (OcfaConfig::Instance()->getValue("stdouttofile") == "true") {
       std::string fnam1="/tmp/ocfa_stdout_" + boost::lexical_cast<std::string>(getpid()) + ",log";
       open(fnam1.c_str(),O_RDWR|O_CREAT,0750);
    } else {
       dup(f1);
    }
    if (OcfaConfig::Instance()->getValue("stderrtofile") == "true") {
       std::string fnam2="/tmp/ocfa_stderr_" + boost::lexical_cast<std::string>(getpid()) + ",log";
       open(fnam2.c_str(),O_RDWR|O_CREAT,0750);
    } else {
       dup(f1);
    }



    // set filemode creation mask to rw-r--r--
    umask(022);
    
    // change working directory to "/".
    chdir("/");
  }
  getLogStream(LOG_NOTICE) << "BaseAccessor::BaseAccessor going to initialize" << endl;
  initialize(inName, inNamespace);
}

/**
 * wrapper around getEvidnece.getActiveJob
 */
string BaseAccessor::getJobArgument(std::string name) const {

  return getEvidence()->getActiveJob()->getArgument(name);
}

/**
 * shortcut for setting metadata of the active Evidence.
 * 
 */
void BaseAccessor::setMeta(string inMetaName, MetaValue &inValue){

  if ((getEvidence() == 0) || (getEvidence()->getActiveJob() == 0)){

    throw OcfaException("no active evidence or no activeJob set", this);
  }
  
  getEvidence()->getActiveJob()->setMeta(inMetaName, &inValue);  
}

void BaseAccessor::setMeta(string inMetaName, Scalar inValue){

  if ((getEvidence() == 0) || (getEvidence()->getActiveJob() == 0)){

    throw OcfaException("no active evidence or no activeJob set", this);
  }
  ScalarMetaValue scalarMeta(inValue); 

  getEvidence()->getActiveJob()->setMeta(inMetaName, &scalarMeta);  
}

/**
 * Add a Scalar to an array type Meta within the active job
 * @param n The name of the meta data
 * @param s The value (and type) of the meta data
 * @deprecated
 **/
/*
void BaseAccessor::pushBackMeta(string inName, Scalar s){
 
  JobIterator jobIterator = getEvidence()->getJobIterator();
  jobIterator->last();
  metaIterator = jobIterator->getMetaIterator();
  if (metaIterator == 0){

    ocfaLog(LOG_WARNING, string("Cannot find meta data simply using setMeta instead"));
    setMeta(name, s);
  
  } else {
  
    bool notFound = true;
    do {
      
      if (metaIterator->getName() == inName){
      
	MetaValue theValue = 
      }
    } while (metaIterator->hasNext() && notFound);
  

}
*/

void BaseAccessor::checkValidEvidenceAndJob() const {

  checkValidEvidence();
  
  if (getEvidence()->getActiveJob() == 0){

    throw OcfaException("no activeJob set", this);
  }
}

void BaseAccessor::checkValidEvidence() const {

  if (getEvidence() == 0){

    throw OcfaException("no active Evidence", this);
  }  
}

/**
 * shortcut for getting item of activeevidence. Also provides a sanity check.
 */
string BaseAccessor::getEvidenceItemID() const {
  
  checkValidEvidence();
  if (getEvidence()->getEvidenceIdentifier() == 0){

    throw OcfaException("No EvidenceIdentifier", this);
  }
  return getEvidence()->getEvidenceIdentifier()->getItemID(); 
}
/**
 * shortcut for getting source of activeevidence. Also provides a sanity check.
 */
string BaseAccessor::getEvidenceSourceID() const {
  
  checkValidEvidence();
  if (getEvidence()->getEvidenceIdentifier() == 0){

    throw OcfaException("No EvidenceIdentifier", this);
  }
  return getEvidence()->getEvidenceIdentifier()->getEvidenceSourceID(); 
}
/**
 * shortcut for getting evidenceid of activeevidence. Also provides a sanity check.
 */
string BaseAccessor::getEvidenceID() const {

  checkValidEvidence();
  if (getEvidence()->getEvidenceIdentifier() == 0){

    throw OcfaException("No EvidenceIdentifier", this);
  }
  return getEvidence()->getEvidenceIdentifier()->getEvidenceID(); 
}


/**
 * shortcut for getting caseid of evidence. also provide sanity check.
 * @TODO why not getCaseId instead of investigation.
 *
 */
string BaseAccessor::getInvestigationID() const {

  checkValidEvidence();
  if (getEvidence()->getEvidenceIdentifier() == 0){

    throw OcfaException("No EvidenceIdentifier", this);
  }
  return getEvidence()->getEvidenceIdentifier()->getCaseID();
}

/**
 *makes sure that if necessary messages can be handled from a central authority.
 * in the future message might be sent talking about the progress on the current evidence.
 *
 */
void BaseAccessor::aliveAndKicking(int , int , bool ){
  
}


string  BaseAccessor::getConfEntry(string inName){

  return OcfaConfig::Instance()->getValue(inName, this);
}

Scalar BaseAccessor::getEvidenceName() const {

  checkValidEvidence();
  return getEvidence()->getEvidenceName();
}

Scalar BaseAccessor::getEvidenceLocation() const {

  checkValidEvidence();
  return getEvidence()->getEvidencePath() + "/" 
    +  getEvidence()->getEvidenceName();
}

void BaseAccessor::run(){
  while (!mpStop){
    Message *msg = getMessageBox()->getNextMessage(Message::MIN_PRIORITY, 0);
    handleMessage(msg);
  }
}

string BaseAccessor::getDigestMD5() const {
  getLogStream(LOG_DEBUG) << "BaseAcessor:getDigestMD5(): checking valid evidence" << endl;

  checkValidEvidence();
  getLogStream(LOG_DEBUG) << "BaseAcessor:getDigestMD5(): returning md5" << endl;
  return getEvidence()->getDigestMD5();
}

string BaseAccessor::getDigestSHA1() const {

  getLogStream(LOG_DEBUG) << "BaseAcessor:getDigestSHA1(): checking valid evidence" << endl;
  checkValidEvidence();
  getLogStream(LOG_DEBUG) << "BaseAcessor:getDigestSHA1(): returning SHA1" << endl;
  return getEvidence()->getDigestSHA();

}


string BaseAccessor::getCase() const {

  getLogStream(LOG_DEBUG) << "BaseAcessor:getCase(): checking valid evidence" << endl;
  checkValidEvidence();
  getLogStream(LOG_DEBUG) << "BaseAcessor:getCase(): returning CaseName" << endl;
  return getEvidence()->getCase();

}

