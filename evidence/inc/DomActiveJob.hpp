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
						
#ifndef _DOMACTIVEJOB_
#define _DOMACTIVEJOB_
#include <misc.hpp>
#include <evidence/ActiveJob.hpp>
#include <OcfaObject.hpp>
#include <evidence/ArgumentIterator.hpp>
#include <evidence/CoParent.hpp>
#include <evidence/commit_type.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMElement.hpp>
#include <map>
#include <string>
namespace ocfa {
  namespace evidence {
    class DomActiveJob:public OcfaObject, public ActiveJob {
    public:
      DomActiveJob(xercesc::DOMNodeList * nl, xercesc::DOMDocument * ddoc,
		   misc::ModuleInstance * minst, std::string caseid);
      DomActiveJob(const DomActiveJob &);
      const DomActiveJob& operator=(const DomActiveJob&) {
         throw misc::OcfaException("No assgnment of DomActiveJob allowed",this);
	 return *this;
      }
       ~DomActiveJob();
	    /** Add a reference to a derived (child) evidence, optionaly identifying a set of coparents of that evidence */
      void addChildRef(std::string childref, std::string relname,
		       const std::vector < CoParent > *coparents,
		       misc::Scalar childname);
	    /** get a named argument from the active job */
        std::string getArgument(std::string name);
	    /** Create an empty  named metadata of the 'scalar' type within the active job */
      void setMeta(std::string name, misc::MetaValue * val);
	    /** Add logging information to the active job using an ostream interface*/
      ostream & evidenceSyslog(misc::syslog_level level);
	    /** Add logging information to the active job using a low-level line oriented interface*/
      void addLogLine(misc::syslog_level level, std::string line);
	    /** Retreive the Commit Flag of the active job **/
      commit_type getCommitFlag();
	    /** Set the end time and status of the job, so it becomes valid output */
      void close();
      size_t getChildCount() const;
      bool isClosed() const;
      bool hasChildren() const;
      void setPreMutableTimes(long long real,long long prof);
      void setStartTimers(long long realstart,long long profstart);
    private:
      void setMetaLL(std::string name, misc::ScalarMetaValue * val);
      void setMetaLL(std::string name, misc::ArrayMetaValue * val);
      void setMetaLL(std::string name, misc::TableMetaValue * val);
      void createTableMeta(std::string n, std::vector < string > *fn);
      void setMeta(std::string name, misc::Scalar s);
      void pushBackMeta(std::string name, misc::Scalar s);
	    /** Add a reference to a derived (child) evidence, optionaly identifying a set of coparents of that evidence */
      xercesc::DOMElement * jdomelement;
      xercesc::DOMDocument * domdoc;
      misc::syslog_level minlevel;
      std::map < std::string, std::string > argmap;
      std::string mCaseID;
      size_t mChildCount;
      long long mProfstart;
      long long mRealstart;
      bool mClosed;
    };
}}
#endif
