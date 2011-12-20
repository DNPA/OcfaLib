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
						
#ifndef _DOMJOBITERATOR_HPP
#define _DOMJOBITERATOR_HPP
#include <misc.hpp>
#include <string>
#include <DomOcfaIterator.hpp>
#include <evidence/JobIterator.hpp>
#include <evidence/Evidence.hpp>
#include <xercesc/dom/DOMNodeList.hpp>

using namespace std;
//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better
namespace ocfa {
  namespace evidence {
    /**OcfaIterator class used to iterate over Jobs within an Evidence */
    class DomJobIterator:public JobIterator, public DomOcfaIterator {
    public:
      DomJobIterator(const xercesc::DOMNodeList * jobnodes,
		     std::string caseid,Evidence *facadeevidence=0);
      DomJobIterator(const DomJobIterator& dji):OcfaIterator(dji),JobIterator(dji),DomOcfaIterator(dji),st(0),et(0),mi(0),cit(0),lit(0),mit(0),ait(0),mCaseID(""),mFacadeevidence(0) {
	      throw misc::OcfaException("No copying allowed for DomJobIterator",this);
      }
       virtual ~DomJobIterator();
       const DomJobIterator& operator=(const DomJobIterator&) {
             throw misc::OcfaException("No assignment allowed for DomJobIterator",this);
	     return *this;
       }
      /**Get the MetaIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      MetaIterator *getMetaIterator();
      /**Get the LogIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      LogIterator *getLogIterator();
      /**Get the ChildIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      ChildIterator *getChildIterator();
      /**Get the ArgumentIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      ArgumentIterator *getArgumentIterator();
      /**Get the msg::ModuleInstance of the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
        misc::ModuleInstance * getModuleInstance();
      /**Get the module its starrtime of the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      misc::DateTime *getStartTime();
      /**Get the module its endtime of the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      misc::DateTime *getEndTime();
      /**Check if the status of the current job is DONE (not NEW or PROCESSED) */
      bool isDone() const;
      /**Check if the status of the current job id PROCESSED (not NEW or DONE) */
      bool isProcessed() const;
      /**Set the status of a currently PROCESSED job to DONE
       *
       * A module will after processing a job set its status to PROCESSED. The router
       * will process the metadata of all PROCESSED jobs and set them to DONE.
       * Other modules with iterator access should NOT use this method !!*/
      void setDone();
      virtual bool next();
      virtual void last();
    private:
      misc::DateTime * st;
      misc::DateTime *et;
      misc::ModuleInstance * mi;
      ChildIterator *cit;
      LogIterator *lit;
      MetaIterator *mit;
      ArgumentIterator *ait;
      std::string mCaseID;
      Evidence *mFacadeevidence;
    };
}}
#endif
