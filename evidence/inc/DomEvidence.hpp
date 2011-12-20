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
						
#ifndef __OCFADOMEVIDENCE_
#define __OCFADOMEVIDENCE_
#include <string>
#include <misc.hpp>
#include <DomTopNode.hpp>
#include <DomJobIterator.hpp>
#include <DomActiveJob.hpp>
#include <OcfaErrorHandler.hpp>
#include <evidence/Evidence.hpp>
#include <OcfaObject.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/sax/ErrorHandler.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
namespace ocfa {
  namespace evidence {

    class DomEvidence:public DomTopNode,virtual public Evidence {
    public:
      //Documented in Evidence.hpp
      misc::EvidenceIdentifier * getEvidenceIdentifier();
      misc::Scalar getEvidenceName() const;
      misc::Scalar getEvidencePath() const;
      size_t getJobCount() const;
      size_t getParentCount();
      JobIterator *getJobIterator();
      ActiveJob *getActiveJob();
      misc::OcfaHandle * getRawDataHandle();
      /** Get the MetaMemBuf representation of the Evidence */
      misc::MemBuf * asMemBuf();
      void setMutable();
      string getDigestMD5();
      string getDigestSHA();
      string getCase();
    public:			//Implementation public methods not part of the baseclass interface
        /**
	 * Constructor to create a completely new DomEvidence derived from an other existing evidence
	 * @evidenceDataHandle : The handle the repository uses to access the evidence data for this evidence.
	 * @digests : The digestpair as created by the store library for the evidence data.
	 * @evidenceName : The name to give to the new evidence.
	 * @evidencePath : The human readable pseudo path where the evidence could be thought of to reside.
	 * @evidenceid : The evidence id to identify this evidence.
	 * @myModinstance : The ModuleInstance of the process used to tag new jobs with.
	 */
         DomEvidence(misc::OcfaHandle ** evidenceDataHandle,
		    misc::DigestPair * digests, misc::Scalar & evidenceName,
		    misc::Scalar & evidencePath,
		    misc::EvidenceIdentifier **evidenceid,
		    misc::ModuleInstance *myModinstance);
	/**
	 * Constructor to reconstruct an evidence from a membuf.
	 * @evidenceDataHandle : handle that can be used to extract the evidence data from the repository.
	 * @membuf : membuf containing the evidence xml.
	 * @myModinstance : The ModuleInstance of the process used to tag new jobs with.
	 */ 
        DomEvidence(misc::MemBuf * membuf,
		    misc::OcfaHandle ** evidenceDataHandle,
		    misc::ModuleInstance *myModinstance);
	/*
	 * A forbidden to use copy constructor
	 */
	DomEvidence(const DomEvidence& de):Evidence(de),DomTopNode(de),mJobCount(0),mLocationDomNode(0),mEvidenceIdentifier(0),mActiveJob(0),mDataHandle(0),mModuleInstance(0),mStartProfilingTimerVal(0),mStartRealTimerVal(0),mDomJobs(0),mJit(0) {
				throw misc::OcfaException("Copying of DomEvidence not allowed",this);
			}
       virtual ~DomEvidence();
       /*
	* The forbidden to use copying asignment operator
	*/
       const DomEvidence& operator=(const DomEvidence&) {
          throw misc::OcfaException("Assignment of DomEvidence not allowed",this);
	  return *this;
       }
    private:
      //members
      size_t                           mJobCount;           //number of jobs in the evidence
      xercesc::DOMElement            * mLocationDomNode;    //The DOM node of the location XML tag
      misc::EvidenceIdentifier       * mEvidenceIdentifier; //Unique composite id for this evidence.
      ActiveJob                      * mActiveJob;          //The job that is currently being worked on.
      misc::OcfaHandle               * mDataHandle;         //The store handle of the evidence data
      misc::ModuleInstance           * mModuleInstance;     //the process its module instance
      long long                        mStartProfilingTimerVal; //used for profiling.
      long long                        mStartRealTimerVal;  //used for profiling.
      xercesc::DOMNodeList           * mDomJobs;            //List with the DOM job nodes. 
      JobIterator                    * mJit;                //Iterator for iterating over the jobs.
    protected:
      xercesc::DOMNodeList * getDomJobNodes();   
      void LLsetMutable();                    //Set the evidence as mutable
      void setJobIterator(JobIterator **jit);
    public:  
      //Static profiling methods
      static void initTimers();
      static long long getProfilingTimerVal();
      static long long getRealTimerVal();
    };
}}
#endif
