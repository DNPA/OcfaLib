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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <DomEvidence.hpp>
#include <defines.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <OcfaErrorHandler.hpp>
#include <sys/time.h>
#include <DomHelper.hpp>
using namespace xercesc;
using namespace std;
using namespace ocfa::misc;
namespace ocfa
{
  namespace evidence
  {
      void DomEvidence::initTimers() {
	struct itimerval itv;
	//Make the timer expire aproximately 60 years from now (what should not hapen for most runs).
	itv.it_interval.tv_sec=2147483647; //aprox 60 years
	itv.it_value.tv_sec=2147483647;    //aprox 60 years
	itv.it_interval.tv_usec=0;
	itv.it_value.tv_usec=0;
	if (setitimer(ITIMER_PROF,&itv,0) !=0) {
	   throw OcfaException("Problem setting interval timer for ITIMER_PROF in DomEvidence::initTimers",0);
	}
	return;
      }
      
      long long DomEvidence::getProfilingTimerVal() {
        struct itimerval itv;
        if (getitimer(ITIMER_PROF,&itv) != 0) {
          throw OcfaException("Problem fetching interval timer for ITIMER_PROF in DomEvidence::initTimers",0);
	}
	return 1000000*itv.it_value.tv_sec+itv.it_value.tv_usec;
      }
      
      long long DomEvidence::getRealTimerVal(){
	struct timeval itv;
	if (gettimeofday(&itv,0) != 0) {
           throw OcfaException("Problem fetching interval timer for ITIMER_REAL in DomEvidence::initTimers",0);
	}
	return 1000000*itv.tv_sec+itv.tv_usec;
      }
      
      misc::EvidenceIdentifier  	*DomEvidence::getEvidenceIdentifier() {
        if (!(mEvidenceIdentifier)) {
            mEvidenceIdentifier=new EvidenceIdentifier(getAttr("case"),getAttr("src"),getAttr("item"),getAttr("id"));
	}
	return mEvidenceIdentifier;
      }

      string DomEvidence::getCase() {
	return getAttr("case");
      }
      
      string DomEvidence::getDigestMD5() {
        return getAttr("md5");
      }
      
      string DomEvidence::getDigestSHA() {
        return getAttr("sha");
      }
      
      misc::Scalar 			DomEvidence::getEvidenceName() const{
	 if (mLocationDomNode == 0) throw OcfaException("getEvidenceName called with NULL mLocationDomNode",this);
	 return DomHelper::getInstance()->getAttribute(mLocationDomNode,"name");
      }
      
      misc::Scalar 			DomEvidence::getEvidencePath() const{
	 if (mLocationDomNode == 0) throw OcfaException("getEvidencePath called with NULL mLocationDomNode",this);
	 const XMLCh *xcontent=static_cast<const XMLCh *>( mLocationDomNode->getTextContent() );
	 char *tcontent=DomHelper::transcode(xcontent);
	 string content(tcontent);
	 XMLString::release(&tcontent);
	 Scalar cont(content);
         return cont;
      }
      
      size_t 				DomEvidence::getJobCount() const{
         return mJobCount;
      }
      
      size_t				DomEvidence::getParentCount() {
          size_t cnt=0;
	  size_t index;
	    
	  string id=this->getEvidenceIdentifier()->getEvidenceID();
	  size_t size=id.size();
	  for (index=0;index<size;index++) {
             if (id.c_str()[index]== '.') cnt++;
	  }
	  return cnt;
      }
      
      JobIterator 			*DomEvidence::getJobIterator(){
	if (mJit) {
           delete mJit;
	   mJit=0;
	}
        if (!(mJit)) {
	    ocfaLog(LOG_DEBUG,"Creating JobIterator without facade");
            mJit=new DomJobIterator(mDomJobs,getEvidenceIdentifier()->getCaseID());
	}
	return mJit;
      }
      
      void DomEvidence::setJobIterator(JobIterator **amJit){
          if (mJit) {
             delete mJit;
             mJit=0;
          }
	  mJit=*amJit;
      }
      
      ActiveJob 			*DomEvidence::getActiveJob(){
        if (!(mActiveJob)) {
              throw OcfaException("getActiveJob called on non mutable Evidence",this);
	}
	return mActiveJob;
      }
      
      misc::OcfaHandle 			*DomEvidence::getRawDataHandle() {
         return mDataHandle;
      }
      
      /** Get the MetaMemBuf representation of the Evidence */
      misc::MemBuf 			*DomEvidence::asMemBuf(){
	 
	 if (mActiveJob == 0) {
            throw OcfaException("No membuf available for non muted evidence",this);
	 }
	 if (mActiveJob->isClosed()== false) {
            throw OcfaException("No membuf available for active job that is not yet closed",this);
	 }
	 return DomTopNode::asMemBuf();
      }
      
      void 				DomEvidence::LLsetMutable(){
	 if (mActiveJob == 0) {
	     
	     DomActiveJob *dommActiveJob=new DomActiveJob(mDomJobs,getDOMDoc(),mModuleInstance,getEvidenceIdentifier()->getCaseID());
	     if (misc::OcfaConfig::Instance()->getValue("profiling",this) == "verbose") {
                long long preMutableProfileTime=mStartProfilingTimerVal - getProfilingTimerVal();
		long long preMutableRealTime=getRealTimerVal() - mStartRealTimerVal;
		dommActiveJob->setPreMutableTimes(preMutableRealTime,preMutableProfileTime);
	     }
	     if ((misc::OcfaConfig::Instance()->getValue("profiling",this) == "true")||
			     (misc::OcfaConfig::Instance()->getValue("profiling",this) == "verbose")){
                  dommActiveJob->setStartTimers(getRealTimerVal(),getProfilingTimerVal());
	     }
             if (mActiveJob) {
                delete mActiveJob;
             }
	     mActiveJob=dommActiveJob;
	 }
      }
      
      void                              DomEvidence::setMutable(){
	 ocfaLog(LOG_DEBUG,"setting evidence mutable");
	 size_t count=0;
	 LLsetMutable();
	 if (misc::OcfaConfig::Instance()->getValue("moduletwice",this) == "fail") {
	       
               JobIterator *mymJit=getJobIterator();
               if (mymJit == 0) {
			throw OcfaException("Unable to retreive JobIterator from DomEvidence in setMutable",this);
	       }
	       do {
	           misc::ModuleInstance *minst=mJit->getModuleInstance();
		   if ((minst->getModuleName() == mModuleInstance->getModuleName())&&(minst->getNameSpace() == mModuleInstance->getNameSpace())) {
		      count++;
                      if (count > 1) throw OcfaException("Module has seen this evidence before",this);
		   }
	       } while (mymJit->next());
	 }
      }
      
      DomEvidence::DomEvidence(OcfaHandle **evidenceDataHandle,misc::DigestPair *digests,
		      misc::Scalar& evidenceName,misc::Scalar& evidencePath,
		      misc::EvidenceIdentifier **evidenceid,
		      misc::ModuleInstance *minst):
	      DomTopNode("evidence"),
	      mJobCount(1),
	      mLocationDomNode(0),
	      mEvidenceIdentifier(*evidenceid),
	      mActiveJob(0),
	      mDataHandle(*evidenceDataHandle),
	      mModuleInstance(minst),
	      mStartProfilingTimerVal(getProfilingTimerVal()),
	      mStartRealTimerVal(getRealTimerVal()),
	      mDomJobs(0),
	      mJit(0)
      {
	   updateTypeName("DomEvidence");
	   ocfaLog(LOG_DEBUG,"Starting constructor");
	   *evidenceDataHandle=0;
	   *evidenceid=0;
           if (digests && (!mDataHandle))
		   throw OcfaException("digests provided to DomEvidence constructor, but mDataHandle is not",0);
	   if (mDataHandle && (!digests))
		   throw OcfaException("mDataHandle provided to DomEvidence constructor, but digests is not",0);
	   ocfaLog(LOG_DEBUG,"Setting some arguments");
           setAttr("case",mEvidenceIdentifier->getCaseID());
           setAttr("src",mEvidenceIdentifier->getEvidenceSourceID());
	   setAttr("item",mEvidenceIdentifier->getItemID());
	   setAttr("id",mEvidenceIdentifier->getEvidenceID());
	   if (mDataHandle){
	      setAttr("storeref",*mDataHandle);
	   } 

	   if (digests) {
		   ocfaLog(LOG_DEBUG,"Setting digest params");
		   setAttr("sha",digests->getSHA1());
		   setAttr("md5",digests->getMD5());
	   }
	   setAttr("status","NEW");
	   mLocationDomNode =0;
	   DomHelper::getInstance()->createElement(&mLocationDomNode,getDOMDoc(),"location");
           if (mLocationDomNode == 0) {
	     throw OcfaException("Unable to get the location element from the evidence meta XML",0);
           }
           getTopNode()->appendChild(mLocationDomNode);
	   DomHelper::getInstance()->setAttribute(mLocationDomNode,"name",evidenceName.asUTF8());
	   XMLCh *argval;
	   argval = DomHelper::transcode(evidencePath.asUTF8().c_str());
           //getTopNode()->appendChild(getDOMDoc()->createTextNode(argval));
	   mLocationDomNode->appendChild(getDOMDoc()->createTextNode(argval));
	   XMLString::release(&argval);
	   ocfaLog(LOG_DEBUG,"Adding job");
	   DOMElement *jobelement =0;
	   DomHelper::getInstance()->createElement(&jobelement,getDOMDoc(),"job");
           getTopNode()->appendChild(jobelement);
	   mDomJobs = DomHelper::getInstance()->getElementsByTagName(getTopNode(),"job");
	   if (mDomJobs->getLength() == 0) {
              throw OcfaException("No job found in evidence, this cant be right as we just added a new one.",this);
	   }
	   mJobCount=mDomJobs->getLength() - 1;
	   ocfaLog(LOG_DEBUG,"Done constructing");
      }
      DomEvidence::DomEvidence(misc::MemBuf *membuf,misc::OcfaHandle **evidenceDataHandle,misc::ModuleInstance *minst):
	      DomTopNode(membuf),
	      mJobCount(0),
	      mLocationDomNode(0),
	      mEvidenceIdentifier(0),
	      mActiveJob(0),
	      mDataHandle(0),
	      mModuleInstance(minst),
	      mStartProfilingTimerVal(getProfilingTimerVal()),
	      mStartRealTimerVal(getRealTimerVal()),
	      mDomJobs(0),
	      mJit(0)
      {
	   updateTypeName("DomEvidence");
	   if (evidenceDataHandle == 0) {                        
              throw OcfaException("Invalid evidence data handle pointer passed to DomEvidence constructor",0);
	   }
	   if (*evidenceDataHandle !=0) {                       
              throw OcfaException("Can not overwrite existing evidence data handle in DomEvidence constructor",0);
	   }
	   MemBufInputSource *inputsource=new MemBufInputSource(static_cast<const XMLByte*>(membuf->getPointer()),membuf->getSize(),"dummy");

	   
	   DOMNodeList *locations = DomHelper::getInstance()->getElementsByTagName(getTopNode(),"location");
           if (locations == 0) {
	             throw OcfaException("Constructor returned NULL for location elementlist",0);
	   }
	   XMLSize_t lsize = locations->getLength();
	   if (lsize > 0) {
		mLocationDomNode = dynamic_cast < DOMElement * >(locations->item(0));
	        if (mLocationDomNode == 0) {
	             throw OcfaException("Unable to cast location element from XML doc into a DOMElement",0);
												               
		}
	   }
	   mDomJobs = DomHelper::getInstance()->getElementsByTagName(getTopNode(),"job");
	   if (mDomJobs->getLength() == 0) {
	       throw OcfaException("No job found in evidence, membuf evidences should hold at least one job.",this);
	   }
	   mJobCount=mDomJobs->getLength() - 1;
	   delete inputsource;
	   std::string ssref =getAttr("storeref");          
	   if (ssref != "") {                           
              *evidenceDataHandle=new OcfaHandle(ssref); 
	      mDataHandle=new OcfaHandle(ssref);        
	   }                                   
	   return;
      } 
      DomEvidence::~DomEvidence(){
	 ocfaLog(LOG_DEBUG,"Starting destructor");
         if (mDataHandle) {delete mDataHandle;mDataHandle=0;}
	 ocfaLog(LOG_DEBUG,"mDataHandle processed");
	 if (mEvidenceIdentifier) {delete mEvidenceIdentifier;mEvidenceIdentifier=0;}
	 ocfaLog(LOG_DEBUG,"mEvidenceIdentifier processed");
	 if (mJit) {delete mJit;mJit=0;}
	 ocfaLog(LOG_DEBUG,"mJit processed");
	 if (mActiveJob) {delete mActiveJob;mActiveJob=0;}
	 ocfaLog(LOG_DEBUG,"mActiveJob processed");
      }
      xercesc::DOMNodeList * DomEvidence::getDomJobNodes() {
          return mDomJobs;
      }
  }
}
