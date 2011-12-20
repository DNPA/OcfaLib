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
						
#include <DomExtendableEvidence.hpp>
#include <defines.hpp>
#include <xercesc/util/XMLString.hpp>
#include <DomHelper.hpp>
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    void DomExtendableEvidence::addNewJob(JobInfo * jobinfo) {
      if (mIsMutable) {
	if (mJobCount > 1) {
	  throw OcfaException("Trying to add more than one active job", this);
	};
	if (!(jobinfo)) {
	  throw OcfaException ("addNewJob called on mutable job with jobinfo==NULL", this);
	};
      }
      else {
	if (mJobCount > 0) {
	  throw OcfaException ("Trying to second new evidence without first setting the first one as mutable", this);
	}
	if (jobinfo) {
	  throw OcfaException ("addNewJob called on to be activated job with jobinfo!=NULL", this);
	}
      }
      DOMElement *jobelement =0;
      DomHelper::getInstance()->createElement(&jobelement,getDOMDoc(),"job");
      getTopNode()->appendChild(jobelement);
      if (jobinfo) {
	map < string, string > *arguments = jobinfo->getArguments();
	map < string, string >::const_iterator p;
	for (p = arguments->begin(); p != arguments->end(); ++p) {
	  string name = p->first;
	  string value = p->second;
	  DOMElement *argument=0;
          DomHelper::getInstance()->createElement(&argument,getDOMDoc(),"argument");
	  DomHelper::getInstance()->setAttribute(argument,"name",name);
	  XMLCh *aval=DomHelper::transcode(value.c_str());
	  argument->appendChild(getDOMDoc()->createTextNode(aval));
	  XMLString::release(&aval);
          jobelement->appendChild(argument);
	}
	//JBS removed this one. Jobinfo is a pointer and should not be deleted.
	// delete jobinfo;
      }
      mJobCount++;
    }
    void DomExtendableEvidence::setMutable() {
      if (mJobCount != 1) {
	throw OcfaException ("setMutable called while the number of new jobs added not equal to one.", this);
      }
      mIsMutable = true; 
      DomEvidence::LLsetMutable();
    }
  DomExtendableEvidence::DomExtendableEvidence(misc::MemBuf * membuf, misc::OcfaHandle ** evidenceDataHandle,misc::ModuleInstance *minst):
	  DomEvidence(membuf,evidenceDataHandle,minst),
	  mGlobalMetaFacade(false),
	  mJobCount(0),
	  mIsMutable(false),
	  mRuleDomNode(0),
	  mRule(0)
    {
      updateTypeName("DomExtendableEvidence");

/* FIVES-PH: next rule */
      DOMNodeList *nextrules = DomHelper::getInstance()->getElementsByTagName(getTopNode(),"nextrule");
      XMLSize_t nextrulesize = nextrules->getLength();

      if (nextrulesize == 0){
            //does not exist -> create
            DomHelper::getInstance()->createElement(&mRuleDomNode,getDOMDoc(),"nextrule");
            if (mRuleDomNode == 0) {
                  throw OcfaException("Unable to get the nextrule element from the evidence meta XML", this);
            }
            //Add nextrule just before all the job information, the order in the XML document is important
            DOMNodeList *jobs = DomHelper::getInstance()->getElementsByTagName(getTopNode(),"job");
            getTopNode()->insertBefore(mRuleDomNode, jobs->item(0));
            XMLCh *argval = DomHelper::transcode("0"); //start at rule 0
            mRuleDomNode->appendChild(getDOMDoc()->createTextNode(argval));
            XMLString::release(&argval);
      }else if (nextrulesize > 0) {
            mRuleDomNode = dynamic_cast < DOMElement * >(nextrules->item(0));
            if (mRuleDomNode == 0) {
                  throw OcfaException("Unable to cast nextrule element from XML doc into a DOMElement", this);
            }
      }

      if (mRuleDomNode == 0) 
            throw OcfaException("mRuleDomNode is NULL",this);

      const XMLCh *xcontent=static_cast<const XMLCh *>( mRuleDomNode->getTextContent() );
      char *tcontent=DomHelper::transcode(xcontent);
      string content(tcontent);
      Scalar cont(content);
      setRuleNumber (cont.asInt()); /* what about unsignedness? */
      XMLString::release(&tcontent);
    }
  
  DomExtendableEvidence::~DomExtendableEvidence() {
  }
  void DomExtendableEvidence::setGlobalMetaFacades(bool val){
           mGlobalMetaFacade=val;
           ocfaLog(LOG_DEBUG,"facade set for evidence");
  }
  JobIterator  *DomExtendableEvidence::getJobIterator(){
       JobIterator  *tmpjit=0;
       if (mGlobalMetaFacade) {
                  ocfaLog(LOG_DEBUG,"Creating JobIterator with facade");
                  tmpjit=new DomJobIterator(getDomJobNodes(),getEvidenceIdentifier()->getCaseID(),this);
       } else {
                  ocfaLog(LOG_DEBUG,"Creating JobIterator without facade");
                  tmpjit=new DomJobIterator(getDomJobNodes(),getEvidenceIdentifier()->getCaseID());
       }
       setJobIterator(&tmpjit);
       return tmpjit;
   }

/*FIVES-PH: */
/** Get the MetaMemBuf representation of the Evidence */
      misc::MemBuf *DomExtendableEvidence::asMemBuf(){
         /* FIVES-PH: update rule  with info about 'Next Rule' */
         DOMNodeList *nextrules = DomHelper::getInstance()->getElementsByTagName(getTopNode(),"nextrule");
         if (nextrules == 0) {
               throw OcfaException("Constructor returned NULL for nextrule elementlist",this);
         }
         XMLSize_t nextrulesize = nextrules->getLength();
         if (nextrulesize > 0) {
               mRuleDomNode = dynamic_cast < DOMElement * >(nextrules->item(0));
               if (mRuleDomNode == 0) {
                       throw OcfaException("Unable to cast nextrule element from XML doc into a DOMElement",this);
                }
         }
         XMLCh *argval;
         argval = DomHelper::transcode(Scalar(getRuleNumber()).asUTF8().c_str());
         mRuleDomNode->setTextContent(argval);
         XMLString::release(&argval);

         if (getActiveJob() == 0 /*mActiveJob == 0*/) {
            throw OcfaException("No membuf available for non muted evidence",this);
         }
         if (getActiveJob()->isClosed()== false /*mActiveJob->isClosed()== false*/) {
            throw OcfaException("No membuf available for active job that is not yet closed",this);
         }

         return DomTopNode::asMemBuf();
      }
	




  void DomExtendableEvidence::setRuleNumber(unsigned int rulenum){
	mRule = rulenum;
  }

  unsigned int DomExtendableEvidence::getRuleNumber(){
	return mRule;
  }
  }
}
