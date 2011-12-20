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
						
#ifndef _DOMROUTEREVIDENCE_
#define _DOMROUTERECIDENCE_
#include <evidence/ExtendableEvidence.hpp>
#include <DomEvidence.hpp>
namespace ocfa {
  namespace evidence {
    class DomExtendableEvidence:public ExtendableEvidence, public DomEvidence {
    public:
      void addNewJob(JobInfo * jobinfo);
      void setMutable();
      JobIterator *getJobIterator();
      void setGlobalMetaFacades(bool val);
		void setRuleNumber(unsigned int rulenum);
		unsigned int getRuleNumber();
    public:
        DomExtendableEvidence(misc::MemBuf * membuf,
			      misc::OcfaHandle ** evidenceDataHandle,
			      misc::ModuleInstance *mModinstance);
       ~DomExtendableEvidence();
       DomExtendableEvidence(const DomExtendableEvidence& dee):Evidence(dee),ExtendableEvidence(dee),DomEvidence(dee),mGlobalMetaFacade(false),mJobCount(0),mIsMutable(false), mRuleDomNode(0) {
           throw misc::OcfaException("No copying allowed for DomExtendableEvidence",this);
       }
       const DomExtendableEvidence& operator=(const DomExtendableEvidence&) {
           throw misc::OcfaException("No assignment allowed for DomExtendableEvidence",this);
	   return *this;
       }

       misc::MemBuf *asMemBuf();

    private:
      bool   mGlobalMetaFacade;
      size_t mJobCount;
      bool   mIsMutable;

      /* FIVES-RM: Moved this away from abstract class*/
      unsigned int mRule;
      /* FIVES-PH: The DOM node for the last rule matched */
      xercesc::DOMElement            * mRuleDomNode;
    };
}}
#endif
