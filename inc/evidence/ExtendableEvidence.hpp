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
						
#ifndef __OCFAEXTENDABLEEVIDENCE_
#define __OCFAEXTENDABLEEVIDENCE_
#include <string>
#include "../misc.hpp"
#include "Evidence.hpp"
#include "JobInfo.hpp"
namespace ocfa {
	namespace evidence {
	  /* This derived class of Evidence , as created also by the EvidenceFactory, is the type
	   * of evidence as used by a router. Other than normal modules, he router will add new jobs
	   * to an evidence, its own new ActiveJob, and a new job targeted at the next module.
	   * */
	  class ExtendableEvidence:virtual public Evidence {
		  public:
			 //Add a new job to the Evidence
			 virtual void addNewJob(JobInfo *jobinfo)=0;
			 //Set up two facades for the first and for the last job of the evidence,
			 //as to allow access to global metadata truegh the scope of the JobIterators.
			 virtual void setGlobalMetaFacades(bool val=true)=0; 
			 virtual ~ExtendableEvidence() {};

/* FIVES-PH: */
			 virtual void setRuleNumber(unsigned int rulenum) = 0;
			 virtual unsigned int getRuleNumber() = 0;
	  };
	}
}
#endif
