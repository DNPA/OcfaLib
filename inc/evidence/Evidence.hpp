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
						
#ifndef __OCFAEVIDENCE_
#define __OCFAEVIDENCE_
#include <string>
#include "../misc.hpp"
#include "JobIterator.hpp"
#include "ActiveJob.hpp"
namespace ocfa {
	namespace evidence {
          //The Evidence class is the API representation of the XML representation of a single
	  //evidence data BLOB, and all actions done and all metadata that were added to it
	  //by different modules.
	  class Evidence{
		  public:
			  //get the EvidenceIdentifier that uniquely identifies the Evidence.
			  virtual misc::EvidenceIdentifier	*getEvidenceIdentifier()=0;
			  //get the original name of the evidence
			  virtual misc::Scalar			getEvidenceName() const=0;
			  //get the path of the evidence with respect to the evidence item it came from
			  virtual misc::Scalar			getEvidencePath() const=0;
			  //get the number of jobs, including the current one that were added to
			  //the Evidence thusfar.
			  virtual size_t			getJobCount() const=0;
			  //get the number of parents that have been there from the item to this Evidence
			  //(not counting coparents)
			  virtual size_t			getParentCount()=0;
			  //get and (re)initialize an Iterator to iterate over all the Evidence its jobs. 
			  virtual JobIterator			*getJobIterator()=0;
			  //The ActiveJob of the Evidence.
			  virtual ActiveJob			*getActiveJob()=0;
			  //get the handle for the store subsytem of the raw data belonging to the Evidence
			  virtual misc::OcfaHandle    		*getRawDataHandle() = 0;
			  /** Get the MetaMemBuf representation of the Evidence */
			  virtual misc::MemBuf			*asMemBuf()=0;
			  //set the evidence as being mutable, this will set a starttime for the active job,
			  //and will add the module its ModuleInstance info inside the XML representation of
			  //the active job.
			  virtual void				setMutable()=0;
			  //Fetch the MD5 digest of the raw data belonging to the Evidence
			  virtual string			getDigestMD5()=0;
			  //Fetch the SHA1 digest of the raw data belonging to the Evidence
			  virtual string			getDigestSHA()=0;
			  //Fetch the CaseName belonging to the Evidence
			  virtual string			getCase()=0;
			  virtual ~Evidence() {};
	  };
	}
}
#endif
