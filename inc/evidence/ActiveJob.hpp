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
						
#ifndef __OCFAACTIVEJOB_
#define __OCFAACTIVEJOB_
#include <string>
#include "../misc.hpp"
#include "commit_type.hpp"
#include <misc/MetaValue.hpp>
namespace ocfa {
	namespace evidence {
	  /* The active job, as available truegh Evidence::getActiveEvidence() 
	   * Represents the job of the Evidence that is currently being processed by the module
	   * */
	  class ActiveJob {
		  public:
			  //Fetch an argument (as set by the router) by its name.
			  virtual std::string getArgument(std::string name)=0;
			  //Add a named MetaValue to the activejob its XML representation.
			  virtual void setMeta(std::string name,misc::MetaValue *val)=0;
			  //(Conditionaly) ad a logline to the xml representation of the activejob,
			  //dependent on the configured and suplied loglevel
			  virtual void addLogLine(misc::syslog_level level, std::string line)=0;
			  //Mark the job as completely done, no mor log info or meta will be added later on.
			  virtual void close()=0;
			  //Check if the job has been closed
			  virtual bool isClosed() const=0;
			  //Fetch the number of the child evidences that have been derived thusfar from the current
			  //evidence within the ActiveJob
			  virtual size_t getChildCount() const=0;
			  //Check if there are any child evidences that have been derived thusfar from the current
			  //evidence within the ActiveJob
			  virtual bool hasChildren() const=0;
			  virtual commit_type getCommitFlag()=0;
			  //
			  virtual ~ActiveJob(){};
	  };
	}
}
#endif
