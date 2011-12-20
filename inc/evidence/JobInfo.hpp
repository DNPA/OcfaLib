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
						
#ifndef _OCFA_JOBINFO_
#define _OCFA_JOBINFO_
#include "../OcfaObject.hpp"
#include <string>
namespace ocfa {
	namespace evidence {
		//This helperclass for ExtendableEvidence and the creation of new jobs
		//holds the submitflag and the arguments of the new to be created
		//job. 
		class JobInfo:public OcfaObject {
			public :
				//Constructor, specifying the submit flag.
				JobInfo(int submitflag);
				//Add a named argument to the JobInfo
				void addArgument(std::string name,std::string val);
				//get the submitflag of the JobInfo 
				int getSubmitFlag() const;
				//get an argumentmap for the arguments of the JobInfo
				std::map <std::string , std::string > *getArguments();
			private:
				std::map <std::string , std::string > mArguments;
				int mSubmitflag;
		};
	}
}
#endif
