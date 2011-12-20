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
						
#include <misc/OcfaGroup.hpp>
#include <misc/OcfaException.hpp>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
using namespace std;
namespace ocfa {
	namespace misc {
             OcfaGroup::OcfaGroup(std::string groupname):OcfaObject("OcfaGroup","ocfa") {
                 gid_t *grouplist;
		 int nogroups;
		 long ngroups_max;
		 struct group *ocfagr=getgrnam(groupname.c_str());
		 if (ocfagr == 0) {
		     throw OcfaException(string("required group is not defined:")+groupname,this);
		     return;
		 }
		 getLogStream(LOG_INFO) << groupname << " has id " << ocfagr->gr_gid << "\n";
		 gid_t mygroup=ocfagr->gr_gid;
		 ngroups_max = sysconf(_SC_NGROUPS_MAX)+1;
		 grouplist=static_cast<gid_t *>(malloc(ngroups_max * sizeof(gid_t)));
		 nogroups=getgroups(ngroups_max,grouplist);
		 for (long index=0;index < nogroups;index++) {
		    getLogStream(LOG_INFO) << "membership of " << grouplist[index] << "\n";
                    if (grouplist[index] == mygroup) {
			getLogStream(LOG_NOTICE) << "membership of " << groupname << " confirmed \n";
			if (getegid() == mygroup) {
                             getLogStream(LOG_NOTICE) << "running with egid of " << groupname << " confirmed \n";
                             free(grouplist);
                             return;
			} else {
                             getLogStream(LOG_ERR) << "not running with egid of " << groupname << "\n";
                             free(grouplist);
			     throw OcfaException(string("We are not running with the egid of the required group ")+groupname,this);
			     return;
			}
		    } else {
                       getLogStream(LOG_DEBUG) << "no match between group " << mygroup << " and " << grouplist[index] << "\n";
		    }
		 }
                 free(grouplist);
		 getLogStream(LOG_ERR) << "All group memberships processed and no matches found.\n";
		 throw OcfaException(string("We are not a member of the required group:")+groupname,this);
		 return;
	     }
	}
}
