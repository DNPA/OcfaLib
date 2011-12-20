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
						
#include"store/AbstractRepository.hpp"
#include <misc/PolicyLoader.hpp>
using namespace ocfa::misc;
namespace ocfa {

 namespace store {

   using namespace ocfa::misc;
   /**
    * singleton instance. 
    */
   AbstractRepository *AbstractRepository::_instance = 0;
 
   
   /**
    * Returns an instance of an abstract repository.
    * uses storeimpl to find the library to load, then calls createRepository from that 
    * library.
    * @param concrete repository. 
    */
   AbstractRepository* AbstractRepository::Instance(){
     
     if (_instance == 0){
	string repRoot;
	repRoot = OcfaConfig::Instance()->getValue("repository");
        std::string myLib=ocfa::misc::OcfaConfig::Instance()->getValue("storeimpl");
        if (myLib == "") {
           throw OcfaException("AbstractRepository::Instance : No config entry for 'repository' found",0);
        }
	//RJM:CODEREVIEW new templated construct for loading dynamic libraries
	typedef SinglePointerConstructor<AbstractRepository,const char>  CRepositoryType;
        PolicyLoader<CRepositoryType> pl(myLib,"createRepository");
	CRepositoryType *constructor=pl.constructor();
        _instance = (*constructor)(repRoot.c_str());

	//      RJM:CODEREVIEW the folowing commented code is all replaced by the abouve.       
//      string concreteRepository;
//      AbstractRepository *(*constructor)(const char *);  RJM:CODEREVIEW
//      concreteRepository = OcfaConfig::Instance()->getValue("storeimpl");
//      OcfaLogger::Instance()->syslog(LOG_DEBUG, "store.abstractrepository") 
//	<< "repository root is " << repRoot << endl;
//     if (concreteRepository == ""){	
//	throw OcfaException("cannot initialize Repository no library given");
//      }
//      string slibfile = concreteRepository + ".so";
//      OcfaLogger::Instance()->syslog(LOG_DEBUG, "store.abstractrepository")
//	<< "slibfile is " << slibfile << endl;
//      void *handle = dlopen(slibfile.c_str(),RTLD_NOW | RTLD_GLOBAL);
//      if (handle == 0){
//	
//	printf("dlopen: %s", dlerror());
//	throw OcfaException("Cannot open libfile " + slibfile);    
//      }
//#ifndef VOID_FP_CAST_WORKAROUND
//      constructor = reinterpret_cast<AbstractRepository*(*)(const char *)>(dlsym(handle, "createRepository"));
//#else
//      constructor = reinterpret_cast<AbstractRepository*(*)(const char *)>(reinterpret_cast<int>(dlsym(handle, "createRepository")));
//#endif
//      if (constructor == 0){
//	printf("dlsym: %s", dlerror());
//	throw OcfaException("Cannot find repository constructor in " + slibfile);
//      }
//      
//      _instance = (*constructor)(repRoot.c_str());

     }
     return _instance;
   }
   
 }
}
