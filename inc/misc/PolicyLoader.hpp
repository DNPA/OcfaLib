#ifndef _POLICY_LOADER_HPP
#define _POLICY_LOADER_HPP
#include <dlfcn.h>
#include <string>
#include <OcfaObject.hpp>
#include <misc/VoidToFunction.hpp>
#include <misc/OcfaConfig.hpp>
#include <misc/OcfaException.hpp>
template <class TConstructor>
class PolicyLoader: public ocfa::OcfaObject {
  public:
	PolicyLoader(std::string myLib,std::string loadername):ocfa::OcfaObject("PolicyLoader","misc"),mLibHandle(0),mConstructor(0) {
           getLogStream(ocfa::misc::LOG_DEBUG) << "myLib='" << myLib << "'" << std::endl;
	   if (myLib.c_str()[0] != '/') {
	      getLogStream(ocfa::misc::LOG_DEBUG) << "No absolute path given" << std::endl;
	       std::string libpath=ocfa::misc::OcfaConfig::Instance()->getValue("ocfaroot");
	       
	       libpath += std::string("/lib/");
	       if (myLib.substr(0,3) != "lib") {
                  libpath += "lib";
		  libpath += myLib;
		  libpath += ".so";
		  getLogStream(ocfa::misc::LOG_DEBUG) << "Rewritten libpath to: '" << libpath << "'" << std::endl;
	       } else {
	          libpath += myLib;
		  getLogStream(ocfa::misc::LOG_DEBUG) << "Appended myLib to libpath. libpath now: '" << libpath << "'" << std::endl;
	       }
	       myLib=libpath;
	   } else {
             getLogStream(ocfa::misc::LOG_DEBUG) << "myLib unchanged" << std::endl;
	   }
	   getLogStream(ocfa::misc::LOG_DEBUG) << "Patched myLib='" << myLib << "'" << std::endl;
	   mLibHandle=dlopen(myLib.c_str(),RTLD_NOW|RTLD_GLOBAL);
	   if (mLibHandle == 0) {
              throw ocfa::misc::OcfaException( std::string("Problem loading library '") + 
			                 myLib + 
					 std::string("' (") + 
					 std::string(dlerror()) + 
					 std::string(")")
					 ,this);
	   }
	   mConstructor = VoidToFunction<TConstructor>::cast(dlsym(mLibHandle,loadername.c_str()));
	   if (mConstructor == 0) {
	      std::string errString=std::string("Problem looking up symbol '") + loadername + std::string("' in library '")  + 
		      myLib + std::string("' (") + std::string(dlerror()) + std::string(")");
              dlclose(mLibHandle);
	      throw ocfa::misc::OcfaException(errString,this);
	   }
	   getLogStream(ocfa::misc::LOG_NOTICE) << "Successfully loaded " <<  myLib << " (handle=" << mLibHandle << ")" << std::endl; 
	}
	~PolicyLoader() {
	   delete mConstructor;
	}
	void closeLib() {
	   if (mLibHandle) {
	      getLogStream(ocfa::misc::LOG_NOTICE) << "Closing opened library. (handle=" <<  mLibHandle << ")" << std::endl;  
              dlclose(mLibHandle);
	   }
	   mLibHandle=0;
	}
	TConstructor *constructor() {
           return mConstructor;
	}
  private:
	void *mLibHandle;
	TConstructor *mConstructor;
};

#endif
