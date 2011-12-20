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
						
#include<fstream>
#include<iostream>
#include <stdlib.h>
#include <SimpleConfig.hpp>
#include <OcfaObject.hpp>
#include <misc/OcfaException.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/algorithm/string.hpp>

namespace ocfa {
  namespace misc {
    SimpleConfig::SimpleConfig():OcfaConfig(),d_keyvalpairs(),mModuleName(""){
      updateTypeName("SimpleConfig");
      const char *envz = getenv("OCFACASE");
      const char *envc = getenv("OCFACONF");
      const char *envr = getenv("OCFAROOT");
      //OCFAROOT should be defined and exist
#ifdef DEFAULT_OCFAROOT
      if (envr==0) {
	 envr = DEFAULT_OCFAROOT ;
      }
#endif
      if (envr==0) {
         throw OcfaException("The essential envinronment variable OCFAROOT has not been set.");
      }
      if (! boost::filesystem::exists(envr)) {
         throw OcfaException(std::string("The directory ")+ envr + " designated by the OCFAROOT envinronment variable does not exist.");
      }
      d_keyvalpairs["ocfaroot"] = envr;
      //OCFACONF is depricated.
      if (envc != 0) {
          throw OcfaException("The usage of the envinronment variable OCFACONF is depricated");
      }
      //OCFACASE should be difined and should exist.
      if ((envz==0) || (envz[0]==0) || (envz[0]=='.')) {
          throw OcfaException("The essential envinronment variable OCFACASE has not been set.");
      }
      std::string ocfaetc=std::string("/var/ocfa/cases/") + envz + "/etc";
      if (! boost::filesystem::exists(ocfaetc)) {
          throw OcfaException(std::string("The directory ")+ ocfaetc + " does not exist. You may need to run createcase");
      }
      d_keyvalpairs["ocfaetc"] = ocfaetc;
      //Now open and process the main config file.
      string myconfname = ocfaetc + std::string("/ocfa.conf");
      ifstream *conf = new ifstream(myconfname.c_str());
      string line, name, value;
      if (!(conf->is_open())) {
	throw OcfaException("Could not open config file");
	return;
      }
      // loop through file
      bool empty = true;
      while (getline(*conf, line)) {
	empty = false;
	int l = line.length();
	if (l > 0) {
	  if (line[0] == '#') {
	    continue;
	  }
	  int i = line.find_first_of("=");
	  if ((i > 0) && (i < l - 1)) {	// the '=' should be somewhere in the middle of the line
	    name = line.substr(0, i);
	    value = line.substr(i + 1, line.length() - 1);
            boost::algorithm::replace_all(value,"$OCFAROOT",envr);
            boost::algorithm::replace_all(value,"$OCFAETC",ocfaetc);      
	    d_keyvalpairs[name] = value;
	  }
	}
      }
      if (empty) {
        delete conf;
	throw string("The config file was empty");
      }
      delete conf;
    }
    SimpleConfig::~SimpleConfig() {

    }
   

    string SimpleConfig::getValueByCaller(string name, OcfaObject *caller) const {
      map<string,string>::const_iterator p;
      if (caller != 0) {
	 string key=caller->getClassName() + ":" + name;
	 ocfaLog(LOG_DEBUG,"asking for " + key);
	 p=d_keyvalpairs.find(key);
	 if (p!=d_keyvalpairs.end())
		  return p->second;
      }
      return ""; // not found

    }
    
    string SimpleConfig::getValue(string name,OcfaObject *caller) const {
      map<string,string>::const_iterator p;
      if ((mModuleName !="") && (caller != 0)) {
          string key=mModuleName + ":" + caller->getClassName() + ":" + name;
	  ocfaLog(LOG_DEBUG,"asking for " + key);
	  p=d_keyvalpairs.find(key);
	  if (p!=d_keyvalpairs.end())
		  return p->second;
      }
      if (caller != 0) {
	 string key=caller->getClassName() + ":" + name;
	 ocfaLog(LOG_DEBUG,"asking for " + key);
	 p=d_keyvalpairs.find(key);
	 if (p!=d_keyvalpairs.end())
		  return p->second;
      }
      if (mModuleName != "") {
	string key=mModuleName + ":" + name;
	ocfaLog(LOG_DEBUG,"asking for " + key);
	p=d_keyvalpairs.find(key);
	if (p!=d_keyvalpairs.end())
		return p->second;
      }
      ocfaLog(LOG_DEBUG,"asking for " + name);
      p=d_keyvalpairs.find(name);
      if (p!=d_keyvalpairs.end()) {
        return p->second;
      }
      ocfaLog(LOG_NOTICE,name + " not found");
      return "";
    }
   void SimpleConfig::baptize(ModuleInstance *modinstance) {
      if (mModuleName == "") {
        mModuleName=modinstance->getModuleName();;
      } else {
        throw OcfaException("Can not baptize the config twice",this);
      }
   }
  }
}
