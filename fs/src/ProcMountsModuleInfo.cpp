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
						
#define __USE_FILE_OFFSET64
#include "ProcMountsModuleInfo.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <dlfcn.h>
using namespace ocfa::misc;
namespace ocfa {
  namespace fs {

    std::map < std::string, std::string > ProcMountsModuleInfo::mCharsetMap;
    std::map < std::string, std::string > ProcMountsModuleInfo::mFileSystemClassMap;
    misc::Scalar ProcMountsModuleInfo::mValidPathRegex="bogus";

    /**
     * JBS pretty long method here. I chunked it
     */
    ProcMountsModuleInfo::ProcMountsModuleInfo(std::string path, std::string charset) {
       //If not previously initialized, initilaize the lookup maps.
      
       if (mFileSystemClassMap.size()==0) {
	 initializeLookupMaps();
	 //Also look if we should update our  mValidPathRegex.
         std::string valpathregex=misc::OcfaConfig::Instance()->getValue("validpathregex");
	 if (valpathregex == "") 
	    throw OcfaException("No validpathregex entry found in config file");
         mValidPathRegex=valpathregex;
       }
       //Delete any active  selected filesystem.
       MountInfo theMountInfo;
       struct stat sres;
       if (lstat(path.c_str(), &sres) == -1) {
	  throw OcfaException("Could not stat " + path + " in ProcMountsModuleInfo constructor", 0);
       }
       //Save the device number that we are going to look up
       theMountInfo.pathdev = sres.st_dev;
       //Open the /proc/mounts to locate the mountpoint and identify the fs type and the mountflags.
       std::ifstream * mountsfile = new std::ifstream("/proc/mounts");
       if (!(mountsfile->is_open())) {
            throw OcfaException("Could not open /proc/mounts file to determine filesystem type and mount flags in ProcMountsModuleInfo constructor",0);
       }
       std::string line;
       bool devfound=false;
       
       while (getline(*mountsfile, line)) {
           misc::Scalar lines=line;
	   if (mValidPathRegex[line]) {
		//tokenise the line using spaces as seperator

		std::vector < std::string > tokens;
		stringstream ss(line);
		string buf;
                while (ss >> buf) {
	            tokens.push_back(buf);
		}
               if (stat(tokens[1].c_str(),&sres) == -1) {
		       ocfa::misc::OcfaLogger::Instance()->syslog(LOG_NOTICE, "ProcMountsModuleInfo ") << "Could not stat " << tokens[1] <<" (from /proc/mounts)" << endl;
	       }
	       //Check to see if this line is our match
	       else if (theMountInfo.pathdev == sres.st_dev) {
		 devfound=true;
		 getInfoFromMountOptions(tokens, theMountInfo);
	       }
	   }
       }
       delete mountsfile;
       //Throw an exception if the device is not located in /proc/mounts
       if (devfound == false) {
          throw OcfaException("Unable to locate the entry for " + path + " in /proc/mounts during ProcMountsModuleInfo construction.",0);
       }
       //Lookup the most suitable charset to use.
       string mycharset="";
       bool isroot=!geteuid();
       mycharset = determineCharsetToUse(theMountInfo, charset, isroot);
       ocfa::misc::OcfaLogger::Instance()->syslog(LOG_NOTICE, "ProcMountsModuleInfo ") << "Using charset " << mycharset << "\n";

       //Lookup the most suitable class to handle the identified filesystem type.
       if (isroot) {
 	 mModuleName=misc::OcfaConfig::Instance()->getValue("TreeGraphModuleLoader:handler:root:"+theMountInfo.fsType,0);
       }
       if (mModuleName=="") {
 	 mModuleName=misc::OcfaConfig::Instance()->getValue("TreeGraphModuleLoader:handler:"+theMountInfo.fsType,0);
       }
       if (mModuleName=="") {
	 mModuleName=mFileSystemClassMap[theMountInfo.fsType];
       }
       if (mModuleName == "") mModuleName=mFileSystemClassMap["default"];
       if (mModuleName == "") {
	// JBS changed path to theMountInfo.mountPoint. 
	throw OcfaException("Undefined filesystem class :'"+ theMountInfo.fsType + "' for " 
			    + theMountInfo.mountPoint + " found in /proc/mounts during ProcMountsModuleInfo construction.",0);
       }
       if (theMountInfo.readOnly) 
         mAttributes["ro"]=Scalar("true");
       else 
	 mAttributes["ro"]=Scalar("false");
       mAttributes["charset"]=Scalar(mycharset);
       mAttributes["mountpoint"]=Scalar(theMountInfo.mountPoint);
       long int pdev=static_cast<long int>(theMountInfo.pathdev);
       mAttributes["device"]=Scalar(pdev);
       mAttributes["owner"]=Scalar(theMountInfo.owner);
       mAttributes["fstype"]=Scalar(theMountInfo.fsType);
       mAttributes["devicefile"]=Scalar(theMountInfo.devicefile);
       return;
    }

    void ProcMountsModuleInfo::initializeLookupMaps(){
         mCharsetMap["default"] = "LATIN1";
         mCharsetMap["smb"] = "CHECK";
	 mCharsetMap["nfs"] = "CHECK";
	 mCharsetMap["ntfs"] = "CHECK";
         mFileSystemClassMap["default"] = "BasicFsFileSystem";
         mFileSystemClassMap["efs"] = "UnixFileSystem";
	 mFileSystemClassMap["ext2"] = "UnixFileSystem";
	 mFileSystemClassMap["ext3"] = "UnixFileSystem";
	 mFileSystemClassMap["jffs2"] = "UnixFileSystem";
	 mFileSystemClassMap["jffs"] = "UnixFileSystem";
	 mFileSystemClassMap["minix2"] = "UnixFileSystem";
	 mFileSystemClassMap["minix"] = "UnixFileSystem";
	 mFileSystemClassMap["qnx4"] = "UnixFileSystem";
	 mFileSystemClassMap["reiserfs2"] = "UnixFileSystem";
	 mFileSystemClassMap["reiserfs"] = "UnixFileSystem";
	 mFileSystemClassMap["sysv"] = "UnixFileSystem";
	 mFileSystemClassMap["nfs"] = "UnixFileSystem";
    }


    /**
     *JBS new method extracted from select and Init.
     * has as argument a tokenized option.
     * @param &token a tokenized mountline.
     * @param outMountInfo struct containing all information about the mount. 
     *
     */
    void ProcMountsModuleInfo::getInfoFromMountOptions(const std::vector < std::string > &tokens, MountInfo &outMountInfo){

      outMountInfo.devicefile = tokens[0];
      outMountInfo.mountPoint = tokens[1];
      outMountInfo.fsType = tokens[2];
      
      std::string mountflags=tokens[3];
      //Check if the filesystem is mounted read only
      unsigned int i;
      if (mountflags=="ro") {outMountInfo.readOnly=true;}
      else if (mountflags=="rw") {outMountInfo.readOnly=false;}
      else {

	i = mountflags.find_first_of(",ro");
	unsigned int floc=i+3;
	if (floc < mountflags.length()) {
	  outMountInfo.readOnly=true;
	} 
	else {
	  i = mountflags.find_first_of(",rw");
	  floc=i+3;
	  if (floc < mountflags.length()) {
	    outMountInfo.readOnly=false;
	  }
	  else {
	    throw OcfaException("Can not locate the ro/rw flags for  " + outMountInfo.mountPoint + " in /proc/mounts during ProcMountsModuleInfo::getInfoFromMountOptions.",0);
	  }
	}
      }
      //Check to see if the filesystem is mounted with some other uid as owner
      i=mountflags.find("uid=");
      if ((mountflags.length() > i) &&((i+5) < mountflags.length())) {

	outMountInfo.owner=atoi(mountflags.c_str()+i+4);
      }
      //New, hopefuly smarter guesing of the charset to use, temporary optional untill it proofs itself.
      if (misc::OcfaConfig::Instance()->getValue("smartcharsets") == "true") {
	i=mountflags.find("iocharset=");
	if ((mountflags.length() > i)&&((i+11) < mountflags.length())) {
	  
	  string iocharset=mountflags.c_str()+i+10;
	  size_t i2=iocharset.find(",");
	  if (iocharset.length() > i2) {
	    string iocharsettmp=iocharset.substr(0,i2);
	    iocharset=iocharsettmp;
	  }
	  outMountInfo.detectedCharSet=iocharset;
	}
	i=mountflags.find("nls=");
	if ((mountflags.length() > i)&&((i+5) < mountflags.length())) {
	  string nls=mountflags.c_str()+i+4;
	  size_t i2=nls.find(",");
	  if (nls.length() > i2) {
	    string nlstmp=nls.substr(0,i2);
	    nls=nlstmp;
	  }
	  outMountInfo.detectedCharSet=nls;
	}
#if     BYTE_ORDER == BIG_ENDIAN
	if (outMountInfo.detectedCharSet == "utf8") { outMountInfo.detectedCharSet="UTF8-BE";}
	if (outMountInfo.detectedCharSet == "ucs2") { outMountInfo.detectedCharSet="UCS2-BE";}
	if (outMountInfo.detectedCharSet == "ucs4") { outMountInfo.detectedCharSet="UCS4-BE";}
	if (outMountInfo.detectedCharSet == "unicode") { outMountInfo.detectedCharSet="UNICODEBIG";}
	if (outMountInfo.detectedCharSet == "utf16") { outMountInfo.detectedCharSet="UTF16BE";}
	if (outMountInfo.detectedCharSet == "utf32") { outMountInfo.detectedCharSet="UTF32BE"; } // JBS added '}'
#else
	if (outMountInfo.detectedCharSet == "utf8") { outMountInfo.detectedCharSet="UTF8-LE";}
	if (outMountInfo.detectedCharSet == "ucs2") { outMountInfo.detectedCharSet="UCS2-LE";}
	if (outMountInfo.detectedCharSet == "ucs4") { outMountInfo.detectedCharSet="UCS4-LE";}
	if (outMountInfo.detectedCharSet == "unicode") { outMountInfo.detectedCharSet="UNICODELITLE";}
	if (outMountInfo.detectedCharSet == "utf16") { outMountInfo.detectedCharSet="UTF16LE";}
	if (outMountInfo.detectedCharSet == "utf32") { outMountInfo.detectedCharSet="UTF32LE";}
#endif
      } else {
	i=mountflags.find("nls=utf8");
	if ((mountflags.length() > i)&&((i+7) < mountflags.length())) {
	  outMountInfo.detectedCharSet="UTF8-LE";
	}
      }
    }

    /**
     * JBS: method extracted from selectAndInit.
     * JBS: Determines which character set should be used based upon information from the mount, and the character set
     * JBS: given by the user. 
     *
     */

    std::string ProcMountsModuleInfo::determineCharsetToUse(MountInfo &inMountInfo, std::string &inGivenCharSet, bool isRoot){

      string charSetToUse;
      if (inGivenCharSet =="AUTO") {
	
	ocfa::misc::OcfaLogger::Instance()->syslog(LOG_INFO, "ProcMountsModuleInfo::determineCharSetToUse ") << "Auto detection implied for filesysten\n";
	if (inMountInfo.detectedCharSet != "") {
	  ocfa::misc::OcfaLogger::Instance()->syslog(LOG_DEBUG, "ProcMountsModuleInfo::determineCharSetToUse ") << "Using detected charset " <<  inMountInfo.detectedCharSet << "\n";
	  charSetToUse=inMountInfo.detectedCharSet;
	} else {
	  ocfa::misc::OcfaLogger::Instance()->syslog(LOG_DEBUG, "ProcMountsModuleInfo::determineCharSetToUse ") << "No charset detected for fs\n";
	  if (isRoot) {
	    charSetToUse=misc::OcfaConfig::Instance()->getValue("TreeGraphModuleLoader:charset:root:"+inMountInfo.fsType,0);
	  }
	  if (charSetToUse=="") {
	    charSetToUse=misc::OcfaConfig::Instance()->getValue("TreeGraphModuleLoader:charset:"+ inMountInfo.fsType,0);
	  }
	  if (charSetToUse=="") {
	    ocfa::misc::OcfaLogger::Instance()->syslog(LOG_DEBUG, "ProcMountsModuleInfo::determineCharSetToUse ") << "No charset in conffile, looking for a charset in the fs charsetmap\n";
	    charSetToUse=mCharsetMap[inMountInfo.fsType];
	  } else {
	    ocfa::misc::OcfaLogger::Instance()->syslog(LOG_INFO, "ProcMountsModuleInfo::determineCharSetToUse ") << "Charset fetched from config file\n";
	  }
	}
	if (charSetToUse == "") {
	  ocfa::misc::OcfaLogger::Instance()->syslog(LOG_INFO, "ProcMountsModuleInfo::determineCharSetToUse ") << "No charsets found or detected, falling back to default\n";
	  charSetToUse=mCharsetMap["default"];
	}
      } else {
	charSetToUse=inGivenCharSet;
      }
      //If the lookup returned false, it probably is a network mount, and a charset needs to be explicitly specified by the user.
      if (charSetToUse == "CHECK") {
	if (misc::OcfaConfig::Instance()->getValue("smartcharsets") != "true") { 
	  return "";
	}
	ocfa::misc::OcfaLogger::Instance()->syslog(LOG_NOTICE, "ProcMountsModuleInfo::determineCharSetToUse ") << "Ignoring CHECK directive\n";
	 charSetToUse = inMountInfo.detectedCharSet;
	 if (charSetToUse == "") {
	   ocfa::misc::OcfaLogger::Instance()->syslog(LOG_INFO, "ProcMountsModuleInfo::determineCharSetToUse ") << "Using default\n";
	   //If we tried smart guesing of the charset and failed, the default LATIN1 seems apropriate
	   charSetToUse = mCharsetMap["default"];
         } else {
           ocfa::misc::OcfaLogger::Instance()->syslog(LOG_INFO, "ProcMountsModuleInfo::determineCharSetToUse ") << "Using detected charset\n";
	 }
       }
      return charSetToUse;
    }
    
  }
}

