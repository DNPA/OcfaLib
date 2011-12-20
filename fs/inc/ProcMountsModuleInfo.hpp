#ifndef _PROCMOUNTMODULEINFO_HPP_
#define _PROCMOUNTMODULEINFO_HPP_
#include <string>
#include <map>
#include <vector>
#include <fs/FileSystemModuleInfo.hpp>
#include <misc/Scalar.hpp>
namespace ocfa {
  namespace fs {
    struct MountInfo{
             MountInfo():readOnly(false), devicefile(""),detectedCharSet(""), fsType(""),owner(0), mountPoint(""){
	     }
            bool readOnly;
            std::string devicefile;
            std::string detectedCharSet;
            std::string fsType;
	    uid_t owner;
            std::string mountPoint;
            dev_t pathdev;
     };


     class ProcMountsModuleInfo: public FileSystemModuleInfo {
     public:
       ProcMountsModuleInfo(std::string path,std::string charset);
     private:
       static ocfa::misc::Scalar mValidPathRegex;
       void initializeLookupMaps();
       void getInfoFromMountOptions(const std::vector < std::string > &tokens, MountInfo &outMountInfo);
       std::string determineCharsetToUse(MountInfo &inMountInfo, std::string &inGivenCharSet, bool isRoot);
       /**
 	 *  This static atribute holds a map that is used to lookup what known named
    	 *  filesystem type has wat (default) character encoding.
         */
       static std::map <std::string, std::string> mCharsetMap;
        /**
         * This static atribute holds a map that is used to lookup what known named
	 * filesystem type has what subclass of the TreeGraphFactory as most apropriate
	 * filesystem representation class.
	 */
       static std::map <std::string, std::string> mFileSystemClassMap;

     };
  }
}
#endif
