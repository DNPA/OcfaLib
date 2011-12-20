#ifndef _INVALIDNODE_HPP
#define _INVALIDNODE_HPP
#include "treegraph.hpp"
#include "misc.hpp"
#include <string>
namespace ocfa {
  namespace treegraph {
     class InvalidNode: public TreeGraphNode {
        public:
          bool hasContent(){ return false;}
          off_t getSize() {return 0;}
          void streamToOutput(ocfa::misc::AbstractWriteFacet &writefacet){}
          bool hasSubEntities() { return false;}
          void resetSubEntityIterator() {}
          bool nextSubEntity() {}
          void getCurrentSubEntity(TreeGraphNode ** subent) {}
          std::string getCurrentSubEntityRelation() { return "ocfa-broken-branch";}
          std::string getName() { return "BROKEN";}
          void takeMetaMap(std::map < std::string, misc::MetaValue * >**map);
          void unlinkOnDestruct(){}          
          void openStream(){}
          void closeStream(){}
          size_t streamRead(char *buf, size_t count){ return 0;}
          std::string getSoftLinkablePath(ocfa::misc::DigestPair **) {return "";}
          std::string getHardLinkablePath(std::string targetbasepath,ocfa::misc::DigestPair **) { return "";}

     }; 
  }
}
#endif 
