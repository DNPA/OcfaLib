#ifndef _DATASTOREMODULE_HPP_
#define _DATASTOREMODULE_HPP_
#include "XMLAccessor.hpp"
#include <string>
namespace ocfa {
  namespace facade {
     class DataStoreModule: public XMLAccessor {
      public:
       DataStoreModule(std::string name,std::string ns):XMLAccessor(name,ns){}
       virtual void processEvidenceMessage(const ocfa::message::Message &message);
     };
  }
}

#endif
