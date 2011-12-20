#ifndef _CONCRETEWRITEFACET_HPP
#define _CONCRETEWRITEFACET_HPP
#include "misc.hpp"
#include "store.hpp"
namespace ocfa {
  namespace module {
     class ConcreteWriteFacet: public ocfa::misc::AbstractWriteFacet {
        public:
          ConcreteWriteFacet(ocfa::store::EvidenceStoreEntity *sent):mSent(sent){}
          ~ConcreteWriteFacet(){}
          void operator()(char *buf, size_t count){
            mSent->writeStream(buf,count);
          }
        private:
          ocfa::store::EvidenceStoreEntity *mSent;
     };
  }
}
#endif
