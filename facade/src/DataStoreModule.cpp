#include "facade/DataStoreModule.hpp"
#include "store.hpp"
#include "misc.hpp"
namespace ocfa {
  namespace facade {
    void DataStoreModule::processEvidenceMessage(const ocfa::message::Message &message) {
      try {
        //create an evidence from the message.
        store::MetaStoreEntity *metaEntity;
        misc::ModuleInstance sender(message.getSender());
        getLogStream(LOG_INFO) << " received message with content " <<
          message.getContent() << endl;
        store::AbstractRepository::Instance()
          ->createMetaStoreEntity(&metaEntity, misc::OcfaHandle(message.getContent()));
        if (metaEntity == 0){

          throw misc::OcfaException(string("no Meta could be created from ") + message.getContent());
        }
        ocfaLog(LOG_DEBUG, "setting evidence");
        setEvidence(createEvidenceFromMeta(metaEntity));
        // set evidence mutable.
        getEvidence()->setMutable();
        // call the pure virtual process message now that the active evidence is set.
        ocfaLog(LOG_DEBUG, "Calling processEvidence.");
        try {
          processEvidence();
        } catch (OcfaException &e){
          getLogStream(LOG_ERR) << e.what() << endl;
          logEvidence(LOG_ERR, e.what());
        }
        //
        // close the activeJob
        ocfaLog(LOG_DEBUG, "closing active JOb");
        getEvidence()->getActiveJob()->close();

        ocfaLog(LOG_DEBUG, "closed active Job");
        // update the metastoreentity with the changed evidence.
        updateMetaWithEvidence(*metaEntity, *getEvidence());
        delete metaEntity;
        delete getEvidence();
        setEvidence(0);
        //OcfaObject::PrintObjCount();
      } catch (OcfaException &e){
         ocfaLog(LOG_ERR, "ocfaexception ");
	 getLogStream(LOG_ERR) << e.what() << endl;
         throw e;
      }
    }
  }
}
