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
						
#ifndef __OCFAMODULE_
#define __OCFAMODULE_
#include "../OcfaObject.hpp"
#include "../message/MessageBox.hpp"
#include "../evidence/EvidenceFactory.hpp"
#include "../evidence/Evidence.hpp"
#include "../misc/ModuleInstance.hpp"
#include "../store/MetaStoreEntity.hpp"
namespace ocfa {
 
  namespace module {


    /**
     * class that contains the minimum necessary methods to function
     * as a module in the digital washing machine. Other classes can
     * derive from this one to provide additional or changed
     * functionality. You can derive from this class directly if you
     * want to create a module with some very special feature. Normally you 
     * could derive from one of the clases in the the facade library.
     *
     *
     */
    class OcfaModule : public OcfaObject  {
    public:

      /**
       * constructor. Does not initialize anything. 
       *
       */
      OcfaModule();
      /**
       * dispatches the message.
       *
       */
      virtual void handleMessage(const ocfa::message::Message *msg);
      
      //void 				processOneJob(); 
 
      /**
       * logs  to the the central module logging.
       */
      void                              logModule(ocfa::misc::syslog_level inLevel, 
						  std::string logLine);

      /**
       * logs to the evidence.
       *
       */
      void                              logEvidence(ocfa::misc::syslog_level inLevel, 
						    std::string inLogLine);
      
      /**
       * helper method that creates a new metastoreentity from the
       * evidence and sends a new evidence to the router. 
       */
      virtual void  submitEvidence(ocfa::evidence::Evidence *inEvidence, 
				   const ocfa::misc::ModuleInstance *inRouter  = 0);
      
      /**
       * sets the messagebox and the store. Also makes sure that all components
       * in the module know how the module is called.
       * @param inName the name of the module.
       * @param inNameSpace the namespace in which the module operates.
       *
       */
      virtual void initialize(std::string inName, std::string inNamespace);
    protected:
      /**
       * Protect copy constructors (effective c++)
       */
      OcfaModule(const OcfaModule&);
      const OcfaModule& operator=(const OcfaModule&);
      virtual ~OcfaModule();
      /**
       * pure virtual method that is called when the evidence is set. 
       * Normal modules override this method to do the actual processing 
       * of a message.
       *
       */
      virtual void 			processEvidence()=0;
      //  virtual void 			processMessage(ocfa::message::Message &msg);
      
      /**
       * Method that is called when an message containing an evidences is received. 
       * @param message. The evidence message.
       */
      virtual void processEvidenceMessage(const ocfa::message::Message &message);
      
      /**
       * Method that is called when a heartbeatmessage is received. 
       * @param message the message that is received.
       */
      virtual void processHeartBeatMessage(const ocfa::message::Message &message);


      /**
       * Message that is called when a system message is received. 
       * System messages are a very versatile kind of message. The ocfamodule only 
       * interprets the one with subject "SetLogLevel" with content "<prefix> <loglevel>";
       *
       */
      virtual void processSystemMessage(const ocfa::message::Message &inMessage);

      /**
       * Helper method to create an evidence from a metaEntity. You normally do not need to 
       * override this method unless you want to create a 'special' kind of evidence object.
       * @param inMetaEntity The entity that is used to create the evidence.
       * @return the evidence that was in the metaStoreEntity. The calles takes ownership over this 
       * evidenc.
       */
      virtual ocfa::evidence::Evidence *createEvidenceFromMeta(ocfa::store::MetaStoreEntity *inMetaEntity);

      /**
       * Helper method that returns a handle to the
       * evidencestoreentity that is linker to a metastoreentity. This
       * method doesnot need to be overridden.
       * @param inMetaEntity the metastorentity which possibly is connected to an evidencestoreentity.
       * @return  the handle to an the evidencestoreentity linked to the metastoreentity. If the 
       *   metastoreentity is not linked to an evidencestoreentity the return value is 0. The caller 
       * takes responsbility over
       * the returned value if not 0. 
       *
       */
      virtual ocfa::misc::OcfaHandle *createDataHandleFromMeta(ocfa::store::MetaStoreEntity *inMetaEntity);
      
      /**
       * writes the evidence as a membut and updates the  metastoreentity with it. 
       * 
       *
       */
      virtual void updateMetaWithEvidence(ocfa::store::MetaStoreEntity &inMeta, ocfa::evidence::Evidence &inEvidence);
      /**
       * helper method that takes an evidence wraps it into a message
       * and sends it to the router.
       *
       */
    protected: /*The folowing methods will become provate in the *Components*/
      
      /**
       * returns the messagebox that belongs to this module.
       *
       */
      ocfa::message::MessageBox		*getMessageBox();
      
      /**
       * sets the messagebox that belongs to this module. Normally
       * this is done in the initialize method.  At this moment the
       * messagebox is a singleton, so don't start setting it to
       * something else unless you truly know what you're
       * @param inBox the messagebox that is used by this module.
       */
      void                               setMessageBox(ocfa::message::MessageBox *inBox);
      
      /**
       * returns the current active evidence.
       * @return the evidence that is currently being processed or 0 if no such evidence exists.
       *
       */
      ocfa::evidence::Evidence 	*getEvidence() const;

      int getDerivePriority(const ocfa::misc::ModuleInstance *minst) const;
      /**
       * returns the evidencefactory that is used by this module to create evidences
       */
      ocfa::evidence::EvidenceFactory	*getEvidenceFactory();

      /**
       * sets the evidencefactory that is used by this module. At the
       * moment this is an singleton so don't start setting it to
       * something else unless you surely know what you're doing
       */
      void setEvidenceFactory(ocfa::evidence::EvidenceFactory *inFactory);

      /**
       * sets the active evidence.
       *
       */
      void				setEvidence(ocfa::evidence::Evidence *inEvidence,int priority=MSG_EVIDENCE_LOWPRIO);

      /**
       * dispatches amessage.
       *
       */
      virtual void	     dispatchMessage(const ocfa::message::Message &msg);
      bool mpStop;
    private:
      ocfa::misc::OcfaGroup			mGroup;
      ocfa::evidence::EvidenceFactory 		*mpEvidenceFactory;
      ocfa::evidence::Evidence			*mpActiveEvidence;
      ocfa::message::MessageBox			*mpMessageBox;
      int 					mpActivePriority;
  };
}
}
#endif
