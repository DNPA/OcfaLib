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
						
#ifndef __OCFAACCESSORTARGET_
#define __OCFAACCESSORTARGET_

#include "BaseAccessor.hpp"
#include "evidence/JobInfo.hpp"
namespace ocfa {

  namespace facade {

    /**
     * Accessor used to send evidences to different modules. It 
     * can also add new jobs to evidences.
     *
     */
    class TargetAccessor : public BaseAccessor {
    public:

      TargetAccessor(std::string inName, std::string inNamespace, bool forceNoDaemonize = false);
      /**
       * sets the moduleinstance to which the evidence will be sent.
       */
      virtual void setTarget(std::string inName, std::string inNameSpace);
      /**
       * adds a new job to the current evidence
       * @param jobInfo informaiton about the new job. 
       *
       */
      virtual void addNewJob(ocfa::evidence::JobInfo *jobinfo);

      //RJM: proposal to make router cleaner.
      //  Dont forget to update VERSION-INFO.makeinfo if it gets accepted.
      //ExtendableEvidence *TargetAccessor::getExtendableEvidence();      
    protected:
      /**
       * Protect copy constructors 
       */
      TargetAccessor(TargetAccessor&);
      //TargetAccessor operator=(TargetAccessor&);
      
      /**
       * small adaptation of ocfamodule::processEvidenceMessage.
       *
       */
      virtual void processEvidenceMessage(const ocfa::message::Message &inMessage);
      /**
       * adaptation that created extendabl;e evidences. 
       */
      virtual ocfa::evidence::Evidence *createEvidenceFromMeta(ocfa::store::MetaStoreEntity *inEntity);

    private:
      misc::ModuleInstance *mTarget;
      
      
      
    };



  }
}
#endif
