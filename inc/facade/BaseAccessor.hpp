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
						
#ifndef __OCFAACCESSORBASE_
#define __OCFAACCESSORBASE_
#include "module/OcfaModule.hpp"

namespace ocfa {

  namespace facade {

    class BaseAccessor : public ocfa::module::OcfaModule {

    public:
      BaseAccessor(std::string inName, std::string inNamespace,bool forcenodeamonize=false);
      /**
       * Retreive the value of a job argument from the active job
       * @returns The value of the named argument
       * @param name The name of the argument to retreive from the job
       */
      std::string getJobArgument(std::string name) const;

      /** 
       * Set the value of a scalar type Meta within the active job.
       * @param n The name of the meta data
       * @param s The value (and type) of the meta data
       */
      void setMeta(std::string n, ocfa::misc::MetaValue &s);

      void setMeta(std::string n, ocfa::misc::Scalar s);

      /**
       * 
       *
       */

     /**
      * Add a Scalar to an array type Meta within the active job
      * @param n The name of the meta data
      * @param s The value (and type) of the meta data
      * @deprecated
      **/
//      void pushBackMeta(std::string name, ocfa::misc::Scalar s);
      
     /**Get the ID of the evidence item, this id is unique for any particular evidence source */
      std::string getEvidenceItemID() const;

      /**Get the ID of the evidence, this id is unique for any particular evidence item */
      std::string getEvidenceID() const;

      /**Get the ID of the evidence source, this id is unique for any particular investigation */
      std::string getEvidenceSourceID() const;
 
     /**Get the ID of the investigation*/
      std::string getInvestigationID() const;

      
      /** Relinquish controll for a moment to the library so the library can do some administrative work if needed.
       * This method should be used by slow modules that take many minutes to process a single evidence or message
       * @param done The number of processing actions done in the active job
       * @param estimatedEnd The estimated total number of processing actions on this job including those already d
       */
      void aliveAndKicking(int done, int estimatedEnd, bool force = false);

      /**Fetch the MD5 digest belonging to the evidence data*/
      std::string getDigestMD5() const;
      /**Fetch the SHA1 digest belonging to the evidence data*/
      std::string getDigestSHA1() const;
      /** Fetch the CaseName of the Evidence **/
      std::string getCase() const;
      /**Fetch the name belonging to the evidence data*/
      ocfa::misc::Scalar getEvidenceName() const;
      /**Fetch the evidence path of the evidence data*/
      ocfa::misc::Scalar getEvidencePath() const;
      /**
       * Fetch the evidence location of the evidence data
       * This is a combination of path and name
       **/
      ocfa::misc::Scalar getEvidenceLocation() const;

      /**
       * returns the corresponding Conf entry.
       *
       */
      std::string getConfEntry(std::string inName);
      
      /**
       * sets the level for which the module can be disturbed 
       * when processing evidence.
       * @param 
       */
      //void setPreemptLevel(int maxPrio); RJM:CODEREVIEW

      /**
       * starts the processing of messages.
       *
       */
      void run();

     

    protected:

      /**
       * Checks whether the current evidence is valid and has a current active job.
       */
      void checkValidEvidenceAndJob() const;
      /**
       * checks whether an Evidence is valid.
       *
       */
      void checkValidEvidence() const;
    };
  }
}

      

#endif
