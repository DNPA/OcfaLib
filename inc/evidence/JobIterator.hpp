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
						
#ifndef _JOBITERATOR_HPP
#define _JOBITERATOR_HPP
#include "../misc.hpp"
#include "MetaIterator.hpp"
#include "LogIterator.hpp"
#include "ChildIterator.hpp"
#include "ArgumentIterator.hpp"
#include <string>

//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better
namespace ocfa {
  namespace evidence {
    /**JobIterator class used to iterate over Jobs within an Evidence 
     * The JobIterator is fetched and (RE)INITIALIZED by Evidence::getJobIterator*/
    class JobIterator: virtual public OcfaIterator {
    public:
      /**Get the MetaIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      virtual MetaIterator *getMetaIterator()=0;
      /**Get the LogIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      virtual LogIterator *getLogIterator()=0;
      /**Get the ChildIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      virtual ChildIterator *getChildIterator()=0;
      /**Get the ArgumentIterator for the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
      virtual ArgumentIterator *getArgumentIterator()=0;
      /**Get the msg::ModuleInstance of the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
       virtual misc::ModuleInstance * getModuleInstance()=0;
      /**Get the module its starrtime of the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
       virtual misc::DateTime *getStartTime()=0;
      /**Get the module its endtime of the current Job 
       *
       * Please note that the pointer returned will remain valid only
       * during a single run of processEvidence and only as long as
       * no next() or last() is called on the JobIterator
       * */
       virtual misc::DateTime *getEndTime()=0;
       /**Check if the status of the current job is DONE (not NEW or PROCESSED) */
       virtual bool isDone() const =0;
       /**Check if the status of the current job id PROCESSED (not NEW or DONE) */
       virtual bool isProcessed() const =0;
      /**Set the status of a currently PROCESSED job to DONE
       *
       * A module will after processing a job set its status to PROCESSED. The router
       * will process the metadata of all PROCESSED jobs and set them to DONE.
       * Other modules with iterator access should NOT use this method !!*/
       virtual void setDone()=0;
       virtual ~JobIterator() {};
    };
}}
#endif
