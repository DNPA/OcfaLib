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
						
#include <DomEvidenceFactory.hpp>
#include <DomEvidence.hpp>
#include <DomExtendableEvidence.hpp>
#include <map>
#include <boost/lexical_cast.hpp>
using namespace std;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    void DomEvidenceFactory::createEvidence(Evidence **newevidence,OcfaHandle **
						 evidenceDataHandle,
						 misc::DigestPair * digests,
						 misc::Scalar & evidenceName,
						 map < std::string,
						 misc::MetaValue * >**statmap,
						 Evidence * parentevidence,
						 std::
						 string parentChildRelname,
						 std::vector < CoParent >
						 *coparents){
	    ocfaLog(LOG_DEBUG,"Testing input for NULL values");
	    if (mModinstance==0) throw OcfaException("DomEvidenceFactory is not baptized, cant create evidence",this);
	    if (*newevidence !=0) throw OcfaException("Target for evidence creation not a NULL ponter",this);
	    if ((*statmap == 0)||(parentevidence==0)) throw OcfaException("statmap and parentevidence may not be NULL",this);
	    ocfaLog(LOG_DEBUG,"Checking parentcount");
	    if (parentevidence->getParentCount() >= mMaxParentCount) {
                throw OcfaException("ParentCount would exceed the maximum",this);
	    }
	    ocfaLog(LOG_DEBUG,"All checks are ok");
	    Scalar parentpath=parentevidence->getEvidencePath();
	    ocfaLog(LOG_DEBUG,"Parent path:");
	    ocfaLog(LOG_DEBUG,parentpath.asUTF8());
	    Scalar parentname=parentevidence->getEvidenceName();
	    if (parentname.asUTF8() == "") {
              throw OcfaException("Parent had an empty string as name",this);
	    }
	    Scalar parentfullpath=parentpath + Scalar(string("/")) + parentname;
	    ocfaLog(LOG_DEBUG,"Parent fullpath:");
	    ocfaLog(LOG_DEBUG,parentfullpath.asUTF8());
	    DomEvidence *parent=dynamic_cast < DomEvidence * > (parentevidence);
	    if (parent==0) throw OcfaException("Unable to dynamicly cast parent evidence to DomEvidence",this);
	    DomActiveJob *activejob=dynamic_cast < DomActiveJob * > (parent->getActiveJob());
	    if (activejob == 0) throw OcfaException("Unable to create a 'derived' evidence while parent aparently isn't mutable",this);
            std::string idstring=".j" + boost::lexical_cast<std::string>(parentevidence->getJobCount()) + "e" +
                 boost::lexical_cast<std::string>(activejob->getChildCount());
	    string newid=parentevidence->getEvidenceIdentifier()->getEvidenceID() + idstring;
	    ocfaLog(LOG_DEBUG,"Creating derived evidence identifier");
	    misc::EvidenceIdentifier *neweid=new EvidenceIdentifier(parentevidence->getEvidenceIdentifier()->getCaseID(),
			    					    parentevidence->getEvidenceIdentifier()->getEvidenceSourceID(),
								    parentevidence->getEvidenceIdentifier()->getItemID(),
								    newid);
	    ocfaLog(LOG_DEBUG,"Creating derived evidence");
	    *newevidence=new DomEvidence(evidenceDataHandle,digests,evidenceName,parentfullpath,&neweid,mModinstance);
	    JobIterator *jit=parentevidence->getJobIterator();
	    if (jit==0) throw OcfaException("parentevidence did not return a JobIterator",this);
	    jit->last();
	    misc::ModuleInstance *minst=jit->getModuleInstance();
	    if (minst == 0) throw OcfaException("parent jobiterator did not return a ModuleInstance",this);
	    (*newevidence)->setMutable();
	    ocfaLog(LOG_DEBUG,"Adding a childreference to the derived eviedence to the parent Evidence");
            activejob->addChildRef(newid, parentChildRelname,coparents,evidenceName);
            map < string, misc::MetaValue * >::const_iterator p;
	    map < std::string,misc::MetaValue * > *smap=*statmap;
	    for (p = smap->begin(); p != smap->end(); ++p) {
	       ocfaLog(LOG_DEBUG,"Adding STATMAP entry");
               (*newevidence)->getActiveJob()->setMeta(p->first, p->second);
	       delete p->second;
	    }
	    delete *statmap;
	    *statmap=0;
	    return;
            
    }
    void DomEvidenceFactory::createEvidence(Evidence **newevidence,
		    				 misc::OcfaHandle **evidenceDataHandle,
						 misc::DigestPair * digests,
						 misc::Scalar & evidenceName,
						 map < std::string,misc::MetaValue * >**statmap,
						 misc::Item *parentitem){
	     if (evidenceName.asUTF8() == "") {
	        ocfaLog(LOG_WARNING,"Creating file with evidence name '" + evidenceName.asUTF8() + "'\n");
		throw OcfaException("Trying to create new top level evidence without a name",this);
	     }
	     if (mModinstance==0) throw OcfaException("DomEvidenceFactory is not baptized, cant create evidence",this);
             if ((statmap == 0)||(parentitem==0)) throw OcfaException("statmap and parentitem may not be NULL",this);
	     ocfaLog(LOG_DEBUG,"Calling getTopEvidenceCount on parent item");
             std::string newid=boost::lexical_cast<std::string>(parentitem->getTopEvidenceCount());
	     ocfaLog(LOG_DEBUG,"Constructing new evidence identifier");
	     misc::EvidenceIdentifier *neweid=new EvidenceIdentifier(parentitem->getCaseID(),
	                                                             parentitem->getEvidenceSourceID(),
	                                                             parentitem->getItemID(),
	                                                             newid);
	     Scalar empty(string(""));
	     ocfaLog(LOG_DEBUG,"Constructing new evidence");
	     *newevidence=new DomEvidence(evidenceDataHandle,digests,evidenceName,empty,&neweid,mModinstance);
	     (*newevidence)->setMutable();
	     map < string, misc::MetaValue * >::const_iterator p;
	     map < std::string,misc::MetaValue * > *smap=*statmap;
	     for (p = smap->begin(); p != smap->end(); ++p) {
		     ocfaLog(LOG_DEBUG,"Adding STATMAP entry");
		     (*newevidence)->getActiveJob()->setMeta(p->first, p->second);
		     delete p->second;
	     }
	     delete *statmap;
	     *statmap = 0;
	     ocfaLog(LOG_DEBUG,"Returning new evidence");
	     return; 
    }
    void DomEvidenceFactory::createEvidence(Evidence **newevidence,misc::MemBuf * membuf,
						 misc::OcfaHandle **evidenceDataHandle)
    {
	    if (mModinstance==0) throw OcfaException("DomEvidenceFactory is not baptized, cant create evidence",this);
	    *newevidence=new DomEvidence(membuf,evidenceDataHandle,mModinstance);
            return;
    }
    void DomEvidenceFactory::createExtendableEvidence(ExtendableEvidence **newextendableevidence,misc::
		    						     MemBuf *membuf,
								     misc::OcfaHandle **evidenceDataHandle){
	    if (mModinstance==0) throw OcfaException("DomEvidenceFactory is not baptized, cant create evidence",this);
	    *newextendableevidence=new DomExtendableEvidence(membuf,evidenceDataHandle,mModinstance);
	    return;

    }
    DomEvidenceFactory::DomEvidenceFactory():mModinstance(0),mMaxParentCount(200){
	    updateTypeName("DomEvidenceFactory");
	    ocfaLog(LOG_DEBUG,"Fetching conf value for maxparents");
	    string maxparentstr=misc::OcfaConfig::Instance()->getValue("maxparents",this);
	    sscanf(maxparentstr.c_str(),"%lu",(unsigned long *)(&mMaxParentCount));
	    ocfaLog(LOG_DEBUG,"DomEvidenceFactory constructed");
    }
    void DomEvidenceFactory::baptize(ModuleInstance *modinstance) {
      if (mModinstance == 0)
       mModinstance=new ModuleInstance(*modinstance);
    }
}}
