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
						
#include <string>
#include <iostream>
#include <unistd.h>
#include <map>
#include <misc.hpp>
#include <DomActiveJob.hpp>
#include <defines.hpp>
#include <xercesc/util/XMLString.hpp>
#include <evidence/JobIterator.hpp>
#include <DomEvidence.hpp>
#include <DomJobIterator.hpp>
#include <xercesc/dom/DOM.hpp>
#include <DomHelper.hpp>
#include <boost/lexical_cast.hpp>
using namespace std;
using namespace xercesc;
using namespace ocfa::misc;
//For now use the namespace ocfa (Open Computer Forensics Architecture) untill we think of something better

namespace ocfa {
  namespace evidence {
    DomActiveJob::DomActiveJob(DOMNodeList * dnlist, DOMDocument *ddoc,misc::ModuleInstance *minst,std::string caseid):
	    OcfaObject("DomActiveJob","evidence"),
	    jdomelement(0),
	    domdoc(ddoc),
	    minlevel(LOG_NOTICE),
	    argmap(),
	    mCaseID(caseid),
	    mChildCount(0),
	    mProfstart(0),
	    mRealstart(0),
	    mClosed(false)
    {
      updateTypeName("DomActiveJob");
      ocfaLog(LOG_DEBUG,"DomActiveJob::DomActiveJob");
      if (dnlist == NULL) {
	throw OcfaException("DomActiveJob::DomActiveJob dnlist=NULL", this);
      }
      string esyslog =misc::OcfaConfig::Instance()->getValue("esyslog",this);
      minlevel = LOG_NOTICE;
      if (esyslog == "debug")
           minlevel = LOG_DEBUG;
      else if (esyslog == "info")
           minlevel = LOG_INFO;
      else if (esyslog == "notice")
         minlevel = LOG_NOTICE;
      else if (esyslog == "warning")
         minlevel = LOG_WARNING;
      else if (esyslog == "err")
         minlevel = LOG_ERR;
      else if (esyslog == "crit")
         minlevel = LOG_CRIT;
      else if (esyslog == "alert")
         minlevel = LOG_ALERT;
      else if (esyslog == "emerg")
         minlevel = LOG_EMERG;
      if (domdoc == 0) {
	throw
	  OcfaException ("DomActiveJob::DomActiveJob constructor called with DOMDocument set to NULL", this);
      }
      XMLSize_t lsize = dnlist->getLength();
      if (lsize > 0) {
	  ocfaLog(LOG_DEBUG,
	    "casting our job node to a domelement");
	jdomelement = dynamic_cast < DOMElement * >(dnlist->item(lsize - 1));
	if (jdomelement == 0) {
	  throw OcfaException ("DomActiveJob::DomActiveJob casting Job node to a DOMElement dynamicly failed", this);
	}
	  ocfaLog(LOG_DEBUG,"setting starttime");
	DomHelper::getInstance()->setAttribute(jdomelement,"stime",misc::DateTime::translate(time(NULL)));
	DOMElement *minstobj = 0;
	DomHelper::getInstance()->createElement(&minstobj,domdoc,"moduleinstance");
	if (minstobj == 0) {
	  throw OcfaException ("DomActiveJob::DomActiveJob Creating moduleinstance DOM Element failed ", this);
	}
	jdomelement->appendChild(minstobj);
	if (minst == 0) {
	  throw OcfaException ("DomActiveJob::DomActiveJob constructor called with ModuleInstance set to NULL", this);
	}
	DomHelper::getInstance()->setAttribute(minstobj,"host",minst->getHostname());
	DomHelper::getInstance()->setAttribute(minstobj,"namespace",minst->getNameSpace());
	DomHelper::getInstance()->setAttribute(minstobj,"module",minst->getModuleName());
	DomHelper::getInstance()->setAttribute(minstobj,"instance",minst->getInstanceName());
	  ocfaLog(LOG_DEBUG,
	    "DomActiveJob::DomActiveJob creating domnode for moduleinstance done");
      }
      else {
	throw OcfaException("DomActiveJob::DomActiveJob called with zero size dnlist", this);
      }
	ocfaLog(LOG_DEBUG,
	  "DomActiveJob::DomActiveJob fetching and filling map of argumewnts");
      JobIterator *jit = new DomJobIterator(dnlist,caseid);
      if (jit != NULL) {
	ocfaLog(LOG_DEBUG,"Jumping to the last Job to fetch Arguments");
	jit->last();
	ArgumentIterator *argit = jit->getArgumentIterator();
	if (argit != NULL) {
          do {
	    string name = argit->getName();
	    string val = argit->getVal();
	    ocfaLog(LOG_DEBUG,"Found an argument :" + name + "=" +val);
	    argmap[name] = val;
	  } while (argit->next());
	} else {
          ocfaLog(LOG_DEBUG,"Job had no arguments");
	}
        delete jit;
      }
      else {
	throw OcfaException("DomActiveJob::DomActiveJob problem creating new JobIterator",this);
      }
	ocfaLog(LOG_DEBUG,"Activejob::DomActiveJob done");
    }

    DomActiveJob::DomActiveJob(const DomActiveJob & aj):
	    OcfaObject(aj),
	    ActiveJob(aj),
	    jdomelement(0),
	    domdoc(0),
	    minlevel(LOG_NOTICE),
	    argmap(),
	    mCaseID(0),
	    mChildCount(0),
	    mProfstart(0),
	    mRealstart(0),
	    mClosed(false)
    
    {
      updateTypeName("DomActiveJob");
      throw OcfaException("No copiing of DomActiveJob allowed", this);
    }
    DomActiveJob::~DomActiveJob() {
	ocfaLog(LOG_DEBUG,"DomActiveJob::~DomActiveJob");
    }
    string DomActiveJob::getArgument(string name) {
	ocfaLog(LOG_DEBUG,"DomActiveJob::getJobArgument " + name);
      return argmap[name];
    }
    void DomActiveJob::createTableMeta(string n,vector < string > *fn) {
	    DOMElement *mymeta =0;
	    DomHelper::getInstance()->createElement(&mymeta,domdoc,"meta");
            if (mymeta == 0) {
		throw OcfaException("Could not create meta DOM element", this);
	    }
	    DomHelper::getInstance()->setAttribute(mymeta,"name",n);
	    DomHelper::getInstance()->setAttribute(mymeta,"type","table");
	    size_t index;
	    for (index = 0; index < fn->size(); index++) {
		  DOMElement *myhead =0;
		  DomHelper::getInstance()->createElement(&myhead,domdoc,"head");
		  if (myhead == 0) {
                      throw OcfaException("Could not create head DOM element", this);
		  }
		  XMLCh *tnameval = DomHelper::transcode((*fn)[index].c_str());
		  myhead->appendChild(domdoc->createTextNode(tnameval));
		  XMLString::release(&tnameval);
		  mymeta->appendChild(myhead);
		  //FIXME::CR::JOCHEN::MEMORY:: delete myhead;
	    }
	    jdomelement->appendChild(mymeta);
	    //FIXME::CR::JCOHEN::MEMORY:: delete mymeta
    }
    void DomActiveJob::setMeta(string name, Scalar s) {
      ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta");
      if (jdomelement == 0) {
	      throw OcfaException("DomActiveJob::setMeta jdomelement==NULL",this);
      }
      DOMNodeList *metalist =DomHelper::getInstance()->getElementsByTagName(jdomelement,"meta");
      if (metalist == 0) {
	throw OcfaException ("DomActiveJob::setMeta DomHelper::getInstance()->getElementsByTagName returned NULL", this);
      }
      XMLSize_t lsize = metalist->getLength();
      DOMElement *myscalar = 0;
      DOMElement *tmpmeta;
      if (lsize > 0) {
	  ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta job has meta");
	XMLSize_t index;
	for (index = 0; (index < lsize) && (myscalar == 0); index++) {
	    ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta looking at meta");
	  tmpmeta = dynamic_cast < DOMElement * >(metalist->item(index));
	  if (tmpmeta == 0) {
	    throw OcfaException ("DomActiveJob::setMeta Casting meta node to DOMElement failed", this);
	  }
	  string sname=DomHelper::getInstance()->getAttribute(tmpmeta,"name");
	  string stype=DomHelper::getInstance()->getAttribute(tmpmeta,"type");
	    ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta comparing (" + sname + ") to ("+ 
	      name + ") and (" + stype + ") to (scalar)");
	  if ((sname == name) && (stype == string("scalar"))) {
	      ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta MATCH");
	    //Ok we found an existing one, lets get the scalar element handle
	    DOMNodeList *scalarlist =DomHelper::getInstance()->getElementsByTagName(tmpmeta,"scalar");
	    if (scalarlist->getLength() > 0) {
		ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta setting myscalar");
	      myscalar = dynamic_cast < DOMElement * >(scalarlist->item(0));
	      if (myscalar == 0) {
		throw OcfaException ("DomActiveJob::setMeta Casting scalar node to DOMElement failed", this);
	      }
	      DOMNode *olddata = myscalar->removeChild(myscalar->getFirstChild());
	      if (olddata != 0)
		olddata->release();
	    }
	    else {
	      throw OcfaException ("DomActiveJob::setMeta found an existing but invalidly empty meta element", this);
	    }
	  }
	  else {
	      ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta NO existing meta by this name");
	  }
	}
	  ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta done looking at meta");
      }
      if (myscalar == 0) {
	  ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta making new meta");
	//Aparently this metadata is the first in this job with this name
	//lets create a new metadata first and apend it to the active job
	DOMElement *mymeta = 0;
	DomHelper::getInstance()->createElement(&mymeta,domdoc,"meta");
	if (mymeta == 0) {
	  throw OcfaException("Could not create meta DOM element", this); }
	DomHelper::getInstance()->setAttribute(mymeta,"name",name);
	DomHelper::getInstance()->setAttribute(mymeta,"type","scalar");
	jdomelement->appendChild(mymeta);
	//now lets hang a new empty scalar on the matadata
	myscalar = 0;
	DomHelper::getInstance()->createElement(&myscalar,domdoc,"scalar");
	if (myscalar == 0) {
	  throw OcfaException("Could not create scalar DOM element", this);
	}
	mymeta->appendChild(myscalar);
	  ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta making new meta done");
      }
	ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta setting scalar");
      // now we need to set the scalar to that of s
      switch (s.getType()) {
      case Scalar::SCL_INT:
	DomHelper::getInstance()->setAttribute(myscalar,"type","int");
	break;
      case Scalar::SCL_FLOAT:
	DomHelper::getInstance()->setAttribute(myscalar,"type","float");
	break;
      case Scalar::SCL_DATETIME:
	DomHelper::getInstance()->setAttribute(myscalar,"type","datetime");
	break;
      case Scalar::SCL_STRING:
	DomHelper::getInstance()->setAttribute(myscalar,"type","string");
	break;
      case Scalar::SCL_INVALID:
	throw OcfaException("Trying to add an invalid scalar as metadata.", this);
      }
      XMLCh *xs = DomHelper::transcode(s.asUTF8().c_str());
      myscalar->appendChild(domdoc->createTextNode(xs));
      XMLString::release(&xs);
	ocfaLog(LOG_DEBUG,"DomActiveJob::setMeta done");
      return;
    }

    //Append metadata to end of list (array), like STL...
    void DomActiveJob::pushBackMeta(string name, Scalar s) {
	ocfaLog(LOG_DEBUG,"DomActiveJob::pushBackMeta ");
      if (jdomelement == NULL) {
	throw OcfaException("DomActiveJob::pushBackMeta jdomelement==NULL");
      }
      //First lets try to find if the active job has a meta with this name
      DOMNodeList *metalist = DomHelper::getInstance()->getElementsByTagName(jdomelement,"meta");
      if (metalist == 0) {
	throw OcfaException("DomHelper::getInstance()->getElementsByTagName returned NULL for meta", this);
      }
      XMLSize_t lsize = metalist->getLength();
      DOMElement *mymeta = 0;
      DOMElement *tmpmeta;
      if (lsize > 0) {
	XMLSize_t index;
	for (index = 0; (index < lsize) && (mymeta == 0); index++) {
	  tmpmeta = dynamic_cast < DOMElement * >(metalist->item(index));
	  if (tmpmeta == 0) {
	    throw OcfaException ("DomActiveJob::pushBackMeta Casting meta node to DOMElement failed", this);
	  }
	  string sname=DomHelper::getInstance()->getAttribute(tmpmeta,"name");
	  string stype=DomHelper::getInstance()->getAttribute(tmpmeta,"type");
	  if ((sname == name) && ((stype == string("array")))||(stype == string("table"))) {
	    mymeta = tmpmeta;
	  }
	}
      }
      if (mymeta == 0) {
	//Aparently this metadata is the first in this job with this name
	//lets create a new metadata first and apend it to the active job
	mymeta = 0;
	DomHelper::getInstance()->createElement(&mymeta,domdoc,"meta");
	if (mymeta == 0) {
	  throw OcfaException("Could not create meta DOM element", this);
	}
	  ocfaLog(LOG_DEBUG, "Created mymeta=");
	DomHelper::getInstance()->setAttribute(mymeta,"name",name);
	DomHelper::getInstance()->setAttribute(mymeta,"type","array");
	jdomelement->appendChild(mymeta);
      }
      //now lets hang a new scalar on the matadata
      DOMElement *myscalar = 0;
      DomHelper::getInstance()->createElement(&myscalar,domdoc,"scalar");
      if (myscalar == 0) {
	throw OcfaException("Could not create scalar DOM element", this);
      }
      mymeta->appendChild(myscalar);
      // now we need to set the scalar to that of s
      switch (s.getType()) {
      case Scalar::SCL_INT:
	DomHelper::getInstance()->setAttribute(myscalar,"type","int");
	break;
      case Scalar::SCL_FLOAT:
	DomHelper::getInstance()->setAttribute(myscalar,"type","float");
	break;
      case Scalar::SCL_DATETIME:
	DomHelper::getInstance()->setAttribute(myscalar,"type","datetime");
	break;
      case Scalar::SCL_STRING:
	DomHelper::getInstance()->setAttribute(myscalar,"type","string");
	break;
      case Scalar::SCL_INVALID:
	throw OcfaException("Trying to pushback an invalid scalar as metadata.", this);
      }
      XMLCh *xs = DomHelper::transcode(s.asUTF8().c_str());
      myscalar->appendChild(domdoc->createTextNode(xs));
      XMLString::release(&xs);
      ocfaLog(LOG_DEBUG,"DomActiveJob::pushBackMeta  done");
      return;
    }
    void DomActiveJob::addLogLine(syslog_level level, string line) {
      if (mClosed) throw OcfaException("Can not add logline to c closed job",this);
      if (level >= minlevel) {
	DOMElement *logel =0;
        DomHelper::getInstance()->createElement(&logel,domdoc,"logline");
	if (logel == 0) {
	  throw OcfaException("Failed to create logline element in addLogLine", this);
	}
	jdomelement->appendChild(logel);
	DomHelper::getInstance()->setAttribute(logel,"time",misc::DateTime::translate(time(NULL)));
	switch (level) {
	case LOG_DEBUG:
	  DomHelper::getInstance()->setAttribute(logel,"prio","debug");
	  break;
	case LOG_INFO:
	  DomHelper::getInstance()->setAttribute(logel,"prio","info");
	  break;
	case LOG_NOTICE:
	  DomHelper::getInstance()->setAttribute(logel,"prio","notice");
	  break;
	case LOG_WARNING:
	  DomHelper::getInstance()->setAttribute(logel,"prio","warning");
	  break;
	case LOG_ERR:
	  DomHelper::getInstance()->setAttribute(logel,"prio","err");
	  break;
	case LOG_CRIT:
	  DomHelper::getInstance()->setAttribute(logel,"prio","crit");
	  break;
	case LOG_ALERT:
	  DomHelper::getInstance()->setAttribute(logel,"prio","alert");
	  break;
	case LOG_EMERG:
	  DomHelper::getInstance()->setAttribute(logel,"prio","emerg");
	  break;
	}
	XMLCh *argval;
	argval = DomHelper::transcode(line.c_str());
	logel->appendChild(domdoc->createTextNode(argval));
	XMLString::release(&argval);
      }
    }
    size_t DomActiveJob::getChildCount() const{
       return mChildCount; 
    }
    bool DomActiveJob::hasChildren() const{
       return (mChildCount != 0);
    }
    void DomActiveJob::setMeta(std::string name, MetaValue * val){
       if (mClosed) throw OcfaException("Can not set meta for closed job",this);
       switch (val->getType()) {
	       case META_SCALAR:{
				ScalarMetaValue *mv=dynamic_cast <ScalarMetaValue *> (val);
				if (mv==0) throw OcfaException("Problem casting MetaValue to its subtype",this);
				setMetaLL(name,mv);
				mv=0;}
				break;
	       case META_ARRAY: {
				ArrayMetaValue *mv=dynamic_cast <ArrayMetaValue *> (val);
				if (mv==0) throw OcfaException("Problem casting MetaValue to its subtype",this);
				setMetaLL(name,mv);
				mv=0;}
				break;
	       case META_TABLE: {
				TableMetaValue *mv=dynamic_cast <TableMetaValue *> (val);
				if (mv==0) throw OcfaException("Problem casting MetaValue to its subtype",this);
				setMetaLL(name,mv);
				mv=0;}
				break;
       }
    }
    void DomActiveJob::setMetaLL(std::string name, ScalarMetaValue * val){
        setMeta(name, val->asScalar()); 
    }
    void DomActiveJob::setMetaLL(std::string name, ArrayMetaValue * val){
       size_t size=val->size();
       size_t index;
       for (index=0;index<size;index++) {
          ScalarMetaValue *mv=dynamic_cast <ScalarMetaValue *>(val->getValueAt(index));
	  if (mv == 0) throw OcfaException("Problem retreiving or casting item of ArrayMetaValue to ScalarMetaValue",this);
	  ocfaLog(LOG_DEBUG,"Adding to meta array " + name + " : " + mv->asScalar().asUTF8());
	  pushBackMeta(name, mv->asScalar()); 
       }
    }
    void DomActiveJob::setMetaLL(std::string name, TableMetaValue *val ){
       vector<string> headers;
       size_t cols=val->getColCount();
       size_t col;
       for (col=0;col<cols;col++) {
         headers.push_back(val->getColName(col));
       }
       createTableMeta(name, &headers);
       size_t rows=val->size();
       size_t row;
       for (row=0;row<rows;row++) {
	 ArrayMetaValue *mv=dynamic_cast <ArrayMetaValue *>(val->getValueAt(row));
         setMetaLL(name,mv);
       }

    }
    commit_type DomActiveJob::getCommitFlag() {
	ocfaLog(LOG_DEBUG,"DomActiveJob::getCommitFlag ");
      DOMElement *job = dynamic_cast < DOMElement * >(jdomelement);
      if (job == 0) {
	throw OcfaException ("Unable to cast Job node ot DOMElement in getCommitFlag method", this);
      }
      string flagstr=DomHelper::getInstance()->getAttribute(jdomelement,"commitflag");
	ocfaLog(LOG_DEBUG,"DomActiveJob::getCommitFlag looking what flag is set");
      if (flagstr == string("SUSPEND"))
	return COMMIT_SUSPEND;
      if (flagstr == string("DEFAULT"))
	return COMMIT_DEFAULT;
      if (flagstr == string("STORESPEED"))
	return COMMIT_OPTIMIZED_ON_STORE_SPEED;
      if (flagstr == string("SEARCHSPEED"))
	return COMMIT_OPTIMIZED_ON_SEARCH_SPEED;
      return COMMIT_NOT;
    }
    void DomActiveJob::close() {
      ocfaLog(LOG_DEBUG,"DomActiveJob::close");
      if (mClosed) throw OcfaException("Can not close the same activejob twice",this);
      DomHelper::getInstance()->setAttribute(jdomelement,"etime",misc::DateTime::translate(time(NULL)));
      DomHelper::getInstance()->setAttribute(jdomelement,"status","PROCESSED");
      if (mRealstart != 0) {
	long long real=DomEvidence::getRealTimerVal() -mRealstart;
	long long prof=mProfstart - DomEvidence::getProfilingTimerVal();
	DomHelper::getInstance()->setAttribute(jdomelement,"realinjobtime",boost::lexical_cast<std::string>(real));
	DomHelper::getInstance()->setAttribute(jdomelement,"profinjobtime",boost::lexical_cast<std::string>(prof));
      }
      mClosed=true;
      ocfaLog(LOG_DEBUG,"DomActiveJob::close done");
    }
    void DomActiveJob::addChildRef(string childref, string attrrelname,
				const vector < CoParent > *coparents,
				Scalar childname) {
	ocfaLog(LOG_DEBUG,"DomActiveJob::addChildRef");
      if (mClosed) throw OcfaException("Can not add childref to closed job",this);
      DOMElement *childel =0;
      DomHelper::getInstance()->createElement(&childel,domdoc,"childevidence");
      if (childel == 0) {
	throw OcfaException ("Failed to create childevidence element in addChildRef", this);
      }
      jdomelement->appendChild(childel);
      if (attrrelname != string("")) {
	DomHelper::getInstance()->setAttribute(childel,"relname",attrrelname);
      } else {
        DomHelper::getInstance()->setAttribute(childel,"relname","undefined");
      }
      DomHelper::getInstance()->setAttribute(childel,"evidenceid",childref);
      DomHelper::getInstance()->setAttribute(childel,"name",childname.asUTF8());
      mChildCount++;
      if (coparents != 0) {
	  ocfaLog(LOG_DEBUG,"we have got coparents");
	size_t index;
	for (index = 0; index < coparents->size(); index++) {
	  int jid = (*coparents)[index].getJobID();
	  string eid = (*coparents)[index].getEvidenceID();
	  string item = (*coparents)[index].getItemID();
	  string src = (*coparents)[index].getEvidenceSourceID();
	  string tmprelname = (*coparents)[index].getRelName();
	  DOMElement *copel =0;
	  DomHelper::getInstance()->createElement(&copel,domdoc,"coparent");
	  
	  if (copel == 0) {
	    throw OcfaException ("Failed to create coparent element in addChildRef method", this);
	  }
	  childel->appendChild(copel);
	  XMLCh *argval;
	  argval = DomHelper::transcode(eid.c_str());
	  copel->appendChild(domdoc->createTextNode(argval));
	  XMLString::release(&argval);
	  DomHelper::getInstance()->setAttribute(copel,"relname",tmprelname);
	  DomHelper::getInstance()->setAttribute(copel,"src",src);
	  DomHelper::getInstance()->setAttribute(copel,"item",item);
	  DomHelper::getInstance()->setAttribute(copel,"jobid",Scalar(jid).asASCII());
	}
      }
	ocfaLog(LOG_DEBUG,"DomActiveJob::addChildRef done");
    }
    void DomActiveJob::setPreMutableTimes(long long real,long long prof) {
       if (mClosed) throw OcfaException("Can not set premutabletimes on closed job",this);
       DomHelper::getInstance()->setAttribute(jdomelement,"realpremutabletime",Scalar(real).asASCII());
       DomHelper::getInstance()->setAttribute(jdomelement,"profpremutabletime",Scalar(prof).asASCII());
       return;
    }
    void DomActiveJob::setStartTimers(long long realstart,long long profstart) {
       if (mClosed) throw OcfaException("Can not set starttimers to closed job",this);
       mProfstart=profstart;
       mRealstart=realstart;
    }
    bool DomActiveJob::isClosed() const {
      return mClosed;
    }
  }
}
