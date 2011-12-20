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
#include <DomJobIterator.hpp>
#include <DomMetaIterator.hpp>
#include <DomLogIterator.hpp>
#include <DomChildIterator.hpp>
#include <DomArgumentIterator.hpp>
#include <DomHelper.hpp>
#include <xercesc/util/XMLString.hpp>
using namespace std;
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    DomJobIterator::DomJobIterator(const DOMNodeList *
			     jobnodes,std::string caseid,Evidence *facadeevidence):
      DomOcfaIterator(jobnodes), st(NULL), et(NULL), mi(NULL), cit(NULL),
      lit(NULL), mit(NULL), ait(NULL), mCaseID(caseid),mFacadeevidence(facadeevidence){
	      ocfaLog(LOG_DEBUG,"updating typename to DomJobIterator");
	      updateTypeName("DomJobIterator");
	      if (mFacadeevidence) {
                ocfaLog(LOG_DEBUG,"new DomJobIterator with facade");
	      } else {
                ocfaLog(LOG_DEBUG,"new DomJobIterator without facade");
	      }
    } DomJobIterator::~DomJobIterator() {
      if (st != NULL) {
	delete st;
	st = NULL;
      }
      if (et != NULL) {
	delete et;
	et = NULL;
      }
      if (mi != NULL) {
	delete mi;
	mi = NULL;
      }
      if (cit != NULL) {
	delete cit;
	cit = NULL;
      }
      if (lit != NULL) {
	delete lit;
	lit = NULL;
      }
      if (ait != NULL) {
	delete ait;
	ait = NULL;
      }
      if (mit != NULL) {
	delete mit;
	mit = NULL;
      }
    }
    MetaIterator *DomJobIterator::getMetaIterator() {
      if (mit != NULL) {
	delete mit;
	mit = NULL;
      }
      DOMNodeList *nlist = getSubItNodeList("meta");
      if (nlist == 0)
	return 0;
      if (mFacadeevidence) {
         ocfaLog(LOG_DEBUG,"Creating DomMetaIterator with facade");
      } else {
         ocfaLog(LOG_DEBUG,"Creating DomMetaIterator without facade");
      }
      bool needsfacade=(mFacadeevidence!=0) && ((getIndex()==0)||(getIndex()+1==size()));
      if (needsfacade) {
        mit = new DomMetaIterator(nlist,mFacadeevidence,(size()==getIndex()+1));
      } else {
        mit = new DomMetaIterator(nlist,0,(size()==getIndex()+1));
      }
      return mit;
    }
    LogIterator *DomJobIterator::getLogIterator() {
      if (lit != NULL) {
	delete lit;
	lit = NULL;
      }
      DOMNodeList *loglines = getSubItNodeList("logline");
      if (loglines == 0)
	return 0;
      lit = new DomLogIterator(loglines);
      return lit;
    }
    ArgumentIterator *DomJobIterator::getArgumentIterator() {
      if (ait != NULL) {
	delete ait;
	ait = NULL;
      }
      DOMNodeList *arguments = getSubItNodeList("argument");
      if (arguments == 0)
	return 0;
      ait = new DomArgumentIterator(arguments);
      return ait;
    }
    ChildIterator *DomJobIterator::getChildIterator() {
      if (cit != NULL) {
	delete cit;
	cit = NULL;
      }
      DOMNodeList *childs = getSubItNodeList("childevidence");
      if (childs == 0)
	return 0;
      cit = new DomChildIterator(childs,mCaseID);
      return cit;
    }
    misc::ModuleInstance * DomJobIterator::getModuleInstance() {
      if (mi != NULL) {
	delete mi;
	mi = NULL;
      }
      if (getCurrent() == NULL) {
	ocfaLog(LOG_ERR,"DOMNode==NULL");
	return NULL;
      }
      DOMNodeList *minst =DomHelper::getInstance()->getElementsByTagName(getCurrent(),"moduleinstance");
      if (minst->getLength() > 0) {
	  DOMElement *midomelement = dynamic_cast < DOMElement * >(minst->item(0));
	  string host=DomHelper::getInstance()->getAttribute(midomelement,"host");
	  string module=DomHelper::getInstance()->getAttribute(midomelement,"module");
	  string nspace=DomHelper::getInstance()->getAttribute(midomelement,"namespace");
	  string instance=DomHelper::getInstance()->getAttribute(midomelement,"instance");
	mi =
	  new misc::ModuleInstance(host,module,nspace,instance);
      }
      return mi;
    }
    DateTime *DomJobIterator::getStartTime() {
      if (st != 0) {
	delete st;
	st = 0;
      }
      st = new misc::DateTime(atol(getAttr("stime").c_str()), "OCFA");
      return st;
    }
    DateTime *DomJobIterator::getEndTime() {
      if (et != NULL) {
	delete et;
	et = NULL;
      }
      et = new misc::DateTime(atol(getAttr("stime").c_str()), "OCFA");
      return et;
    }
    bool DomJobIterator::isDone() const {
      string status = getAttr("status");
        return (status == string("DONE"));
    }
    bool DomJobIterator::isProcessed() const {
      string status = getAttr("status");
        return (status == string("PROCESSED"));
    }
    void DomJobIterator::setDone() {
      setAttr(string("status"), string("DONE"));
    }
    bool DomJobIterator::next() {
      if (mFacadeevidence) {
        ocfaLog(LOG_DEBUG,"DomJobIterator::next clearing facade interface");
      }
      return DomOcfaIterator::next();
    }
    void DomJobIterator::last() {
      if (mFacadeevidence) {
         ocfaLog(LOG_DEBUG,"DomJobIterator::last clearing facade interface");
      }
      DomOcfaIterator::last();
      return;
    }
  }
}
