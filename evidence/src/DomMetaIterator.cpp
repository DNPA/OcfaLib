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
#include <DomMetaIterator.hpp>
#include <DomHelper.hpp>
#include <xercesc/util/XMLString.hpp>
#if     BYTE_ORDER == BIG_ENDIAN
#define XERCESUNICODE "UTF-16BE"
#else
#define XERCESUNICODE "UTF-16LE"
#endif

using namespace std;
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace evidence {
    DomMetaIterator::DomMetaIterator(const DOMNodeList *
				     metas,
				     Evidence *
				     facadeevidence,bool attrlast):
	    DomOcfaIterator(metas),
	    mMetaVal(0),
	    mFacadeevidence(facadeevidence),
	    mFacadeCount(METAFACADE_NON),
	    mLast(attrlast) 
    {
      updateTypeName("DomMetaIterator");
      if (mFacadeevidence) {
	ocfaLog(LOG_DEBUG,"New DomMetaIterator with facade");
	if (mLast) {
           mFacadeCount=METAFACADE_JOBCOUNT;
	} 
	else {
	   mFacadeCount = METAFACADE_MAX;
	}
      }
      else {
	ocfaLog(LOG_DEBUG,"New DomMetaIterator without facade");
      }
    }
    DomMetaIterator::~DomMetaIterator() {
      if (mMetaVal)
	ocfaLog(LOG_DEBUG, "deleting mMetaVal");
      delete mMetaVal;
      ocfaLog(LOG_DEBUG, "deleting mMetaVal done");
    }
    bool DomMetaIterator::next() {
      if (mFacadeCount == METAFACADE_NON) {
	ocfaLog(LOG_DEBUG,"Going to next, regular metadata\n");
	return DomOcfaIterator::next();
      }
      else {
        ocfaLog(LOG_DEBUG,"Going to next, facade metadata\n");
	mFacadeCount--;
	return true;
      }
    }
    Scalar DomMetaIterator::getScalar(size_t attrindex) const {
      if (getCurrent() == NULL) {
	ocfaLog(misc::LOG_ERR, "DOMNode==NULL");
	return 0;
      }
      DOMNodeList *scalarlist =
	DomHelper::getInstance()->getElementsByTagName(getCurrent(),
						       "scalar");
      if (scalarlist->getLength() > attrindex) {
	const XMLCh *lcontent = static_cast<const XMLCh *>( scalarlist->item(attrindex)->getTextContent() );
	if (lcontent ==0) {
            throw OcfaException("Problem retreiving TextContext from nth Scalar",this); 
	}
	unsigned int len = XMLString::stringLen(lcontent);
	Scalar rval;
	if (len > 0) {
	  const char *mbuf = reinterpret_cast<const char *>(lcontent);
	  rval = Scalar(mbuf, len * 2, XERCESUNICODE);
	} else {
           rval = Scalar("");
	}
	string scalartype=DomHelper::getInstance()->getAttribute(dynamic_cast < DOMElement * >(scalarlist->item(attrindex)),string("type"));
	if (scalartype == "datetime") {
           int sepindex=rval.asUTF8().find_last_of(":");
	   if ((sepindex == 19)&& (rval.asUTF8().size() > 18)) {
	     //getLogStream(LOG_WARNING) << "Fetched datetime string: " << attrindex << "= " << rval.asUTF8() << std::endl; 
	     std::string timesource=rval.asUTF8().c_str()+sepindex+1;
	     char buffer[20];
	     strncpy(buffer,rval.asUTF8().c_str(),18);
	     const misc::DateTime *dt=new misc::DateTime(misc::DateTime::translate(buffer),timesource);
	     return Scalar(&dt);
	   }
	} else if (scalartype == "int") {
          long long val=0;
	  sscanf(rval.asUTF8().c_str(),"%lli",&val);
	  return Scalar(val);
	} else if (scalartype == "float") {
          long double val=0;
          sscanf(rval.asUTF8().c_str(),"%Lf",&val);
	  return Scalar(val);
	}
	return rval;
      }
      throw OcfaException("MetaIterator::getScalar oops", this);
    }
    string DomMetaIterator::getColName(int attrindex) const {
      if (getCurrent() == NULL) {
	ocfaLog(misc::LOG_ERR, "DOMNode==NULL");
      }
      DOMNodeList *headlist =
	DomHelper::getInstance()->getElementsByTagName(getCurrent(), "head");
      if (headlist->getLength() > static_cast<size_t>(attrindex)) {
	char *tname =
	  DomHelper::transcode(headlist->item(attrindex)->getTextContent());
	string namestr(tname);
	XMLString::release(&tname);
	return namestr;
      }
      throw OcfaException("MetaIterator::getColName oops", this);
    }
    Scalar DomMetaIterator::getScalar() const {
      return getScalar(0);
    }
    int DomMetaIterator::items() const {
      return DomOcfaIterator::items("scalar");
    }
    int DomMetaIterator::collums() const {
      return DomOcfaIterator::items("head");
    }
    meta_type DomMetaIterator::getType() const {
      string type = getAttr("type");
      ocfaLog(LOG_DEBUG,"type = "+type);
      if (type == string("scalar")) {
	return META_SCALAR;
      }
      else if (type == string("array")) {
	return META_ARRAY;
      }
      else {
	return META_TABLE;
      }
    }
    string DomMetaIterator::getName() const {
      switch (mFacadeCount) {
        case METAFACADE_NON:return getAttr("name");
	case METAFACADE_CASEID:return "caseid";
	case METAFACADE_ITEMID:return "itemid";
	case METAFACADE_SRCID:return "evidencesourceid";
	case METAFACADE_EVIDENCE_ID:return "evidenceid";
	case METAFACADE_LOCATION:return "evidencelocation";
	case METAFACADE_PATH:return "evidencepath";
	case METAFACADE_MD5:return "datamd5";
	case METAFACADE_SHA:return "datasha1";
	case METAFACADE_JOBCOUNT:return "jobcount";
	case METAFACADE_PARENTCOUNT:return "parentcount";
      }
      return "BOGUS";
    } 
    
    void DomMetaIterator::fetchMetaVal(misc::MetaValue ** metaval) {
      if (*metaval != 0)
	throw OcfaException ("Can not fetch a metavalue while target is not a null pointer", this);
      Scalar rval(string(""));
      switch (mFacadeCount) {
      case METAFACADE_NON:
      {
	ocfaLog(LOG_DEBUG,"Fetching non facade metadata");
	meta_type typ = getType();
	Scalar s(string(""));
	int tmpindex, cols, row, col, rows, tmpsize;
	ArrayMetaValue *mvArray;
	TableMetaValue *mvTable;
	switch (typ) {
	case META_SCALAR:
          ocfaLog(LOG_DEBUG,"Type=SCALAR");
	  s = getScalar();
	  *metaval = new ScalarMetaValue(s);
	  break;
	case META_ARRAY:
	  ocfaLog(LOG_DEBUG,"Type=ARRAY");
	  mvArray = new ArrayMetaValue();
	  tmpsize = items();
	  for (tmpindex = 0; tmpindex < tmpsize; tmpindex++) {
	    Scalar scal = getScalar(tmpindex);
	    mvArray->addMetaValue(scal);
	  }
	  *metaval = mvArray;
	  break;
	case META_TABLE:
	  ocfaLog(LOG_DEBUG,"Type=TABLE");
	  cols = collums();
	  ArrayMetaValue *header = new ArrayMetaValue(cols);
	  for (col = 0; col < cols; col++) {
	    s = getColName(col);
	    header->addMetaValue(s);
	  }
	  mvTable = new TableMetaValue(&header);
	  rows = items() / cols;
	  for (row = 0; row < rows; row++) {
	    ArrayMetaValue *temprow = new ArrayMetaValue(cols);
	    for (col = 0; col < cols; col++) {
	      tmpindex = row * cols + col;
	      s = getScalar(tmpindex);
	      temprow->addMetaValue(s);
	    }
	    mvTable->addRow(&temprow);
	  }
	  *metaval = mvTable;
	  break;
	}
	ocfaLog(LOG_DEBUG,"Returning non facade metadata");
	return;
      }
      case METAFACADE_JOBCOUNT: rval=mFacadeevidence->getJobCount(); break;
      case METAFACADE_CASEID: rval=mFacadeevidence->getEvidenceIdentifier()->getCaseID(); break;
      case METAFACADE_ITEMID: rval=mFacadeevidence->getEvidenceIdentifier()->getItemID(); break;
      case METAFACADE_SRCID:  rval=mFacadeevidence->getEvidenceIdentifier()->getEvidenceSourceID(); break;
      case METAFACADE_EVIDENCE_ID: rval=mFacadeevidence->getEvidenceIdentifier()->getEvidenceID(); break;
      case METAFACADE_LOCATION: rval=mFacadeevidence->getEvidenceName();break;
      case METAFACADE_PATH: rval=mFacadeevidence->getEvidencePath();break;
      case METAFACADE_MD5: rval=mFacadeevidence->getDigestMD5();break;
      case METAFACADE_SHA: rval=mFacadeevidence->getDigestSHA();break;
      case METAFACADE_PARENTCOUNT: rval=mFacadeevidence->getParentCount();break;
      }
      *metaval = new ScalarMetaValue(rval);
      ocfaLog(LOG_DEBUG,"Returning facade metadata");
      return;
    }
    MetaValue *DomMetaIterator::getMetaVal() {
      if (mMetaVal != 0)
	delete mMetaVal;
      mMetaVal = 0;
      fetchMetaVal(&mMetaVal);
      return mMetaVal;
    }
  }
}
