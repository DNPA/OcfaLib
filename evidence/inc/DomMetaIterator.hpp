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
						
#ifndef _DOMMETAITERATOR_
#define _DOMMETAITERATOR_
#include <evidence/MetaIterator.hpp>
#include <string>
#include <DomOcfaIterator.hpp>
#include <evidence/Evidence.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <defines.hpp>

namespace ocfa {
  namespace evidence {
    class DomMetaIterator:public DomOcfaIterator, public MetaIterator {
    public:
	    //JCW:CODEREVIEW: documentatie public methods !@#$ 
      DomMetaIterator(const xercesc::DOMNodeList * metalist,Evidence *facadeevidence,bool last);
      ~DomMetaIterator();
      DomMetaIterator(const DomMetaIterator& dmi):OcfaIterator(dmi),DomOcfaIterator(dmi),MetaIterator(dmi),mMetaVal(0),mFacadeevidence(0),mFacadeCount(0),mLast(true) {
         throw misc::OcfaException("No copying allowed for DomMetaIterator",this);
      }
      const DomMetaIterator& operator=(const DomMetaIterator&) {
	      throw misc::OcfaException("No assignment allowed for DomMetaIterator",this);
	      return *this;
      }
      misc::MetaValue *getMetaVal();
      void fetchMetaVal(misc::MetaValue **metaval);
      std::string getName();
      virtual bool next();
    private:
      misc::Scalar getScalar(size_t index) const;
      misc::Scalar getScalar() const;
      std::string getColName(int index) const;
      int items() const;
      int collums() const;
      misc::meta_type getType() const;
      std::string getName() const;
      misc::MetaValue *mMetaVal;
      Evidence *mFacadeevidence;
      size_t mFacadeCount;
      bool mLast;
    };
}}
#endif
