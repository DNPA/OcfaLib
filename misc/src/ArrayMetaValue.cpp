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
						
#include <misc/ArrayMetaValue.hpp>
#include <misc/ScalarMetaValue.hpp>
#include <misc/OcfaException.hpp>
namespace ocfa {
	namespace misc {
		ScalarMetaValue *ArrayMetaValue::mDefault=0;
		ArrayMetaValue::ArrayMetaValue():OcfaObject("ArrayMetaValue","evidence"),mpContent(),mFixedSize(0) {
			if (mDefault==0)
				mDefault=new ScalarMetaValue(Scalar(std::string("")));
		}
		ArrayMetaValue::ArrayMetaValue(size_t asize):OcfaObject("ArrayMetaValue","evidence"),mpContent(),mFixedSize(asize){
			if (mDefault==0)
				mDefault=new ScalarMetaValue(Scalar(std::string("")));
		}
		ArrayMetaValue::~ArrayMetaValue(){
                  for (vector < ScalarMetaValue * >::iterator itr = mpContent.begin(); itr != mpContent.end(); itr++) {
                        delete *itr;
			*itr=0;
		  }
		  mFixedSize=0;
		  if (mDefault!=0)
		      delete mDefault;
		  mDefault=0;
		}
		void ArrayMetaValue::addMetaValue(Scalar& val){
                   if ((mpContent.size() < mFixedSize)||(mFixedSize==0)) {
                     ScalarMetaValue *smeta=new ScalarMetaValue(val);
                     mpContent.push_back(smeta);
		   } else {
                     throw OcfaException("Fixed size of ArrayMetaValue exeeded in addMetaValue",this);
		   }
		}
		MetaValue *ArrayMetaValue::getValueAt(size_t index) const{
                  if (mpContent.size() > index) {
                     return mpContent[index];
		  } else {
		     if (mFixedSize > index) {
                       return mDefault;
		     }
		     /** Out of range, return NULL */
		     return 0;
		  }
		}
		meta_type ArrayMetaValue::getType() const {
                   return META_ARRAY;
		}
		size_t ArrayMetaValue::size() const{
                   if (mFixedSize) return mFixedSize;
		   return mpContent.size();
		}
	}
}
