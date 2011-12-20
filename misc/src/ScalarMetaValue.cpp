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
						
#include <misc/ScalarMetaValue.hpp>
#include <misc/OcfaException.hpp>
#include <misc/meta_type.hpp>
namespace ocfa {
	namespace misc {
		ScalarMetaValue::ScalarMetaValue(const misc::Scalar& val):OcfaObject("ScalarMetaValue","evidence"),mContent(val) {
		}
		ScalarMetaValue::ScalarMetaValue():OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar()) {}
#ifndef CYGWIN
		ScalarMetaValue::ScalarMetaValue(wstring val,string encoding):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val,encoding)) {}
#endif
		ScalarMetaValue::ScalarMetaValue(string val,string encoding):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val,encoding)) {}
		ScalarMetaValue::ScalarMetaValue(const char *val,size_t size,string encoding):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val,size,encoding)) {}
		ScalarMetaValue::ScalarMetaValue(const char *val,string encoding):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val,encoding)) {}
		ScalarMetaValue::ScalarMetaValue(long long val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(long val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(unsigned long val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(int val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(unsigned int val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(short val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(unsigned short val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
		ScalarMetaValue::ScalarMetaValue(long double val):OcfaObject("ScalarMetaValue","evidence"),mContent(Scalar(val)) {}
								
		MetaValue *ScalarMetaValue::getValueAt(size_t) const {
			throw OcfaException("ScalarMetaValue getValueAt called",this);
		}
		meta_type ScalarMetaValue::getType() const {
			return META_SCALAR; 
		}
		Scalar ScalarMetaValue::asScalar() const{
			return mContent;
		}
	}
}
