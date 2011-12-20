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
						
#ifndef H_OCFA_SCALARMETAVAL
#define H_OCFA_SCALARMETAVAL
#include "../OcfaObject.hpp"
#include "Scalar.hpp"
#include "MetaValue.hpp"
namespace ocfa {
	namespace misc {
  class ScalarMetaValue:public OcfaObject,public MetaValue {
  public:
    /**The basic constructor */
    ScalarMetaValue(const Scalar& val);
    ScalarMetaValue();
#ifndef CYGWIN
    ScalarMetaValue(wstring val,string encoding=OCFA_UNICODE);
#endif
    ScalarMetaValue(string val,string encoding=OCFA_UNICODE);
    ScalarMetaValue(const char *val,size_t size,string encoding=OCFA_UNICODE);
    ScalarMetaValue(const char *val,string encoding=OCFA_UNICODE);
    ScalarMetaValue(long long val);
    ScalarMetaValue(long val);
    ScalarMetaValue(unsigned long val);
    ScalarMetaValue(int val);
    ScalarMetaValue(unsigned int val);
    ScalarMetaValue(short val);
    ScalarMetaValue(unsigned short val);
    ScalarMetaValue(long double val);
    MetaValue *getValueAt(size_t index) const;
    meta_type getType() const;
    Scalar asScalar() const;
  private:
    Scalar mContent;
  };
	}
}
#endif
