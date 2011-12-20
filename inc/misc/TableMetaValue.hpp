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
						
#ifndef H_OCFA_TABLEMETAVAL
#define H_OCFA_TABLEMETAVAL
#include "MetaValue.hpp"
#include <misc/ArrayMetaValue.hpp>
#include "../OcfaObject.hpp"
#include <misc/OcfaException.hpp>
namespace ocfa {
	namespace misc {
  class TableMetaValue:public OcfaObject,public MetaValue {
  public:
    TableMetaValue(ArrayMetaValue **colNames);
    TableMetaValue(size_t colCount);
    TableMetaValue(const ocfa::misc::TableMetaValue&):OcfaObject("TableMetaValue","misc"),MetaValue(),mColNames(0),mColCount(0),mRows(0) {
        throw OcfaException("No copy constructing TableMetaValues",this);
    }
    ~TableMetaValue();
    void addRow(ArrayMetaValue **val);
    MetaValue *getValueAt(size_t index) const;
    meta_type getType() const;
    size_t size() const;
    size_t getColCount() const;
    std::string getColName(size_t index) const;
  private:
    const TableMetaValue& operator=(const TableMetaValue&){
       throw OcfaException("No invoking operator= allowed for TableMetaValues",this);
       return *this;
    }
    ArrayMetaValue *mColNames;
    size_t mColCount;
    std::vector < ArrayMetaValue * > mRows;
  };
	}
}
#endif
