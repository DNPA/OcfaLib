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
						
#include <misc/TableMetaValue.hpp>
#include <misc/ArrayMetaValue.hpp>
#include <misc/ScalarMetaValue.hpp>
#include <misc/MetaValue.hpp>
namespace ocfa {
	namespace misc {
		TableMetaValue::TableMetaValue(ArrayMetaValue **colNames):OcfaObject("TableMetaValue","misc"),mColNames(*colNames),mColCount(0),mRows() {
		   mColCount=mColNames->size();
		   *colNames=0;
		}
    		TableMetaValue::TableMetaValue(size_t colCount):OcfaObject("TableMetaValue","misc"),mColNames(0),mColCount(colCount),mRows() {
		}
		TableMetaValue::~TableMetaValue() {
                   if (mColNames) {
                      delete mColNames;
		   }
		   for (vector < ArrayMetaValue * >::iterator itr = mRows.begin(); itr != mRows.end(); itr++) {
	                        delete *itr;
				*itr=0;
		   }
		}
                void TableMetaValue::addRow(ArrayMetaValue **val){
		  mRows.push_back(*val);
		  *val=0;
		}
	        MetaValue *TableMetaValue::getValueAt(size_t index) const {
                   if (mRows.size() > index) {
                      return mRows[index];
		   } 
		   return 0;
		}
	        meta_type TableMetaValue::getType() const {
                   return META_TABLE;
		}
		size_t TableMetaValue::size() const {
                  return mRows.size();
		}
		size_t TableMetaValue::getColCount() const{
                   return mColCount;
	        }
                std::string TableMetaValue::getColName(size_t index) const {
                   if ((mColNames) &&(index < mColCount)) {
		      MetaValue *val=mColNames->getValueAt(index);
                      ScalarMetaValue *mv= dynamic_cast <ScalarMetaValue *> (val);
		      return mv->asScalar().asUTF8();
		   } else {
                     return "";
		   }
		}
	}
}
