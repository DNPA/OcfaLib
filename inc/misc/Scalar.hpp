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
						
#ifndef H_OCFA_SCALAR
#define H_OCFA_SCALAR
#include <boost/regex.hpp>   //RJM:CODEREVIEW to facilitate router we add regex suport to Scalars.
#include "../OcfaObject.hpp"
#include "OcfaException.hpp"
#include "DateTime.hpp"
//The default charset for ocfa strings is UTF-8
const string  OCFA_UNICODE =  "UTF-8";
//The default charset for ocfa wstring is UCS2 in the NATIVE ENDIANNESS of the system its running on.
//It is important to note that no assumptions should be made on this always being litle-endian,
//or on being the same as that of filesystems being interpreted on the host system.
#if     BYTE_ORDER == BIG_ENDIAN
const string OCFA_UNICODEW = "UTF-16BE";
#else
const string OCFA_UNICODEW = "UTF-16LE";
#endif
namespace ocfa {
  namespace misc {
    /** The class for scalars in the Open Computer Forensics Architecture */
    class Scalar:public OcfaObject {
    public:
      /** The different types of scalars that exist */
      typedef enum { SCL_INVALID, SCL_INT, SCL_FLOAT, SCL_STRING,
		     SCL_DATETIME
      } scalar_type;
      /*Default constructor resulting in INVALID */
      Scalar();
      /**Constructor for a scalar from a wstring
       * @param val The wstring value to put in the Scalar
       * @param encoding The 16 bit encoding name to feed to the iconv library
       * please use 'iconv -l' for a list of valid encoding names
       * Please take special care with respect to endiannes of your system and of
       * the source of the data being used when using wstrings to hold 16 bit
       * encodings. Where possible your modules should attempt to work on both
       * LE and BE systems and be able to process data generated on both LE and BE
       * systems.*/
#ifndef CYGWIN
      Scalar(wstring val, string encoding = OCFA_UNICODEW);
#endif
      /**Constructor for a scalar from a string
       * @param val The string value to put in the Scalar
       * @param encoding The 8 bit encoding name to feed to the iconv library
       * please use 'iconv -l' for a list of valid encoding names*/
      Scalar(string val, string encoding = OCFA_UNICODE);
      /**Constructor for a scalar from a non null terminated character buffer */
      Scalar(const char *val, size_t len, string encoding = OCFA_UNICODE);
      /**Constructor for a scalar from a null terminated character string */
      Scalar(const char *val,string encoding = OCFA_UNICODE);
      /**Construct a scalar from a 64 bit signed integer */
      Scalar(long long val);
      /**Construct a scalar from a 32 bit signed integer */
      Scalar(long val);
      /**Construct a scalar from a 32 bit unsigned integer */
      Scalar(unsigned long val);
      /**Construct a scalar from a signed integer */
      Scalar(int val);
      /**Construct a scalar from an unsigned integer */
      Scalar(unsigned int val);
      /**Construct a scalar from a 16 bit signed integer */
      Scalar(short val);
      /**Construct a scalar from a 16 bit unsigned integer */
      Scalar(unsigned short val);
      /** Construct a scalar from a floating point number */
      Scalar(long double val);
      /**Construct a Scalar from a DayDime */
      Scalar(const DateTime ** val);
      /** Copy constructor */
      Scalar(const Scalar& sc);
      /** Destructor */
      ~Scalar();
      
      /**
       * adds two Scalars to another. The result depends on the type of the two arguments.
       * If the scalars cannot reasonably be added, in the case of datetime + datetime.
       * an exception is thrown. 
       * 
       *
       */
      friend Scalar operator+(Scalar, Scalar);

      /** Some operating overloading for making life easyer for the router and other
       * Scalar users.
       */
      bool operator==(Scalar s) const; //check if equal
      bool operator<(Scalar s); //check if less than
      bool operator>(Scalar s); //check if greater
      bool operator!=(Scalar s) const {return !(*this == s);}
      bool operator>=(Scalar s) {return (*this == s) || (*this > s);}
      bool operator<=(Scalar s) {return (*this == s) || (*this < s);}
      bool operator[](Scalar s); //we use the index operator for matching regular expressions.
      
      /**Get hte scalar as a "NATIVE" UTF16 wstring, cast any non string type scalar to a string. 
       * Please take special care with respect to endiannes of your system and of
       * the source of the data being used when using wstrings to hold 16 bit
       * encodings. Where possible your modules should attempt to work on both
       * LE and BE systems and be able to process data generated on both LE and BE
       * system */
#ifndef CYGWIN
      wstring asUnicode() const;
#endif
      /**Get hte scalar as an ASCII string. cast any non string type scalar to a string and throw
       * an exeption if the string holds non ASCII code */
      string asASCII() const;
      /**Get hte scalar as a UTF8 wstring, cast any non string type scalar to a string */
      string asUTF8() const;
      /**Check if a scalar fully fits into 7 bit ASCII*/
      bool fitsInASCII() const;
      /**Get the scalar that should be of Integer typa as an integer */
      long long asInt() const;
      /**Get the scalar that should be of Float typa as an integer */
      long double asFloat() const;
      /**Get the scalar that should be of DateTime typa as an integer */
      const DateTime *asDateTime();
      /**Get the type of the Scalar */
      scalar_type getType() const;
      ocfa::misc::Scalar& operator=(const ocfa::misc::Scalar&);
      string whatObjInfo() const;
    private:
      void testControll();
      string content;
      scalar_type _Type;
      const DateTime *tmpdt;
      boost::regex *as_regex;
    };
  Scalar operator+(Scalar a1, Scalar a2);
  }
}
#endif
