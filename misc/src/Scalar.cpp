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
						
#include <misc/Scalar.hpp>
#include <OcfaObject.hpp>
#include <misc/OcfaException.hpp>
#include <misc/Exception.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <iconv.h>
#include <errno.h>
#include <netinet/in.h>
#include <boost/lexical_cast.hpp>
using namespace std;
namespace ocfa {
  namespace misc {
   void Scalar::testControll() {
      int index;
       int len = content.length();
       for (index = 0; index < len; index++) {
          char tch=content.c_str()[index];
          if (tch == 0) {
             throw StringNullTerminationException (std::string("NULL character in scalar string at index") + boost::lexical_cast< std::string > ( index ), this); 
          }
          if ((tch > -1) && (tch < ' ') && ((tch < '\t' ) || (tch > '\r'))) {
             throw CharSetException (std::string("Controll character in scalar string:") + boost::lexical_cast< std::string > (tch ) + " at index " + boost::lexical_cast< std::string > ( index ), this);
          }
       }
    }

    Scalar::Scalar():OcfaObject("Scalar","ocfa"),content(""),_Type(SCL_INVALID),tmpdt(0),as_regex(0){;}
    
    Scalar::Scalar(const Scalar& peer):OcfaObject("Scalar","ocfa"),content(peer.content),_Type(peer._Type),tmpdt(0),as_regex(0){;}

    string Scalar::whatObjInfo() const{
        string stype="BOGUS";
	switch (_Type) {
		case SCL_INVALID:
			stype="INVALID";
			break;
		case SCL_INT:
			stype="INTEGER";
			break;
		case SCL_FLOAT:
			stype="FLOAT";
			break;
		case SCL_DATETIME:
			stype="DATETIME";
			break;
		case SCL_STRING:
			stype="STRING";
		
	}
	return stype + string(":'") + asUTF8() + string("'");
    }
    
    Scalar& Scalar::operator=(const Scalar& peer) {
       if (tmpdt) {
         delete tmpdt;
       }
       if (as_regex) {
         delete as_regex;
	 as_regex=0;
       }
       tmpdt=0;
       _Type=peer.getType();
       switch (_Type) {
          case SCL_INVALID:
	  	  content="";
		  break;
	  case SCL_INT:
	  case SCL_FLOAT:
	  case SCL_DATETIME:
	  case SCL_STRING:
		  content=peer.asUTF8();
       }
       return *this;
    }

    bool Scalar::operator==(Scalar s) const{
        if (getType() != s.getType())
		return false;
        return (content == s.content);	
    }
    bool Scalar::operator<(Scalar s) {
       if ((getType() != s.getType()) && 
	   !((getType()==SCL_INT || getType()==SCL_FLOAT ) && (s.getType()==SCL_INT || s.getType()==SCL_FLOAT ))
	  )
	       return false;
       switch (getType()) {
	  case SCL_INT:
	  case SCL_FLOAT:
		  return (asFloat() < s.asFloat());
	  case SCL_DATETIME:
		  if (asDateTime()->getTimeSourceRef() != s.asDateTime()->getTimeSourceRef()) {
                     if (!((asDateTime()->getTimeSourceRef() == "DNTCR")||(s.asDateTime()->getTimeSourceRef() == "DNTCR")))
			     return false;
		  }
		  return (asDateTime()->getTime() < s.asDateTime()->getTime());
          case SCL_INVALID:
	  case SCL_STRING:
	          ;
       }
       return false;
    }
    
    bool Scalar::operator>(Scalar s) {
    if ((getType() != s.getType()) &&
        !((getType()==SCL_INT || getType()==SCL_FLOAT ) && (s.getType()==SCL_INT || s.getType()==SCL_FLOAT ))
       )
             return false;
       switch (getType()) {
	     case SCL_INT:
	     case SCL_FLOAT:
	             return (asFloat() > s.asFloat());
	     case SCL_DATETIME:
		     if (asDateTime()->getTimeSourceRef() != s.asDateTime()->getTimeSourceRef()) {
			     if (!((asDateTime()->getTimeSourceRef() == "DNTCR")||(s.asDateTime()->getTimeSourceRef() == "DNTCR")))
				     return false;
		     }
		     return (asDateTime()->getTime() > s.asDateTime()->getTime());
	     case SCL_INVALID:
	     case SCL_STRING:
	           ;
       }
       return false;
    }
    
    bool Scalar::operator[](Scalar s) {
        if (as_regex == 0) {
		try {
		   as_regex=new boost::regex(asUTF8().c_str());
		} catch (...) {
		   this->getLogStream(LOG_ERR) << "'" << asUTF8().c_str() << "' is not a valid regex" << std::endl;
                   return false;
		}
	}
	bool rval=boost::regex_match(s.asUTF8().c_str(), *as_regex);
	return rval;
    }
    
#ifndef CYGWIN    
    Scalar::Scalar(wstring val, string encoding):OcfaObject("Scalar","ocfa"),content(""),_Type(SCL_STRING), tmpdt(NULL),as_regex(NULL) {
      _Type = SCL_STRING;
      const wchar_t *lcontent = val.data();
      unsigned int len = val.length();
      char *outbufp = NULL;
      char *outbuf = NULL;
      iconv_t cd;
      cd = iconv_open(OCFA_UNICODE.c_str(), encoding.c_str());
      if (cd == reinterpret_cast<iconv_t> (-1)) {
	throw CharSetException ("Scalar::Scalar(wstring): aparent invalid encoding for iconf library", this);
      }
      size_t inbytes = 2 * len;
      size_t outbytes = inbytes * 3+1;	// 3 times the input buffer size should be more than enough
      outbuf = static_cast<char *>( calloc(inbytes * 3, 1));
#ifdef CONST_ICONV_INBUF
      const char *inbuf = (const char *) lcontent;
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
      char *inbuf = static_cast<char *>(malloc(inbytes));
      char *inbufp=inbuf;
      size_t cindex=0;
      for (cindex=0;cindex < inbytes;cindex++) {
          inbuf[cindex]=(reinterpret_cast<const char *>(lcontent)[cindex]);
      }
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
      free(inbufp);
#endif
      if (inbytes == 0) {
	content = string(outbuf);
	free(outbuf);
	iconv_close(cd);
      }
      else {
	content = "INVALID";
	free(outbuf);
	iconv_close(cd);
	throw CharSetException("Scalar::Scalar(wstring): problem with getTextContent", this);
      }
      testControll();
      return;
    }
#endif
    Scalar::Scalar(string val, string encoding):OcfaObject("Scalar","ocfa"), content(""),_Type(SCL_STRING),tmpdt(NULL),as_regex(NULL) {
      char *outbufp = NULL;
      char *outbuf = NULL;
      const char *enc = encoding.c_str();
      iconv_t cd;
      cd = iconv_open(OCFA_UNICODE.c_str(), enc);
      if (cd == reinterpret_cast<iconv_t>(-1)) {
	throw CharSetException ("Scalar::Scalar, aparent invalid encoding for iconf library", this);
      }
      size_t inbytes = val.length();
      size_t outbytes = inbytes * 5+1;	// 3 times the input buffer size should be more than enough
      outbuf = static_cast<char *>(calloc(outbytes, 1));	// 3 times the input buffer size should be more than enough
      outbufp = outbuf;
      size_t iconvcount=0;
#ifdef CONST_ICONV_INBUF
      const char *inbuf = static_cast<const char *>((val.c_str()));
      iconvcount=iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
      char *inbuf = static_cast<char *>(malloc(strlen(val.c_str())+1));
      char *inbufp=inbuf;
      strcpy(inbuf,val.c_str());
      iconvcount=iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
      free(inbufp);
#endif
      if (iconvcount == (size_t) -1) {
         if (errno == E2BIG) {
            throw CharSetException ("Scalar::Scalar(string,string), problem with encoded sequence:'" + val + "' encoding='"+encoding+", iconf is lost, errno=E2BIG ", this);
         }
         if (errno == EILSEQ) {
            content = outbuf;
            free(outbuf);
            iconv_close(cd);
            _Type = SCL_STRING;
            throw CharSetException ("Scalar::Scalar(string,string), problem with encoded sequence:'" + val + "' from='"+encoding+" to=" + OCFA_UNICODE + " , iconf is lost, errno=EILSEQ . So far:'"+content+"' ", this);
         } 
         if (errno == EINVAL) {
            throw CharSetException ("Scalar::Scalar(string,string), problem with encoded sequence:'" + val + "' encoding='"+encoding+", iconf is lost, errno=EINVAL ", this);
         } 
         throw CharSetException ("Scalar::Scalar(string,string), problem with encoded sequence:'" + val + "' encoding='"+encoding+", iconf is lost, unexpected errno ", this);
      }
      if (inbytes != 0) {
	free(outbuf);
	iconv_close(cd);
	throw CharSetException ("Scalar::Scalar(string,string), problem with encoded sequence:'" + val + "' encoding='"+encoding+", iconf is lost, no errors but inbytes!=0", this);
      } else {
	content = outbuf;
	free(outbuf);
	_Type = SCL_STRING;
	iconv_close(cd);
      }
      testControll();
      return;
    }
    Scalar::Scalar(const char *val, size_t len, string encoding):OcfaObject("Scalar","ocfa"),
							   content(""),_Type(SCL_STRING),tmpdt(NULL),as_regex(NULL) {
      char *outbufp = NULL;
      char *outbuf = NULL;
      const char *enc = encoding.c_str();
      iconv_t cd;
      cd = iconv_open(OCFA_UNICODE.c_str(), enc);
      if (cd == reinterpret_cast<iconv_t>(-1)) {
	throw CharSetException ("Scalar::Scalar(char*,size_t,string), aparent invalid encoding for iconf library", this);
      }
      size_t inbytes=len;
      size_t outbytes = inbytes * 3+1;
      outbuf = static_cast<char *>(calloc(inbytes * 3, 1));
      outbufp = outbuf;
#ifdef CONST_ICONV_INBUF 
      const char *inbuf = val;
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
      char *inbuf=static_cast<char *>( malloc(len+1) );
      inbuf[len]=0;
      for (size_t x=0;x<len;x++)
	      inbuf[x]=val[x];
      char *inbufp=inbuf;
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
      free(inbufp);
#endif
      if (inbytes != 0) {
	free(outbuf);
	iconv_close(cd);
	char *tempbuf=static_cast<char *>( calloc(len+1,1) );
	size_t x;
	strncpy(tempbuf,val,len);
	for (x=0;x<len;x++) {if (tempbuf[x]==0) { tempbuf[x]='?';}}	
	tempbuf[len]=0;
	string strval(tempbuf);
	throw CharSetException ("Scalar::Scalar, problem with encoded char*,len sequence '"+strval+"' encoding "+encoding+", iconf is lost", this);
      } else {
	content = outbuf;
	free(outbuf);
	_Type = SCL_STRING;
	iconv_close(cd);
      }
      testControll();
      return;
    }
    Scalar::Scalar(const char *val, string encoding):OcfaObject("Scalar","ocfa"),
					       content(""),_Type(SCL_STRING),tmpdt(NULL),as_regex(NULL) {
      char *outbufp = NULL;
      char *outbuf = NULL;
      const char *enc = encoding.c_str();
      iconv_t cd;
      size_t inbytes=0;
      if (val) {
       inbytes=strlen(val); 
      }
      if (inbytes == 0) {
         _Type = SCL_STRING;
         return;
      }
      cd = iconv_open(OCFA_UNICODE.c_str(), enc);
      if (cd == reinterpret_cast<iconv_t>(-1)) {
	throw CharSetException ("Scalar::Scalar(char*,size_t,string), aparent invalid encoding for iconf library", this);
      }
      size_t outbytes = inbytes * 3+1;
      outbuf = static_cast<char *>( calloc(outbytes, 1) );
      if (outbuf==0) throw AllocException("Unable to allocate output buffer",this);
      outbufp = outbuf;
#ifdef CONST_ICONV_INBUF
      const char *inbuf = val;
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
      char *inbuf=static_cast<char *>(malloc(strlen(val)+1));
      char *inbufp=inbuf;
      strcpy(inbuf,val);
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
      free(inbufp);
#endif
      if (inbytes != 0) {
	free(outbuf);
	iconv_close(cd);
	throw CharSetException("Scalar::Scalar, problem with encoded 0 terminated sequence, iconf is lost",this);
      } else {
	content = outbuf;
	free(outbuf);
	_Type = SCL_STRING;
	iconv_close(cd);
      }
      testControll();
      return;
    }
    Scalar::Scalar(long long val):OcfaObject("Scalar","ocfa"), content("0"),_Type(SCL_INT),tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(unsigned long val):OcfaObject("Scalar","ocfa"), content("0"),_Type(SCL_INT),tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(long val):OcfaObject("Scalar","ocfa"),content("0"),_Type(SCL_INT), tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(unsigned int val):OcfaObject("Scalar","ocfa"),content("0"),_Type(SCL_INT), tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(int val):OcfaObject("Scalar","ocfa"), content("0"),_Type(SCL_INT),tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(unsigned short val):OcfaObject("Scalar","ocfa"),content("0"),_Type(SCL_INT), tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(short val):OcfaObject("Scalar","ocfa"), content("0"),_Type(SCL_INT),tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(long double val):OcfaObject("Scalar","ocfa"),content("0"),_Type(SCL_FLOAT), tmpdt(NULL),as_regex(NULL) {
      content=boost::lexical_cast<std::string>(val);
    }
    Scalar::Scalar(const DateTime ** val):OcfaObject("Scalar","this"),content("0:invalid"),_Type(SCL_DATETIME), tmpdt(*val),as_regex(NULL) {
      content=misc::DateTime::translate(tmpdt->getTime()) + ":" + tmpdt->getTimeSourceRef();
      _Type = SCL_DATETIME;
      *val=0;
      testControll();
    }
    Scalar::~Scalar() {

      if (tmpdt != 0){

	delete tmpdt;
	tmpdt = 0;
      }
      if (as_regex !=0 ) {
        delete as_regex;
	as_regex=0;
      }

    }
    Scalar operator+(Scalar arg1, Scalar arg2) {
      if ((arg1.getType() == Scalar::SCL_DATETIME)
	  || (arg2.getType() == Scalar::SCL_DATETIME)) 
      {
	if (arg1.getType() == Scalar::SCL_INT) 
	{
	  const DateTime *dt=arg2.asDateTime() + arg1.asInt();
	  Scalar rval(&dt);
	  return rval;
	} else if (arg2.getType() == Scalar::SCL_INT) 
	{
	  const DateTime *dt=arg1.asDateTime() + arg2.asInt();
	  Scalar rval(&dt);
	  return rval;
	} else {
	  throw ScalarMathException("Can not add non int type scalar to an datetime type scalar",&arg1);
	}
      }
      else if ((arg1.getType() == Scalar::SCL_STRING)
	       || (arg2.getType() == Scalar::SCL_STRING)) {
	Scalar rval(arg1.asUTF8() + arg2.asUTF8());
	return rval;
      }
      else if ((arg1.getType() == Scalar::SCL_FLOAT)
	       || (arg2.getType() == Scalar::SCL_FLOAT)) {
	Scalar rval(arg1.asFloat() + arg2.asFloat());
	return rval;
      }
      Scalar rval(arg1.asInt() + arg2.asInt());
      return rval;
    }
#ifndef CYGWIN
    wstring Scalar::asUnicode() const {
      if(_Type == SCL_INVALID){
         throw InvalidScalarException("Unable to get INVALID scalar as unicode", this);
      }
      unsigned int len = content.length();
      char *outbufp = NULL;
      char *outbuf = NULL;
      iconv_t cd;
      cd = iconv_open(OCFA_UNICODEW.c_str(), OCFA_UNICODE.c_str());
      if (cd == reinterpret_cast<iconv_t>(-1)) {
	throw CharSetException ("Scalar::asUnicode(): aparent invalid encoding for iconf library", this);
      }
      size_t inbytes = len;
      size_t outbytes = (inbytes * 2)+2;	// 3 times the input buffer size should be more than enough
      outbuf = static_cast<char *>(calloc(outbytes, 2));
      outbufp = outbuf;
#ifdef CONST_ICONV_INBUF
      const char *inbuf = static_cast<const char *>( content.c_str());
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
      char *inbuf = static_cast<char *>( malloc(strlen(content.c_str())+1) );
      char *inbufp=inbuf;
      strcpy(inbuf,content.c_str());
      iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
      free(inbufp);
#endif
      if (inbytes == 0) {
	wstring rval(reinterpret_cast<wchar_t *>(outbuf));
	free(outbuf);
	iconv_close(cd);
	return rval;
      }
      else {
	free(outbuf);
	iconv_close(cd);
	throw CharSetException("Scalar::asUnicode(): problem with getTextContent", this);
      }
    }
#endif
    string Scalar::asASCII() const {
      if(_Type == SCL_INVALID){
	   throw InvalidScalarException("Unable to get INVALID scalar as ASCII", this);
      }
      if (fitsInASCII()) {
	return content;
      }
      else {
	throw OcfaException("Scalar::asASCII scalar content does not fit in 7 bit ascii", this);
      }
    }
    string Scalar::asUTF8() const {
      if(_Type == SCL_INVALID){
	 throw InvalidScalarException("Unable to get INVALID scalar as unicode", this);
      }
      return content;
    }
    bool Scalar::fitsInASCII() const {
      if(_Type == SCL_INVALID){
           return false;
      }
      int index;
      int len = content.length();
      for (index = 0; index < len; index++) {
	if (content.c_str()[index] < 0) {
	  return false;
	}
      }
      return true;
    }
    long long Scalar::asInt() const {
      if(_Type != SCL_INT){
           int index;
	   int len = content.length();
	   if (len == 0)
	       throw ScalarCastException("Unable to get empty non integer scalar as integer", this);
	   for (index = 0; index < len; index++) {
              if ((content.c_str()[index] < '0') || (content.c_str()[index] > '9')) {
                 throw ScalarCastException("Unable to convert non integer scalar to integer", this);
	      }
	   }
      }
      return atoll(content.c_str());
    }
    long double Scalar::asFloat() const {
      if((_Type != SCL_INT) && (_Type != SCL_FLOAT)) {
          throw ScalarCastException("Unable to get non numeric scalar value as floatingpoint", this);
      }
#ifdef CYGWIN
      return strtod(content.c_str(),  static_cast<char **>(NULL)); 
#else 
      return strtold(content.c_str(), static_cast<char **>(NULL));
#endif
    }
    const DateTime *Scalar::asDateTime() {
      if(_Type != SCL_DATETIME){
	      throw ScalarCastException("Unable to get non datetime scalar as datetime", this);
      }
      if (tmpdt == NULL) {
        int index;
	long time=ocfa::misc::DateTime::translate(content);
	index=content.find_last_of(":");
	tmpdt = new DateTime(time,content.c_str()+index+1);
      }
      return tmpdt;
    }
    Scalar::scalar_type Scalar::getType()const {
      return _Type;
    }
    Scalar operator+(Scalar arg1, char* arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,string arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,long long arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,long arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,unsigned long arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,int arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,unsigned int arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,short arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,unsigned short arg2){
       return arg1+Scalar(arg2);
    }
    Scalar operator+(Scalar arg1,long double arg2){
       return arg1+Scalar(arg2);
    }
  }
}
