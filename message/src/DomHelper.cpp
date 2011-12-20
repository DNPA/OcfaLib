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
						
#include "DomHelper.hpp"
#include <iconv.h>
#include <xercesc/util/XMLString.hpp>
using namespace xercesc;
using namespace ocfa::misc;
namespace ocfa {
  namespace message {
     DomHelper *DomHelper::_Instance=0;
     DomHelper::DomHelper():OcfaObject("DomHelper","evidence") {}
     DomHelper *DomHelper::getInstance() {
         if (_Instance==0) 
		 _Instance=new DomHelper();
	 return _Instance;
     }
     XMLCh *DomHelper::transcode(const char *utf8) {
	 char *outbufp = NULL;
         char *outbuf = NULL;
	 iconv_t cd=iconv_open(OCFA_UNICODEW.c_str(), OCFA_UNICODE.c_str());
	 if (cd == reinterpret_cast<iconv_t>(-1)) {
              throw OcfaException ("DomHelper::transcode(char*): aparent invalid encoding for iconf library", 0);
	 }
	 size_t inbytes = strlen(utf8);
         size_t outbytes = (inbytes * 2)+2;
	 outbuf = static_cast<char *>(calloc(outbytes, 2));
         outbufp=outbuf;
#ifdef CONST_ICONV_INBUF
         const char *inbuf = utf8;
         iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
         char *inbuf = static_cast<char *>( malloc(strlen(utf8)+1) );
         char *inbufp=inbuf;
         strcpy(inbuf,utf8);
         iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
         free(inbufp);
#endif
         if (inbytes == 0) {
	     iconv_close(cd);
             return reinterpret_cast<XMLCh *>(outbuf);
	 } else {
	     throw OcfaException("DomHelper::transcode(char *): problem with iconv", 0);
             return 0;
	 }
     }
     char *DomHelper::transcode(const XMLCh *utf16) {
	 char *outbufp = NULL;
         char *outbuf = NULL;
	 iconv_t cd=iconv_open(OCFA_UNICODE.c_str(), OCFA_UNICODEW.c_str());
	 if (cd == reinterpret_cast<iconv_t>(-1)) {
              throw OcfaException ("DomHelper::transcode(char*): aparent invalid encoding for iconf library", 0);
	 }
	 size_t inbytes = XMLString::stringLen(utf16)*2;
         size_t outbytes = (inbytes * 2)+1;
	 outbuf = static_cast<char *>(calloc(outbytes, 2));
         outbufp=outbuf;
#ifdef CONST_ICONV_INBUF
#ifdef CYGWIN
         const char *inbuf = reinterpret_cast<const char *>(utf16);
#else
         const char *inbuf = static_cast<XMLCh *>(utf16);
#endif
         iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
#else
         char *inbuf = static_cast<char *>( malloc(XMLString::stringLen(utf16)*2+2) );
         char *inbufp=inbuf;
         size_t cindex=0;
         for (cindex=0;cindex < inbytes;cindex++) {
             inbuf[cindex]=(reinterpret_cast<const char *>(utf16)[cindex]);
         }
         iconv(cd, &inbuf, &inbytes, &outbufp, &outbytes);
         free(inbufp);
#endif
         if (inbytes == 0) {
	     iconv_close(cd);
             return outbuf;
	 } else {
	     throw OcfaException("DomHelper::transcode(char *): problem with iconv", 0);
             return 0;
	 }
     }
     void DomHelper::release(char **utf8) {
         free(*utf8);
     }
     void DomHelper::release(XMLCh **utf16) {
         free(*utf16);
     }
     std::string  DomHelper::getAttribute(DOMElement *element,std::string atrname){
       if (element == NULL) {
	               throw OcfaException("getAttribute called with NULL element argument",this);
       }
       XMLCh *xarg = XMLString::transcode(atrname.c_str());
       const XMLCh *xname = static_cast<const XMLCh *>(element->getAttribute(xarg));
       char *tname = DomHelper::transcode(xname);
       XMLString::release(&xarg);
       string namestr(tname);
       DomHelper::release(&tname);
       ocfaLog(LOG_DEBUG,"Fetched attribute :" + namestr);
       return namestr;
     }
     void         DomHelper::setAttribute(DOMElement *element,std::string atrname,std::string val){
       if (element == NULL) {
	               throw OcfaException("setAttribute called with NULL element argument",this);
       }
       XMLCh *xname = XMLString::transcode(atrname.c_str());
       XMLCh *xval  = DomHelper::transcode(val.c_str());
       element->setAttribute(xname,xval); 
       XMLString::release(&xname);
       DomHelper::release(&xval);
       return;
     }
     void         DomHelper::createElement(DOMElement **newelement,DOMDocument *doc,std::string newelementname){
       if (*newelement !=0) {
                       throw OcfaException("createElement called with non NULL pointer as target for creation",this);
       }
       XMLCh *xname = XMLString::transcode(newelementname.c_str());
       *newelement=doc->createElement(xname);
       XMLString::release(&xname);
       return;
     }
     DOMNodeList  *DomHelper::getElementsByTagName(DOMElement *element,string name){
       if (element == NULL) {
	               throw OcfaException("getSubItNodeList called with NULL element argument",this);
       }
       XMLCh *xname = XMLString::transcode(name.c_str());
       DOMNodeList *oitems = element->getElementsByTagName(xname);
       XMLString::release(&xname);
       return oitems;
     }
     
  }
}
