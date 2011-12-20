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
						
#ifndef _OCFA_DOM_HELPER_
#define _OCFA_DOM_HELPER_
#include <xercesc/dom/DOM.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMElement.hpp>
#include <misc.hpp>
namespace ocfa {
	namespace message {
		class DomHelper:public OcfaObject {
                    public:
			    //JCW::CODEREVIEW: Documentatie?????? van de methods.....
			    static 	 DomHelper *getInstance();
			    std::string  getAttribute(xercesc::DOMElement *element,std::string atrname);
			    void 	 setAttribute(xercesc::DOMElement *element,std::string atrname,std::string val);
			    void         createElement(xercesc::DOMElement **newelement,xercesc::DOMDocument *doc,std::string newelementname);
			    xercesc::DOMNodeList  *getElementsByTagName(xercesc::DOMElement *element,string name);
			    xercesc::DOMElement   *getItem(xercesc::DOMNodeList  *item,size_t index);
			    static XMLCh *transcode(const char *utf8);
			    static char *transcode(const XMLCh *utf16);
			    static void release(char **utf8);
			    static void release(XMLCh **utf16);
		    protected:
			    DomHelper();
		    private:
			    static DomHelper *_Instance;
		};
	}
}
#endif
