#ifndef _OCFA_XML_ELEMENTWRAPPER_HPP_
#define _OCFA_XML_ELEMENTWRAPPER_HPP_
namespace ocfa {
  namespace xml {
     class ElementWrapper: public OcfaObject {
        public:
           ElementWrapper(std::string elementname);
	   ~ElementWrapper();
	   Element & operator()();
        private:
	   Element *mElement;
     };
  }
}
#endif 
