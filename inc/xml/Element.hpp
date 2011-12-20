#ifndef _OCFA_XML_ELEMENT_HPP
#define _OCFA_XML_ELEMENT_HPP
namespace ocfa {
  namespace xml {
    class Element {
      public:
         virtual Argument & operator[](std::string argname)=0;
	 virtual NodeList & operator()(std::string childname)=0;
	 virtual Element & addNode(std::string nodename)=0;
	 virtual ~Element(){}
    };
  }
}
#endif
