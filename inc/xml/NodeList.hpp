#ifndef _OCFA_XML_NODELIST_HPP_
#define _OCFA_XML_NODELIST_HPP_
namespace ocfa {
  namespace xml {
    class NodeList {
       public:
          virtual Element & operator[](size_t index)=0;
	  virtual size_t size()=0;
    };
  }
}
#endif
