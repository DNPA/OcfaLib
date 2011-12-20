#ifndef _OCFA_XML_ATTRIBUTE_HPP_
#define _OCFA_XML_ATTRIBUTE_HPP_
#include <sting>
namespace ocfa {
  namespace xml {
    class Element;
    class Attribute {
       public:
         Attribute(std::string name,Element *el);
	 ~Attribute();
         Attribute & operator=(std::string);
	 operator std::string();
       private:
         Element *mElement;
	 std::string mName;
    };
  }
}
#endif
