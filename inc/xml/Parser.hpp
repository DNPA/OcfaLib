#ifndef _OCFA_XML_PARSER_HPP_
#define _OCFA_XML_PARSER_HPP_
namespace ocfa {
  namespace xml {
    class Parser {
      public:
        virtual Element & operator()(misc::MemBuf *mb)=0;
	virtual Element & operator()(std::string s1)=0;
	virtual ~Parser(){}
    };
  }
}
#endif
