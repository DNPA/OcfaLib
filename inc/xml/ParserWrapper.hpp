#ifndef _OCFA_XML_PARSERWRAPPER_HPP_
#define _OCFA_XML_PARSERWRAPPER_HPP_
namespace ocfa {
  namespace xml {
     class ParserWrapper: public OcfaObject {
        public:
           ParserWrapper(std::string schema);
	   ~ParserWrapper();
	   Parser & operator()();
        private:
	   Parser * mParser;
     };
  }
}
#endif 
