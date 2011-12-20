#include <iostream>
#include <treegraph.hpp>
#include <misc.hpp>

typedef SinglePointerConstructor< ocfa::treegraph::TreeGraphFactory, std::map< std::string,ocfa::misc::Scalar > > CTreegraphType;
typedef PolicyLoader<CTreegraphType> PLTreeGraph;

class DataCountStream: public ocfa::misc::AbstractWriteFacet {
    off_t mCount;
    static off_t sCount;
  public:
    DataCountStream():mCount(0){}
    void operator()(char *buf, size_t count);
    off_t getCount(){ return mCount;}
    static off_t getTotalCount();
};

off_t DataCountStream::sCount=0;

void DataCountStream::operator()(char *buf, size_t count){
   mCount += count;
   sCount += count;
}

off_t  DataCountStream::getTotalCount() {
    return sCount;
}

void processNode(ocfa::treegraph::TreeGraphNode *node,std::string virtualpath){
   std::string newvirtualpath=virtualpath + "/" + node->getName();
   std::cerr << newvirtualpath << " [START]" << std::endl; 
   if (node->hasSubEntities()) {
      std::cerr << newvirtualpath << " processing sub entities" << std::endl;
      do {
         std::cerr << newvirtualpath << " processing sub entity" << std::endl;
         std::cerr << newvirtualpath << " subnode relation='" <<  node->getCurrentSubEntityRelation() << "'" << std::endl;
         ocfa::treegraph::TreeGraphNode *childnode=0;
         node->getCurrentSubEntity(&childnode) ;
         if (childnode) {
            std::cerr << newvirtualpath << " processing child node" << std::endl;
            processNode(childnode,newvirtualpath); 
         } else {
           std::cerr << newvirtualpath << " subnode returned as NULL, ERROR!!!, this should never happen." << std::endl;
         }                 
      } while (node->nextSubEntity());     
      std::cerr << newvirtualpath << " has no more sub entities" << std::endl;
   }
   else {
      std::cerr << newvirtualpath << " no sub entities" << std::endl;
   }
   if (node->hasContent()) {
      std::cerr << newvirtualpath << " we have content " << node->getSize() << std::endl;
      std::string hlpath=node->getHardLinkablePath("/var/ocfa/");
      if (hlpath == "") {
         std::string slpath=node->getSoftLinkablePath();
         if (slpath == "") {
            std::cerr << newvirtualpath << " Streamable content" << std::endl;
            DataCountStream outstream;
            node->streamToOutput(outstream);
            std::cerr << newvirtualpath << " Streamed " << outstream.getCount() << " bytes to output stream" << std::endl;
            if (outstream.getCount() != node->getSize()) {
                std::cerr << newvirtualpath << " ERROR: Size " << node->getSize() << " and streamed size " << outstream.getCount() << " are not equal" << std::endl;
            }
         } else {
            std::cerr << newvirtualpath << " Soft linkable path: '" << slpath << "'" << std::endl;
         }
      } else {
         std::cerr << newvirtualpath << " Hard linkable path: '" << hlpath << "'" << std::endl;
      }      
   } else {
      std::cerr << newvirtualpath << " we have no content" << std::endl;
   }   
   std::map < std::string, ocfa::misc::MetaValue * > *metamap=0;
   node->takeMetaMap(&metamap);
   if (metamap) {
       std::cerr << newvirtualpath << " Node has meta data" << std::endl;
       map < string, ocfa::misc::MetaValue * >::const_iterator p;
       std::cerr << newvirtualpath << " Iterating" << std::endl;
       for (p = metamap->begin(); p != metamap->end(); ++p) {
               std::cerr << newvirtualpath << " Next meta." << std::endl;
               std::string metaname=p->first;
               std::cerr << newvirtualpath << " Meta data name='" << metaname << "'" << std::endl;
               ocfa::misc::MetaValue *metaval=p->second;
               ocfa::misc::meta_type mtype=metaval->getType();
               switch (mtype) {
                  case ocfa::misc::META_SCALAR :
                        {
                        std::cerr << newvirtualpath << " meta " << metaname << " is of structural type SCALAR." << std::endl;
                        ocfa::misc::ScalarMetaValue *scalarmeta=dynamic_cast <ocfa::misc::ScalarMetaValue *> (metaval);
                        ocfa::misc::Scalar::scalar_type scaltyp=scalarmeta->asScalar().getType();
                        switch (scaltyp) {
                            case ocfa::misc::Scalar::SCL_INVALID:
                                  std::cerr << newvirtualpath << " ERROR: meta " << metaname << " is of scalar type INVALID." << std::endl;
                                  break;
                            case ocfa::misc::Scalar::SCL_INT:
                                  std::cerr << newvirtualpath << " meta " << metaname << " is of scalar type INTEGER." << std::endl;
                                  break;
                            case ocfa::misc::Scalar::SCL_FLOAT:
                                  std::cerr << newvirtualpath << " meta " << metaname << " is of scalar type FLOAT." << std::endl;
                                  break;
                            case ocfa::misc::Scalar::SCL_STRING:
                                  std::cerr << newvirtualpath << " meta " << metaname << " is of scalar type STRING." << std::endl;
                                  break;
                            case ocfa::misc::Scalar::SCL_DATETIME:
                                  std::cerr << newvirtualpath << " meta " << metaname << " is of scalar type DATETIME." << std::endl;
                                  break;
                        }
                        std::string stringmeta = scalarmeta->asScalar().asUTF8();
                        std::cerr << newvirtualpath << " meta " << metaname << " has value '" << stringmeta << "'" << std::endl;
                        }
                        break;
                  case  ocfa::misc::META_ARRAY :
                        std::cerr << newvirtualpath << " meta " << metaname << " is of structural type ARRAY." << std::endl;
                        break;
                  case  ocfa::misc::META_TABLE :
                        std::cerr << newvirtualpath << " meta " << metaname << " is of structural type TABLE." << std::endl;
                        break;
               }                
               delete p->second;
       }       
       delete metamap;
   } else {
       std::cerr << newvirtualpath << " ERROR: takeMetaMap returned NULL" << std::endl;
   }   
   std::cerr << newvirtualpath << " [END]" << std::endl;
}

int main(int argc,char **argv) {
  if (argc != 3) {
    std::cerr << "usage:\n\ttreegraphdump <module> <file>" << std::endl;
    return 1;
  }
  std::string module=argv[1];
  std::string file=argv[2];
  std::cerr << "module=" << module << " file=" << file <<  std::endl;
  PLTreeGraph *policyLoader=0;
  std::cerr << "loading library for " << module << std::endl; 
  policyLoader=new PolicyLoader<CTreegraphType>(module,"constructor");
  std::cerr << "fetching constructor from library" << std::endl;
  CTreegraphType *constructor = policyLoader->constructor();
  std::cerr << "Creating attributes, setting workdir to /tmp/" << std::endl;
  std::map<std::string,ocfa::misc::Scalar> attributes;
  attributes["workdir"]=ocfa::misc::Scalar("/tmp/");
  std::cerr << "creating factory" << std::endl;
  ocfa::treegraph::TreeGraphFactory *topnodefactory=(*constructor)(&attributes); 
  std::cerr << "fetching info from factory" << std::endl;
  std::string charset=topnodefactory->getCharset();
  std::cerr << "charset = '" << charset << "'" << std::endl;
  std::cerr << "creating topnode (1)" << std::endl;
  ocfa::treegraph::TreeGraphNode *topnode=0;
  std::cerr << "creating topnode (2)" << std::endl; 
  topnodefactory->createTopNode(file, &topnode,"treegraphdump");
  std::cerr << "processing topnode" << std::endl;
  std::string virtualpath=file + "::"; 
  processNode(topnode,virtualpath);
  delete(topnode); 
  std::cerr << "Total number of databytes fetched from tree: " << DataCountStream::getTotalCount() << std::endl;  
}
