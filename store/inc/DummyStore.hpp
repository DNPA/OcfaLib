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
						
#ifndef OCFA_STORE
#define OCFA_STORE
#include <misc.hpp>
#include "../misc/inc/LibCryptDigestPair.hpp"
namespace ocfa {
  namespace store {
     class EvidenceStoreEntity {
	 LibCryptDigestPair *dp;
	 bool isclosed;
        public:
         EvidenceStoreEntity(){ 
		 dp=new LibCryptDigestPair();
		 isclosed=false;
	 }
	 ~EvidenceStoreEntity() {delete dp;}
	 void openStream(off_t datasize){;}
	 void writeStream(char *buffer,size_t count){
             dp->update(buffer,count);
	 }
	 void closeStream(){dp->final();isclosed=true;}
       std::string getHandle(misc::OcfaHandle **handle) { *handle=new misc::OcfaHandle("dummydatahandle");}
	 misc::DigestPair *getDigestPair(){
           if (!isclosed) {
              dp->final();isclosed=true;
	   }
           return dp; 
	 }
     };
     class MetaStoreEntity {
        public:
         MetaStoreEntity(){}
	 void getHandle(misc::OcfaHandle **handle) {*handle= new misc::OcfaHandle("dummymetahandle");}
     };
     class Repository {
	         static Repository *mInstance;
         public:
		 Repository() {}
                 void createEvidenceStoreEntity(EvidenceStoreEntity **estore,std::string linkpath,bool hardlinkmode,misc::Item *item,ocfa::misc::DigestPair **){ 
			 getLogStream(LOG_ERR) << "Warning: link not supported by this dummy storem will be no valid digests\n";
			 *estore=new EvidenceStoreEntity();
			 misc::Item *item2;
			 item2=item;
		 }
                 void createEmptyEvidenceStoreEntity(EvidenceStoreEntity **estore,misc::Item *item) {
			 *estore=new EvidenceStoreEntity();
			 misc::Item *item2;
			 item2=item;
		 }
                 void createMetaStoreEntity(MetaStoreEntity ** newstore,misc::MemBuf *mbuf,misc::OcfaHandle *handle,misc::EvidenceIdentifier *evidenceidentifier){
                   *newstore=new MetaStoreEntity();
		   unsigned char buf[640000];
		   snprintf((char *) buf,mbuf->getSize()+1,"%s",(char *) mbuf->getPointer());
	           buf[mbuf->getSize()+1]=0;
                   getLogStream(LOG_ERR) << buf << "\n";
		 }
                 string getRoot(){return "/var";}
		 static Repository *Instance() {
			 if (!mInstance) {
				 mInstance=new Repository();
			 }
			 return mInstance;
		 }
     };
     Repository *Repository::mInstance=0;
  }
}
#endif //OCFA_STORE

