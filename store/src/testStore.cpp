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
						
#include "AbstractRepository.hpp"
#include "EvidenceStoreEntity.hpp"
#include "MetaStoreEntity.hpp"
#include "MsgStoreEntity.hpp"

#include <iostream>
int main(){

	try {

	  ocfa::store::AbstractRepository *a = ocfa::store::AbstractRepository::Instance("PgRepository");
          if (a == 0){
	    cerr << "Instantiating repository failed" << endl;
	    return 0;
	  }

	ocfa::store::EvidenceStoreEntity *e, *e1, *e2, *e3, *e4;
	a->createEmptyEvidenceStoreEntity(&e);
	//cout << "Class Identifier: " << e.tableName() << endl;
	cout << "open stream " << endl;
	e->openStream();
	char buf[]="Dit is een test";
	cout << "write stream " << strlen(buf) << " bytes " << endl; 
	e->writeStream(buf, strlen(buf));
	cout << "close stream " << endl;
	e->closeStream(); 
	cout << "Stream closed " << endl;

	a->createEmptyEvidenceStoreEntity(&e1);
        string fn("/home/oscar/teststoreevidences/bla.zip");
	cout << "Hardlink" << endl;
	cout << e1->setHardLink(fn) << endl;

	
	a->createEmptyEvidenceStoreEntity(&e2);
        string fn1("/home/oscar/.bashrc"); 	
	cout << "Softlink" << endl;
	cout << e2->setSoftLink(fn1) << endl;

        ocfa::store::MetaStoreEntity me(string(".")); 
        me.openStream();
        me.closeStream();

        ocfa::store::MsgStoreEntity msg(string(".")); 
        msg.openStream();
        msg.closeStream();
        cout << "Testing createEvidenceStoreEntity" << endl;
	char buf1[] = "Dit is test3";
	a->createEvidenceStoreEntity(&e3, strlen(buf1), buf1 );
        cout << "returned handle Buffer " << e3->getHandle() << endl;
	a->createEvidenceStoreEntity(&e3, fn, ocfa::store::soft);
	cout << "returned handle Softlink " << e3->getHandle() << endl;
	a->createEvidenceStoreEntity(&e3, fn1, ocfa::store::hard);
        cout << "returned handle Hardlink " << e3->getHandle() << endl;
	} catch (...) {
          cout << "Exception caught" << endl;
	}

return 0;
}
