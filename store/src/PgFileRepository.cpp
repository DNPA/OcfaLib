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

#include "FileMetaStoreEntity.hpp"
#include "ConcreteEvidenceStoreEntity.hpp"
#include "PgFileRepository.hpp"
#include <stdio.h>
#include <pwd.h>
#include <sstream>
#include "PgItem.hpp"
// The entrypoint of this module.
// The factory method of AbstractRepository calls this function
// to obtain a concrete Repository (in this case the PgRepository)
extern "C" {
  ocfa::store::PgRepository *createRepository(const char *root){
    return new ocfa::store::PgFileRepository(string(root));
  }
}

/**
 * TODO: check when prepared statements should be used.
 */


namespace ocfa {

  namespace store {

 
    /**
     * creates and initialized a root
     * also creates a connection to a postgresdatabase
     */
    PgFileRepository::PgFileRepository(string root):PgRepository(root) {
	ocfaLog(LOG_DEBUG, "Constructor PgFileRepository");     
    }
     
  
    /**
     * Destructor
     **/
    PgFileRepository::~PgFileRepository() {
      PQfinish(d_connection);
    }

    void  PgFileRepository::commitMetaChange(MetaStoreEntity *){

    }
   
    
    /**
     *
     **/
    OcfaHandle PgFileRepository::createHandle(StoreEntity &se) {
     
      ocfaLog(LOG_DEBUG, ">> entering createin PgFileRepository::createHandle: tablename is " + se.tableName()) ;
      
      string query = "insert into "+ se.tableName()  + "(repname) values('" 
	+ se.getStoreName() + "')";
      ocfaLog(LOG_DEBUG, "executing insert: " + query);
      PGresult *pgres = PQexec(d_connection, query.c_str());
      if (PQresultStatus(pgres) == PGRES_COMMAND_OK) {
        PQclear(pgres);

	// the following seems to have a concurrency problem, but it has not. Look up
	// the definition of currval in case of doubt. 
	string seq = "select currval('"+se.tableName()+ "_id_seq')";
        pgres = PQexec(d_connection,seq.c_str());
	if (PQresultStatus(pgres) == PGRES_TUPLES_OK) {
	  string id = PQgetvalue(pgres, 0, 0);
	  OcfaHandle h(id);
          PQclear(pgres);
	  return h;
	}
	else {
	  ocfaLog(LOG_ERR,  "Could not get handle from db: " +  ErrorMessage() + " query=" + query);
	  throw OcfaException("could not retrieve handle", this);
	}
      }
      else {
	ocfaLog(LOG_ERR, "Insert failed: " + ErrorMessage() );
	throw OcfaException("Insert failed", this);
      }
      ocfaLog(LOG_DEBUG, "<< exiting createHandle "); 
      return OcfaHandle("This should not hapen");
    }


   
 
  

    

    void PgFileRepository::getMetaStoreEntity(OcfaHandle & h, MetaStoreEntity **st){
      *st = new FileMetaStoreEntity(d_root);
      getStoreEntity(h, **st);
    }

 
    /**
     *
     **/
    void PgFileRepository::getStoreEntity(OcfaHandle & h, StoreEntity &se) {
      
      ocfaLog(LOG_DEBUG, ">> entering PgFileRepository::getStoreEntity");
      if (h == "") throw OcfaException("getStoreEntity called with empty handle",this);
      string query = "select repname from " + se.tableName() + " where id = " + string(h.c_str()) ;
      se.setHandle(h);
      getLogStream(LOG_DEBUG) << "Executing " << query << endl;
      PGresult *pgres = PQexec(d_connection,query.c_str());
      if (PQresultStatus(pgres) == PGRES_TUPLES_OK) {
	if (PQntuples(pgres) > 0) {

	  Filename repname(PQgetvalue(pgres, 0, 0));
	  se.setStoreName(repname);
	}
	else {
	  ocfaLog(LOG_ERR, "Error: OcfaHandle for StoreEntity not found in DB");
	  throw OcfaException("Error: OcfaHandle "+ h + " not found in DB", this);
	}
      }
      else {
	ocfaLog(LOG_ERR, "Could not get repname from db: " + ErrorMessage() +  " query=" + query);
	throw OcfaException("Cannot get RepName from db " + ErrorMessage() 
			    + " query=" + query, this);
      }
      ocfaLog(LOG_DEBUG, "exiting getStoreEntity");
      PQclear(pgres);
    }
 

    MetaStoreEntity *PgFileRepository::constructMetaEntity(string ){
      ocfaLog(LOG_DEBUG, ">> entering PgFileRepository::constructMetaEntity");
      return new FileMetaStoreEntity(d_root);
    }


  }
}
