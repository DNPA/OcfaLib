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


//#include "BlobMetaStoreEntity.hpp"
#include "ConcreteEvidenceStoreEntity.hpp"
#include "PgBlobRepository.hpp"
#include <stdio.h>
#include <pwd.h>
#include <sstream>
#include "PgItem.hpp"
// The entrypoint of this module.
// The factory method of AbstractRepository calls this function
// to obtain a concrete Repository (in this case the PgBlobRepository)
extern "C" {
  ocfa::store::PgRepository *createRepository(const char *root){
    return new ocfa::store::PgBlobRepository(string(root));
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
    PgBlobRepository::PgBlobRepository(string root):PgRepository(root){
       ocfaLog(LOG_DEBUG, "Constructor PgBlobRepository");
       prepareInsertMetaData();
       prepareUpdateMetaData();
       prepareSelectMetaData();
       prepareInsertEvidence();
    }


    void PgBlobRepository::prepareSelectMetaData(){
       const Oid insertevidenceparamtypes[] = {23} ;
       string selectmetadata = string("select content from  metastoreentity  where id = $1");
       PGresult *pgres = PQprepare(d_connection, "selectmetadata", selectmetadata.c_str(), 1, insertevidenceparamtypes);
       if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
         throw OcfaException("Prepare failed: " + selectmetadata);
       }
       PQclear(pgres);

    }


    void PgBlobRepository::prepareInsertMetaData(){
       const Oid insertevidenceparamtypes[] = {25} ;
       string insertevidence = string("insert into metastoreentity(content) values ($1)");
       PGresult *pgres = PQprepare(d_connection, "insertmetadata", insertevidence.c_str(), 1, insertevidenceparamtypes);
       if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
         throw OcfaException("Prepare failed: " + insertevidence);
       }
       PQclear(pgres);
      
    }

    void PgBlobRepository::prepareUpdateMetaData(){
       const Oid insertevidenceparamtypes[] = {25, 23} ;
       string updatemetadata = string("update metastoreentity set content = $1 where id = $2");
       PGresult *pgres = PQprepare(d_connection, "updatemetadata", updatemetadata.c_str(), 2, insertevidenceparamtypes);
       if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
         throw OcfaException("Prepare failed: " + updatemetadata);
       }
       PQclear(pgres);

    }


    void PgBlobRepository::prepareInsertEvidence(){
       const Oid insertevidenceparamtypes[] = {1043} ;
       string insertevidence = string("insert into evidencestoreentity(repname) values ($1)");
       PGresult *pgres = PQprepare(d_connection, "insertevidence", insertevidence.c_str(), 1, insertevidenceparamtypes);
       if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
         throw OcfaException("Prepare failed: " + insertevidence);
       }
       PQclear(pgres);

    }
     
    /**
     * Destructor
     **/
    PgBlobRepository::~PgBlobRepository() {
      PQfinish(d_connection);
    }

    void PgBlobRepository::commitMetaChange( MetaStoreEntity *blobmeta ){
      //unsigned int len = strlen(reinterpret_cast<char *>(blobmeta->contentsAsBuf()));
      //char *escstr = new char[len * 2];
      //PQescapeStringConn(d_connection, escstr, reinterpret_cast<char *>(blobmeta->contentsAsBuf()) , len, 0);
      //string query = "update "+blobmeta->tableName()+ " set content = '" 
//	+ string(escstr) + "' where id = " + blobmeta->getHandle(); 
      //delete [] escstr;
      //ocfaLog(LOG_DEBUG, "executing update: " + query);
      //PGresult *pgres = PQexec(d_connection, query.c_str());
      const char *params[1];
      params[0] =  reinterpret_cast<const char *>(blobmeta->contentsAsBuf());
      params[1] = blobmeta->getHandle().c_str();
      PGresult *pgres = PQexecPrepared(d_connection, "updatemetadata", 2, params, 0, 0, 0);

      if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
        throw OcfaException( "ERROR POSTGRES: " );  
      }
      PQclear(pgres); 
    }


    void PgBlobRepository::StoreMetadata(OcfaHandle &handle, BlobMetaStoreEntity &blobmeta){
      
      //unsigned int len = strlen(blobmeta.contentsAsString().c_str());
      //char *escstr = new char[len * 2];
      //PQescapeStringConn(d_connection, escstr, blobmeta.contentsAsString().c_str(), len, 0);
      //string query = "insert into "+blobmeta.tableName()+ "(content) values('" 
	//+ string(escstr) + "')"; 
      //delete [] escstr;
      //ocfaLog(LOG_DEBUG, "executing insert: " + query);
      //PGresult *pgres = PQexec(d_connection, query.c_str());
      const char *params[1];
      params[0] = blobmeta.contentsAsString().c_str();
      PGresult *pgres = PQexecPrepared(d_connection, "insertmetadata", 1, params, 0, 0, 0);

      if (PQresultStatus(pgres) == PGRES_COMMAND_OK) {
        PQclear(pgres);

	// the following seems to have a concurrency problem, but it has not. Look up
	// the definition of currval in case of doubt. 
	string seq = "select currval('"+blobmeta.tableName()+ "_id_seq')";
        pgres = PQexec(d_connection,seq.c_str());
	if (PQresultStatus(pgres) == PGRES_TUPLES_OK) {
	  string id = PQgetvalue(pgres, 0, 0);
	  OcfaHandle h(id);
          PQclear(pgres);
	  handle = h;
	}
	else {
	  ocfaLog(LOG_ERR,  "Could not get handle from db: " +  ErrorMessage() + " query="  );
	  throw OcfaException("could not retrieve handle", this);
	}
      }
      else {
	ocfaLog(LOG_ERR, "Insert failed: " + ErrorMessage() );
	throw OcfaException("Insert failed", this);
      }
    }
    
    void PgBlobRepository::getBlobMetaStoreEntity(const OcfaHandle &, BlobMetaStoreEntity &){
     
    }

    MetaStoreEntity *PgBlobRepository::constructMetaEntity(string ){
      ocfaLog(LOG_DEBUG, "In PgBlobRepository::constructMetaEntity.");
      return new BlobMetaStoreEntity();
    }


    
    /**
     *
     **/
    OcfaHandle PgBlobRepository::createHandle(StoreEntity &se) {
     
      ocfaLog(LOG_DEBUG, ">> entering createin PgBlobRepository::createHandle: tablename is " + se.tableName()) ;
     
      BlobMetaStoreEntity *bmse = dynamic_cast<BlobMetaStoreEntity *>(&se); // dirty hack
      if (bmse){
        OcfaHandle h("");
        StoreMetadata(h, *bmse);
        return h;
      }
 
      //string query = "insert into "+ se.tableName()  + "(repname) values('" 
	//+ se.getStoreName() + "')";
      //ocfaLog(LOG_DEBUG, "executing insert: " + query);
      //PGresult *pgres = PQexec(d_connection, query.c_str());
      const char *params[1];
      params[0] = se.getStoreName().c_str(); 
      PGresult *pgres = PQexecPrepared(d_connection, "insertevidence", 1, params, 0, 0, 0);
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
	  ocfaLog(LOG_ERR,  "Could not get handle from db: " +  ErrorMessage() + " query=" + se.getStoreName());
	  throw OcfaException("could not retrieve handle", this);
	}
      }
      else {
	ocfaLog(LOG_ERR, "Insert failed: " + ErrorMessage() );
	throw OcfaException("Insert failed", this);
      }
      ocfaLog(LOG_DEBUG, "<< exiting createHandle "); 
      return OcfaHandle("This should not happen!!");
    }


    
  
    


    void PgBlobRepository::getMetaStoreEntity(OcfaHandle & h, MetaStoreEntity **se){
      *se = new BlobMetaStoreEntity();
      

      ocfaLog(LOG_DEBUG, ">> entering PgBlobRepository::getMetaStoreEntity");
      if (h == "") throw OcfaException("getStoreEntity called with empty handle",this);
      string query = "select content from " + (*se)->tableName() + " where id = " + string(h.c_str()) ;
      (*se)->setHandle(h);
      getLogStream(LOG_DEBUG) << "Executing " << query << endl;
      //PGresult *pgres = PQexec(d_connection,query.c_str());
      const char *params[1];
      params[0] = h.c_str();
      PGresult *pgres = PQexecPrepared(d_connection, "selectmetadata", 1, params, 0, 0, 0);
      if (PQresultStatus(pgres) == PGRES_TUPLES_OK) {
	if (PQntuples(pgres) > 0) {

	  std::string content(PQgetvalue(pgres, 0, 0));
	  dynamic_cast<BlobMetaStoreEntity *>(*se)->setContent(content);
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

 
    /**
     *
     **/
    void PgBlobRepository::getStoreEntity(OcfaHandle & h, StoreEntity &se) {
      

      ocfaLog(LOG_DEBUG, ">> entering geStoreentity");
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

    /**
     *
     **/
        
     

 



  }
}
