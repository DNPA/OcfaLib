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
#include "PgRepository.hpp"
#include <stdio.h>
#include <pwd.h>
#include <sstream>
#include <boost/lexical_cast.hpp>
#include "PgItem.hpp"

/**
 * TODO: check when prepared statements should be used.
 */


namespace ocfa {

  namespace store {

    /**
     * Function that ensures that notices from postgresql are logged by the ocfalogger. 
     */
    static void logNotices(void *, const char *msg){
        OcfaLogger::Instance()->syslog(LOG_NOTICE, string("PgRepository database notice:")+string(msg)+string("\n"));
  
    } 

    /**
     * creates and initialized a root
     * also creates a connection to a postgresdatabase
     */
    PgRepository::PgRepository(string root):SimpleRepository(root),d_connection(0) {
      updateTypeName("PgRepository");
      ocfaLog(LOG_INFO, "Creating pgrepository");
      // get connection info.
      string dbname = ocfa::misc::OcfaConfig::Instance()->getValue("storedbname");
      string dbhost = ocfa::misc::OcfaConfig::Instance()->getValue("storedbhost");
      string dbuser = ocfa::misc::OcfaConfig::Instance()->getValue("storedbuser");
      if (dbuser == "") {
         //Use the uid of the colling prcess
	   struct passwd *pwent=getpwuid(getuid());
	   dbuser=pwent->pw_name;
      }
      string dbpasswd = ocfa::misc::OcfaConfig::Instance()->getValue("storedbpasswd");
      
      /* veilige sprintf*/
      char conninfo[CONNECTINFO_STRING_LENGTH];
      snprintf(conninfo, CONNECTINFO_STRING_LENGTH-1, "dbname=%s hostaddr=%s user=%s password=%s", dbname.c_str(), dbhost.c_str(), dbuser.c_str(), dbpasswd.c_str());
      ocfaLog(LOG_DEBUG, string("connectionString is ") + conninfo);

      // creat connection to postgressdb.
      d_connection = PQconnectdb(conninfo);
       
      if (PQstatus(d_connection) != CONNECTION_OK) {

	string errstr = "PgRepository initialization failed: " + string(ErrorMessage());
	ocfaLog(LOG_ERR, errstr.c_str());
	throw DbConnectException(errstr, this);
      }
 
      ocfaLog(LOG_INFO, "Connected to DB ok");      
      PQsetNoticeProcessor(d_connection, logNotices, 0);

       string insertmetadatainfo = "insert into metadatainfo (metadataid, dataid, evidence, itemid) values ($1,$2,$3,$4)";      
       const Oid insertmetadatainfoparamtypes[] = {23,23,1043,23} ;
       PGresult *pgres = PQprepare(d_connection, "insertmetadatainfo", insertmetadatainfo.c_str(), 4, insertmetadatainfoparamtypes);
       if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
         throw OcfaException("Prepare failed: " + insertmetadatainfo);
       }
       PQclear(pgres);

    }
     
    /**
     *
     **/
    string PgRepository::ErrorMessage(){
      string msg(PQerrorMessage(d_connection));
      return msg; 
    }

    /**
     * Destructor
     **/
    PgRepository::~PgRepository() {
      PQfinish(d_connection);
    }

    
    /**
     * sets the handle to a new one.
     *
     */
    void PgRepository::setHandle(StoreEntity &se){
      ocfaLog(LOG_INFO, "setHandle called");  
      OcfaHandle handle = createHandle(se);
      ocfaLog(LOG_DEBUG, "handle creader");
      se.setHandle(handle); 
      ocfaLog(LOG_DEBUG, "<< setHandle exit");
    }
  

    /**
     *
     **/
    unsigned int PgRepository::getSuspendedMetaEntities(vector<OcfaHandle > &outSuspendedMetaHandles, unsigned int inCount ){

      ostringstream query;
      query << "select * from  suspendedmeta";
      
      if (inCount != 0){

	query << " limit " << inCount;

      }

      PGresult *pgres;
      pgres = PQexec(d_connection, query.str().c_str());
      if (PQresultStatus(pgres) != PGRES_TUPLES_OK) {

	throwDatabaseException(query.str(), pgres);
      }
      int count = PQntuples(pgres);
      for (int x = 0; x < count; x++){

	if (PQgetvalue(pgres, x, 0) == 0){

	  ostringstream errMessage;
	  errMessage << "getSuspendedMetaEntities: cannot find result at " << x;
	  ocfaLog(LOG_ERR, errMessage.str());
	  throw OcfaException("cannot find enough results with getSuspended metaentities", this);
	}
	outSuspendedMetaHandles.push_back(OcfaHandle(PQgetvalue(pgres, x, 0)));
	  
      }
      PQclear(pgres);
      return count;
	

    }
   
    /**
     *
     **/
    unsigned int PgRepository::getMetaEntities(vector<OcfaHandle > &metas, unsigned int count ){

      return getEntities(metas, count, FileMetaStoreEntity::TABLE_NAME);
      
    }

    /**
     *
     **/
    unsigned int PgRepository::getEvidenceEntities(vector<OcfaHandle > &outVector, unsigned int count){
      return getEntities(outVector, count, ConcreteEvidenceStoreEntity::TABLE_NAME);
      
    }

    
    /**
     *
     **/
    unsigned int PgRepository::getEntities(vector<OcfaHandle > &entities, unsigned int count,  string inTableName){
     std::string limit="";
     if (count > 0){
        limit= " limit " + boost::lexical_cast<std::string>(count);
     } 
 
     string q = string("select id from ") + inTableName +  limit;
     PGresult *pgres = PQexec(d_connection,q.c_str());
     
     if (PQresultStatus(pgres) == PGRES_TUPLES_OK){
        int t = PQntuples(pgres);  

        for (int i = 0; i < t; i++){
            string id = PQgetvalue(pgres,i,0);
            OcfaHandle h(id);
            entities.push_back(h);
        }
        return 0;  
     } else {
       
       throwDatabaseException(q, pgres);
     }
     PQclear(pgres);
     return 0;
 }
    
    /**
     *
     **/
 void PgRepository::suspendMetaEntity(OcfaHandle inHandle){

      string command("insert into suspendedmeta (metadataid) values ('");
      command.append(inHandle);
      command.append("')");
      PGresult *pgres = PQexec(d_connection, command.c_str());
      if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
      
        //23505 = UNIQUE VIOLATION
	if ((strcmp(PQresultErrorField(pgres, PG_DIAG_SEVERITY), "ERROR") == 0)
	    && (strcmp(PQresultErrorField(pgres, PG_DIAG_SQLSTATE), "23505") == 0)){

	  ocfaLog(LOG_WARNING, "Attempting to suspend an already suspended metastoreentity.");
	}
	else {

	  throwDatabaseException(command, pgres);
	}
      }
      PQclear(pgres);
    }

    /**
     *
     **/
    void PgRepository::unsuspendMetaEntity(OcfaHandle inHandle){

      string command("delete from suspendedmeta where metadataid = '");
      command.append(inHandle);
      command.append("'");
      PGresult *pgres = PQexec(d_connection, command.c_str());
      if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
	
	throwDatabaseException(command, pgres);
      }
      PQclear(pgres);
    }
    

  
 

    /**
     *
     **/
    ocfa::misc::OcfaHandle PgRepository::getEvidenceStoreHandle( ocfa::store::MetaStoreEntity &inMeta){
      
      string command = "select dataid from metadatainfo where metadataid = '";
      command.append(inMeta.getHandle());
      command.append("'");
      PGresult *pgres = PQexec(d_connection, command.c_str());
      if (PQresultStatus(pgres) != PGRES_TUPLES_OK){

	throwDatabaseException(command, pgres);	
      }
      if (PQntuples(pgres) > 0){
   
	OcfaHandle handle(PQgetvalue(pgres, 0, 0));
	PQclear(pgres);
	return handle;
      }
      else {

	PQclear(pgres);
	throw OcfaException("No EvidenceStoreHandle known ", this);
    
      }
    }
    
    /**
     *
     **/
    bool PgRepository::hasEvidenceStoreHandle(ocfa::store::MetaStoreEntity &inMeta){
      
      string command = "select dataid from metadatainfo where metadataid = '";
      command.append(inMeta.getHandle());
      command.append("'");
      PGresult *pgres = PQexec(d_connection, command.c_str());
      if (PQresultStatus(pgres) != PGRES_TUPLES_OK){
	throwDatabaseException(command, pgres);	
      }
      bool returnValue = (PQntuples(pgres) > 0);
      PQclear(pgres);
      return returnValue;
      
    }
    
    
    /**
     *
     **/
    void PgRepository::fillMetaDataHandles(std::vector<ocfa::misc::OcfaHandle> &outMetaDataHandles, 
						   ocfa::store::EvidenceStoreEntity &inEvidenceStoreEntity){
      
      string command = "select metadataid from metadatainfo where dataid = '" 
	+ inEvidenceStoreEntity.getHandle().append("'");
      PGresult *pgres = PQexec(d_connection, command.c_str());
      if (PQresultStatus(pgres) != PGRES_TUPLES_OK){

	throwDatabaseException(command, pgres);	
      }
      for (int x = 0; x < PQntuples(pgres); x++){

	OcfaHandle handle(PQgetvalue(pgres, x, 0));
	outMetaDataHandles.push_back(handle);
      }
      PQclear(pgres);
      
    }
        
    /**
     * 
     */
    void PgRepository::setMetaDataInfo(const OcfaHandle &inMetaHandle, EvidenceIdentifier &inIdentifier, 
				 const OcfaHandle &inDataHandle){

     
      string itemId = getSerialItemId(inIdentifier.getCaseID(), inIdentifier.getEvidenceSourceID(),
				      inIdentifier.getItemID());
  
      const char *params[4];
      params[0] = inMetaHandle.c_str();

      string command = "insert into metadatainfo (metadataid, dataid, evidence, itemid) values ('";
      command.append(inMetaHandle);
      command.append("', ");

      if (inDataHandle == ""){

	command.append("NULL");
        params[1] = 0;
      }
      else {

	command.append("'");
	command.append(inDataHandle);
	command.append("'");
        params[1] = inDataHandle.c_str();
      }
      command.append(", '");
      command.append(inIdentifier.getEvidenceID());
      params[2] = inIdentifier.getEvidenceID().c_str();
      command.append("', '");
      command.append(itemId);
      params[3] = itemId.c_str();
      command.append("')");
      //PGresult *pgres = PQexec(d_connection, command.c_str());
      PGresult *pgres = PQexecPrepared(d_connection, "insertmetadatainfo", 4, params, 0, 0, 0);
      if (PQresultStatus(pgres) != PGRES_COMMAND_OK){

	throwDatabaseException(command, pgres);
      }
      PQclear(pgres);
    }

    /**
     *
     **/
    void PgRepository::throwDatabaseException(string command, PGresult *inResult){
    
      ocfaLog(LOG_ERR, string("error executing ").append(command));
      ocfaLog(LOG_ERR, string("error was " ).append(PQresStatus(PQresultStatus(inResult))));
      ocfaLog(LOG_ERR, string("primary description: ")
		+ PQresultErrorField(inResult, PG_DIAG_MESSAGE_PRIMARY));	
      ocfaLog(LOG_ERR, string((PQresultErrorField(inResult, PG_DIAG_SQLSTATE))));
      throw OcfaException(string("Error: ").append(PQresStatus(PQresultStatus(inResult))), this);
    }    

    /**
     *
     **/

    string PgRepository::getCachedItemId(string inCaseId, string inSourceId, string inItemId){
        string key = inCaseId + string(":") + inSourceId + string(":") + inItemId;
        if (_itemidmap.find(key) != _itemidmap.end()){
           return _itemidmap[key];
        } else {
           return "";
        }

    }

    string PgRepository::getSerialItemId(string inCaseId, string inSourceId, string inItemId){
      string itemid = getCachedItemId(inCaseId, inSourceId, inItemId);
      if (itemid != ""){
         return itemid;
      }
      string command = "select itemid from item where item = '" + inItemId 
	+ "' and evidencesource = '" + inSourceId + "' and casename = '" + inCaseId + "'";
      PGresult *pgres = PQexec(d_connection, command.c_str());
      
      if (PQresultStatus(pgres) == PGRES_TUPLES_OK
	  && PQntuples(pgres) == 1){
	
	string serialId = PQgetvalue(pgres, 0, 0);
	PQclear(pgres);
        _itemidmap[inCaseId + string(":") + inSourceId + string(":") + inItemId] = serialId;
	return serialId;
      }
      else {
	
	throwDatabaseException(command, pgres);
	return "";
      }
    }


    

    /**
     *
     **/
    void PgRepository::createItem(Item **item, string inCaseId, string inSourceId, 
				  string inItemId){

      string internalItemId;
      string command = "insert into item (casename, evidencesource, item) values ('";
      
      command.append(inCaseId);
      command.append("', '"); 
      command.append(inSourceId);
      command.append("', '");
      command.append(inItemId);
      command.append("')");
      PGresult *pgres = PQexec(d_connection, command.c_str());
      getLogStream(LOG_DEBUG) << "Retrieved " << pgres << endl; 
      if (pgres == 0){

	throw OcfaException("cannot retrieve connection pgres = 0", this);
      }
      if (PQresultStatus(pgres) != PGRES_COMMAND_OK){
        if ( strcmp(PQresultErrorField(pgres, PG_DIAG_SQLSTATE), ERRCODE_UNIQUE_VIOLATION ) == 0)
	   throw ItemConstraintException("Item  already found  in the database",this);
	throwDatabaseException(command, pgres);
      }

      internalItemId = getSerialItemId(inCaseId, inSourceId, inItemId);
      *item = new PgItem(inCaseId, inSourceId, inItemId, internalItemId);
      PQclear(pgres);
    }
  }
}
