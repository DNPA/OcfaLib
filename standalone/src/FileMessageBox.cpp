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
						
#include "FileMessageBox.hpp"
#include "FileMessage.hpp"
#include "store/AbstractRepository.hpp"
#include "store/MetaStoreEntity.hpp"
#include "store/EvidenceStoreEntity.hpp"
#include "message/MessageEvent.hpp"

#include <boost/tokenizer.hpp>
#include <libgen.h>
#include <sstream>
using namespace ocfa::store;
using namespace ocfa::misc;
using namespace ocfa::message;
using namespace ocfa::event;
using namespace boost;

MessageBox *MessageBox::_instance = 0;
MessageBox *MessageBox::createInstance(string name, string mnamespace){

  OcfaLogger::Instance()->syslog(LOG_NOTICE, "filemessagebox") << "Creating an instance" << endl;
  if (_instance == 0){
    _instance = new FileMessageBox(name, mnamespace); 
  }
  return _instance;
}

MessageBox::~MessageBox(){
}


FileMessageBox::FileMessageBox(string inName, string inNameSpace)
  : OcfaObject("FileMessageBox", "message"), mShouldStop(false){
  
  getLogStream(LOG_INFO) << "starting the FileMessageBox" << endl;
  mInstance = new ModuleInstance(inName, inNameSpace, "localhost", string("thetestyone"));
  getLogStream(LOG_INFO) << "mInstance is " << mInstance->getInstanceURI() << endl;
  string testDataFile = OcfaConfig::Instance()->getValue("testdatafile");
  if (testDataFile == ""){

    getLogStream(LOG_WARNING) << "Cannot find testdata" << endl;
    mTestDataStream =0;
  }
  else {
    char *duplicate = strdup(testDataFile.c_str());
    mDataDir = dirname(duplicate);
    mTestDataStream = new ifstream(testDataFile.c_str());
    mCounter = 0;
    free(duplicate);
  }
  createTestItem();
  getLogStream(LOG_INFO) << "2mInstance is " << mInstance->getInstanceURI() << endl;
  
}

FileMessageBox::~FileMessageBox(){
  
  if (mTestDataStream != 0){
    
    delete mTestDataStream;
    mTestDataStream = 0;
  }
  if (mInstance != 0){

    getLogStream(LOG_INFO) << "Deleting moduleinstance " << endl;
    delete mInstance;
    mInstance = 0;
  }
  if (mItemIdentifier != 0){

    delete mItemIdentifier;
    mItemIdentifier = 0;
  }
}
  

Message *FileMessageBox::getNextMessage(int inPriority, int  ) {

  mCounter++;
  ocfaLog(LOG_DEBUG, "Getting next message");
  if (inPriority  >= 0){ 
    FileMessage *message = 0;
    while ( (mTestDataStream != 0) && (*mTestDataStream) && message == 0){
      
      string dataLine;
      getline(*mTestDataStream, dataLine);
      getLogStream(LOG_DEBUG) << "retrieved dataline " << dataLine << endl;
      cout << "Retrieved dataline " << dataLine << endl;
      if (dataLine[0] == '#' || dataLine == ""){
	
	continue;
      }
      // make file relative to the path where testdatafile was found.
      char_separator<char> emptysep(" "); 
      tokenizer<char_separator<char> >  tok(dataLine, emptysep);
      
      

      tokenizer< char_separator<char> >::iterator iter = tok.begin();
      if (iter == tok.end()){

	getLogStream(LOG_ERR) << "invalid dataline " << dataLine << endl;
	throw OcfaException("invalidData line ", this);
      }
      string evidenceId = *iter;
      iter++;
      if (iter == tok.end()){

	getLogStream(LOG_ERR) << "invalid dataline " << dataLine << endl;
	throw OcfaException("invalidData line ", this);
      }
      Filename metaDataFile = *iter;
      Filename dataFile("");
      iter++;
      if (iter != tok.end()){

	dataFile = Filename(*iter);
      }
      
      string content = prepareMetaHandle(evidenceId, metaDataFile, dataFile);

      message = new FileMessage(Message::mtEvidence, Message::UNICAST, 1, "evidence", 
				content, getModuleInstance(), getModuleInstance());  
    }
    if (message == 0 && !mShouldStop){
      
      getLogStream(LOG_DEBUG) << "Returning halt messaage" << endl;
      message = new FileMessage(Message::mtHalt, Message::UNICAST, 1, "stop", "",
				getModuleInstance(), getModuleInstance());
      mShouldStop = true;
    }

    if (message == 0){

      getLogStream(LOG_DEBUG) << "getNextMessage: Returning 0" << endl;
    }
    else {
      //   int type = message->getType();
      //getLogStream(LOG_DEBUG) << "getNextMessage:Returning message with type " <<
      //		        type << endl; 
    }
    return message;
  }
  else {
    return 0;
  }
}


void FileMessageBox::sendMessage(ocfa::message::Message &inMessage) {
  
  string outDir = OcfaConfig::Instance()->getValue("testdataout");  
  ostringstream fileNameStream;
  fileNameStream << outDir + "/out" << mCounter;
  ofstream outStream(fileNameStream.str().c_str(), ios_base::app);
  outStream << "Type: " << inMessage.getType() << '\n';
  outStream << "CastType: " << inMessage.getCastType() << '\n';
  outStream << "Sender: " 
	    << (inMessage.getSender() == 0 ? "null" : (inMessage.getSender()->getInstanceURI()))
	    << '\n';
  outStream << "Receiver: " 
	    << (inMessage.getReceiver() == 0 ? "null" : (inMessage.getReceiver()->getInstanceURI()))
	    << '\n';
  //outStream << "Receiver given: " << receiver.getInstanceURI() << '\n';
  outStream << "Subject: " << inMessage.getSubject() << '\n';
  outStream << "Content: " << inMessage.getSubject() << '\n';
  outStream << "Priority: " << inMessage.getPriority() << '\n';

  if (inMessage.getType() == Message::mtEvidence){

    MetaStoreEntity *entity;
    AbstractRepository::Instance()->createMetaStoreEntity(&entity, OcfaHandle(inMessage.getContent()));
    outStream << "Evidence: \n" << endl;
    outStream << entity->contentsAsString() << "\n";
    delete entity;
  }
  outStream << '\n';

}

void FileMessageBox::createMessage(Message **outMessage, const ModuleInstance *receiver, 
			      Message::CastType casttype, Message::MessageType inType, 
			      std::string inSubject, std::string inContent, int priority ) {
  
  *outMessage = new FileMessage(inType, casttype, priority, inSubject, inContent, getModuleInstance(), 
				receiver);
}



void FileMessageBox::messageDone(const Message *) {
}

//JBS added getModuleInstance to that it can be used for baptizing
ModuleInstance *FileMessageBox::getModuleInstance() {

  cerr << "returnign " << mInstance->getInstanceURI() << endl;
  return mInstance;
}


int FileMessageBox::getEventSourceType(){

  return EventSource::TYPE_TIMEDOUTPOLL;
}

Event *FileMessageBox::getNextEvent(int inPrio){

  ocfaLog(LOG_DEBUG, "Getting next event " );
  return getNextTimeOutEvent(inPrio, 0);
}

Event *FileMessageBox::getNextTimeOutEvent(int inPrio, int ){

  MessageEvent *event;
  ocfaLog(LOG_DEBUG, "Getting nexttimeout event " );
  Message *message = getNextMessage(inPrio);
  if (message == 0){
    
    //   getLogStream(LOG_DEBUG) << "getNextTimeOutEvent: returning null Message" << endl;
  }
  else {
    
    // getLogStream(LOG_DEBUG) << "Returning2 message with type " << message->getType() << endl; 
  }
  if (message != 0){
    
    event = new MessageEvent(&message);
  }
  return event;
}

 
string FileMessageBox::prepareMetaHandle(string inEvidenceId, Filename inMetaDataFile, 
					 Filename inDataFile){
  
  EvidenceStoreEntity *dataEntity = 0;
  MetaStoreEntity *metaEntity = 0;
  OcfaHandle *dataHandle = 0;
  ensureAbsolutePath(inMetaDataFile);
  ensureAbsolutePath(inDataFile);
  getLogStream(LOG_DEBUG) << "datafile is " << inDataFile << endl;
  getLogStream(LOG_DEBUG) << "metadatafile is " << inMetaDataFile << endl;
  if (inDataFile != ""){ 

    AbstractRepository::Instance()->createEvidenceStoreEntity(&dataEntity, inDataFile, soft);
    dataHandle = new OcfaHandle(dataEntity->getHandle());
  }
 
  ifstream metaStream(inMetaDataFile.c_str());
  string metaDataString;
  string line;
  while (metaStream){
    
    getline(metaStream, line);
    metaDataString+=(line);
    metaDataString+=("\n");
    line = "";
  }
  getLogStream(LOG_DEBUG) << "MetaStoreEntity is " << metaDataString << endl;
  OcfaContent metaContent(metaDataString);
  EvidenceIdentifier dummy(mItemIdentifier,inEvidenceId);
  
  AbstractRepository::Instance()->createMetaStoreEntity(&metaEntity, metaContent, dummy,
							dataHandle);
  OcfaHandle metaHandle = metaEntity->getHandle();
  delete metaEntity;
  if (dataEntity != 0){
   
    delete dataEntity;
    delete dataHandle;
  }
  return metaHandle;
}
 

void FileMessageBox::ensureAbsolutePath(string &ioPath){

  if (ioPath != "" && ioPath[0] != '/'){

    ioPath = mDataDir + '/' + ioPath;
  }
}

void FileMessageBox::createTestItem(){

  string firstLine;
  getline(*mTestDataStream, firstLine);
  getLogStream(LOG_DEBUG) << "first line is " << firstLine << endl;
  char_separator<char> emptysep(" "); 
  tokenizer<char_separator<char> >  tok(firstLine, emptysep);
  tokenizer< char_separator<char> >::iterator iter = tok.begin();
  if (iter == tok.end()){

    getLogStream(LOG_DEBUG) << "efirst line is " << firstLine << endl;
    ocfaLog(LOG_ERR, string("first line is ") + firstLine);
    ocfaLog(LOG_ERR, "nothing in first line");
    throw OcfaException("First line of testfile should be <caseid> <evidencesourceid> <itemit>",
			this);
  }
  string caseId = *iter;
  iter++;
  if (iter == tok.end()){
    
    ocfaLog(LOG_ERR, "only caseid in first line");
    throw OcfaException("First line of testfile should be <caseid> <evidencesourceid> <itemit>",
			this);
  }
  string evidenceSourceId = *iter;
  iter++;
  if (iter == tok.end()){

    ocfaLog(LOG_ERR, "only caseid and evidencesourceid in first line");
    throw OcfaException("First line of testfile should be <caseid> <evidencesourceid> <itemit>",
			this);
  }
  string itemId = *iter;
  Item *newItem;
  AbstractRepository::Instance()->createItem(&newItem, caseId, evidenceSourceId, itemId);
  mItemIdentifier = new ItemIdentifier(caseId, evidenceSourceId, itemId);
  delete newItem;
}
