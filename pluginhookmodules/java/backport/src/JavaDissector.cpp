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
						
#include "JavaDissector.hpp"
#include <stdio.h>
#include <unistd.h>
namespace ocfa {

  namespace java {
    using namespace std;
    using ocfa::OcfaException;
    using namespace ocfa::evidence;
    using namespace ocfa;
    
    JavaDissector::JavaDissector(std::string inName, std::string inNameSpace)
      : DissectorComponent(inName, inNameSpace) 
      {
      }

      void JavaDissector::initJava(string inClassPath, string inClass){

	string classPath = inClassPath + ":" + getConfEntry("java.classpath");
	initJavaVM(classPath);
  
	jclass theDissectorClass = getClass(inClass);

	mJavaDissectorComponent = createObject(theDissectorClass);


	// get the processEvidenceId method.
	mProcessEvidenceMethodID = getMethodID(theDissectorClass, "processEvidence", 
					       "(Ljava/lang/String;)Ljava/lang/String;");

	// set path  
	jstring workDir = javaEnv->NewStringUTF(getWorkDir().c_str());
	jmethodID setWorkDirID = getMethodID(theDissectorClass, "setWorkDir", 
					     "(Ljava/lang/String;)V");
  
	javaEnv->CallVoidMethod(mJavaDissectorComponent, setWorkDirID, workDir);


	// get mGetMetaDataID
	mGetMetaDataID = getMethodID(theDissectorClass, "getMetaData",
				     "()[Ljava/lang/String;");
	javaEnv->DeleteLocalRef(workDir);
      }

      void JavaDissector::processMessage(ocfa::msg::Message & msg){

      }
  

  


      int JavaDissector::processEvidence(){
	
	ocfa::store::EvidenceStoreEntity *evidence = createEvidenceStoreObject();
	
	jstring path = javaEnv->NewStringUTF(evidence->getAsFilePath().c_str());
	
	jstring output = (jstring)javaEnv->CallObjectMethod(mJavaDissectorComponent, 
							    mProcessEvidenceMethodID, path);
	
	checkException();
	const char *jbyteOutput = javaEnv->GetStringUTFChars(output, 0);
	
	string filePath((const char *)jbyteOutput);
	cout << "filePath is " << filePath << endl; 
	DerivedEvidence *newEvidence = derive(filePath, Scalar(filePath, "LATIN1"));
	
	jobjectArray metaValuesArray = 
	  (jobjectArray)javaEnv->CallObjectMethod(mJavaDissectorComponent, mGetMetaDataID);
	checkException();
	
	//sanity check we shoudl retrieve an array of name, value pairs.
	int arrayLength = (int) javaEnv->GetArrayLength(metaValuesArray);
	if ((arrayLength % 2) != 0){
	  
	  throw OcfaException("uneven amount of name/value returned", (DissectorComponent *)this);    
	}
	
	for (jsize x = 0; x < arrayLength; x+=2){
	  
	  // getName
	  jstring javaName = (jstring)javaEnv->GetObjectArrayElement(metaValuesArray, x);
	  const char *nameBuf = javaEnv->GetStringUTFChars(javaName, 0);
	  
      // getValue
	  jstring javaValue = (jstring)javaEnv->GetObjectArrayElement(metaValuesArray, x + 1);
	  const char *valueBuf = javaEnv->GetStringUTFChars(javaValue, 0);
	  newEvidence->setMeta(string(nameBuf), string(valueBuf));
	  javaEnv->ReleaseStringUTFChars(javaName,nameBuf);
	  javaEnv->ReleaseStringUTFChars(javaValue, valueBuf);
	  javaEnv->DeleteLocalRef(javaValue);
	  javaEnv->DeleteLocalRef(javaName);
	}
	newEvidence->submit();
	javaEnv->ReleaseStringUTFChars(output, jbyteOutput);
	javaEnv->DeleteLocalRef(output);
	javaEnv->DeleteLocalRef(metaValuesArray);
	return 1;
      }
      
  }
}
  /**
     int main(int argc, char *argv[]){

     char workingdir[1024];
     printf("blaje");
     try {
     JavaDissector dissector("dummy", "default");
     getcwd(workingdir, 1023);
     cout << "working dir is " << workingdir<< endl;
    
     dissector.initJava(".", "Dissector");
     cout << "Java initialized" << endl;
     dissector.run();
     } catch (OcfaException e){

     cout << e.what() << endl;
     }
     }
  */
