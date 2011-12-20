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
						
#include "JavaExtractor.hpp"
#include <stdio.h>
#include <unistd.h>
using namespace std;
using ocfa::OcfaException;
using namespace ocfa::evidence;
using namespace ocfa;
namespace ocfa {

  namespace java {
    JavaExtractor::JavaExtractor(std::string inName, std::string inNameSpace)
      : ExtractorComponent(inName, inNameSpace)
      {
      }
      
      int JavaExtractor::processEvidence(){
	
	ocfa::store::EvidenceStoreEntity *evidence = createEvidenceStoreObject();
	
	jstring path = javaEnv->NewStringUTF(evidence->getAsFilePath().c_str());

	cerr << "Processing " << evidence->getAsFilePath() << endl;
	jobjectArray metaValuesArray = (jobjectArray)javaEnv->CallObjectMethod(mJavaExtractorComponent, 
									       mProcessEvidenceMethodID, path);
	
	checkException();
	//sanity check we shoudl retrieve an array of name, value pairs.
	int arrayLength = (int) javaEnv->GetArrayLength(metaValuesArray);
	if ((arrayLength % 2) != 0){
	  
	  throw OcfaException("uneven amount of name/value returned", (ExtractorComponent *)this);    
	}
	
	for (jsize x = 0; x < arrayLength; x+=2){
	  
	  // getName
	  jstring javaName = (jstring)javaEnv->GetObjectArrayElement(metaValuesArray, x);
	  const char *nameBuf = javaEnv->GetStringUTFChars(javaName, 0);
	  
	  // getValue
	  jstring javaValue = (jstring)javaEnv->GetObjectArrayElement(metaValuesArray, x + 1);
	  const char *valueBuf = javaEnv->GetStringUTFChars(javaValue, 0);
	  setMeta(string(nameBuf), string(valueBuf));
	  javaEnv->ReleaseStringUTFChars(javaName,nameBuf);
	  javaEnv->ReleaseStringUTFChars(javaValue, valueBuf);
	  javaEnv->DeleteLocalRef(javaValue);
	  javaEnv->DeleteLocalRef(javaName);
	}  
	javaEnv->DeleteLocalRef(metaValuesArray);
	return 1;
      }
      
      
      void JavaExtractor::initJava(string inClassPath, string inClass){
	
	jclass theClassID;
	string classPath;  
	
	classPath = inClassPath + ":" + getConfEntry("java.classpath");
	initJavaVM(classPath);
	theClassID = getClass(inClass);
	mJavaExtractorComponent = createObject(theClassID);
  
	mProcessEvidenceMethodID = getMethodID(theClassID, "processEvidence", 
					       "(Ljava/lang/String;)[Ljava/lang/String;");
      }

 
      void JavaExtractor::processMessage(ocfa::msg::Message &msg){
      }

  }
}

      /**
	 int main(int argc, char *argv[]){

	 JavaExtractor extractor("aap", "default");
	 extractor.initJava("", "Extractor");
	 }
      */
