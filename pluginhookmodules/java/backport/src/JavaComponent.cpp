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
						
#include "JavaComponent.hpp"

namespace ocfa {

  namespace java {
    using namespace ocfa;

    JavaComponent::JavaComponent() : Ocfa("JavaComponent"){
    }




    void JavaComponent::initJavaVM(string inClassPath){

      JavaVMInitArgs vm_args;
      JavaVMOption options[1];  
      jint result; 
      vm_args.version = JNI_VERSION_1_4;
      char classPathOption[1024];
      if(snprintf(classPathOption, 1024, "%s%s", "-Djava.class.path=", inClassPath.c_str())
	 >=1024){
    
	throw OcfaException("classpath too big");
      }


      options[0].optionString = classPathOption;
      cout << "option is " <<  options[0].optionString << endl;
      vm_args.options  = options;
      vm_args.nOptions = 1;
      result = JNI_CreateJavaVM(&jvm, (void **)&javaEnv, &vm_args);
      if (result < 0){

	throw OcfaException("Cannot initialize java vm");
      }
    }  

 
    jclass JavaComponent::getClass(string inClass){

      jclass theClass = javaEnv->FindClass(inClass.c_str());
      if (theClass == 0){
    
	throw OcfaException(string("Cannot find class ") + inClass);
      }
      return theClass;
    }

    jobject JavaComponent::createObject(jclass inClass){

      jobject newObject;
      // getting constructor
      jmethodID constructor = javaEnv->GetMethodID(inClass, "<init>", "()V");
      if (constructor == 0){

	throw OcfaException(string("Cannot find constructor for java class "), this);
      }
      newObject = javaEnv->NewObject(inClass, constructor);
      if (newObject == 0){

	throw OcfaException(string("Cannot initialize constructor for java  class "));
			
      }
      return newObject;
    }


    jmethodID JavaComponent::getMethodID(jclass &theClass, const char *methodName, const char *signature){

      jmethodID methodID = javaEnv->GetMethodID(theClass, methodName, signature);
      if (methodID == 0){

	throw OcfaException(string("Cannot find method ") + methodName, this);
      }
      return methodID;
    }


    void JavaComponent::checkException(){

      jthrowable exception = javaEnv->ExceptionOccurred();
      if (exception){

	javaEnv->ExceptionDescribe();
	javaEnv->ExceptionClear();
	throw OcfaException("An javaException occurred", this);
      }
  

    }
  }
}
