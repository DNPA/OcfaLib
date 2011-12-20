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
						
#ifndef JAVA_COMPONENT
#define JAVA_COMPONENT

#include <jni.h>
#include "ocfa.hpp"
namespace ocfa {

  namespace java {
    class JavaComponent : public ocfa::Ocfa {
      
    public:
      JavaComponent();
      
      /**
       *
       * Throws an OcfaException if an uncaught exception occurred in the
       * Java Virtual Machine.
       */
      void checkException();

      /**
       * returns the class with the name inClass. 
       * @param inClass a string containing the name of the class. 
       * @return the classid of that class.
       *
       */
      jclass getClass(string inClass);

      /**
       * Creates an object of that class. It will use the default constructor of inClass.
       * An Exception will be thrown if something goes wrong. 
       *
       */
      jobject createObject(jclass inClass);
      
      /**
       * gets the reference to the method.  
       *
       * @param theClass the class
       * from which the virtual method is taken.  
       * @param methodName
       * the name of the method.  
       * @param signature. the Signature of
       * the method see the jni documentation on how to get a
       * signature.
       *
       */
      jmethodID getMethodID(jclass &theClass, const char *methodName, const char *signature);
      /**
       * Initializes the Java Vvirtual machine. 
       * @param inClassPath the complete classpath that is given to the virtual machine as an option.
       */
      void initJavaVM(string inClassPath);
    protected:
      JNIEnv *javaEnv;
      JavaVM *jvm;
    };
  }
}
#endif
